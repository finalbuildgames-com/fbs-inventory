/*
 * src/inventory.c — FinalBuildSystems spatial (grid) inventory. Implements
 * include/fbs/inventory.h.
 *
 * Original work. Nothing is ported, wrapped or vendored. The owned Fab plugin
 * ("Grid Inventory", Solar Corp) is a *specification input only*: it carries
 * only the Fab Standard License, so it was read for research and no line of
 * it ships. The model (multi-grid inventories, transposed footprints, anchored
 * placement, tag-gated equipment slots, nested container items) is
 * unprotectable design independently attested by these MIT sources:
 * peter-kish/gloot @ 6b09b87ac07a8536779ef1ab0fafc7e99830f948,
 * Ji-Rath/SpatialInventory @ 163077740dfaef1b34a524ccb7c856f766eeafbe and
 * imnazake/GridInventory @ c60729a3fd4739a81b63aa0b66edcfcc9f386e47. The
 * defects I-1 .. I-15 found in that plugin's source (for example I-1, a
 * placement scan that counts free tiles instead of testing a rectangle) are
 * fixed structurally here, not copied.
 *
 * C99. Standard library only (no libm), no floating point, no globals, no
 * static mutable state. One allocation per store.
 *
 * ---------------------------------------------------------------------------
 * Internal contracts that the public header only implies
 * ---------------------------------------------------------------------------
 *
 * HANDLES. fbs_inv_item = (generation << 16) | slot_index. The slot index is
 * the low 16 bits (so max_items <= 65536, exactly as fbs_inv_config states) and
 * the generation is the high 16 bits. Generations are drawn from one store-wide
 * counter that cycles 1, 2, ... 0xFFFE, 1, ...: it never takes the value 0
 * (which would make a handle indistinguishable from a bare index) nor 0xFFFF
 * (which with index 0xFFFF would collide with FBS_INV_NONE). Every accessor
 * decodes the index, reports E_INVALID when it is >= the issued slot count and
 * E_STALE when the stored generation differs or the slot is a tombstone.
 * fbs_inv_store_clear does not reset the counter, so handles issued before a
 * clear stay unusable afterwards.
 *
 * SLOT REUSE. A destroyed item leaves a tombstone. The next spawn reuses the
 * lowest-indexed tombstone (deterministic) and gives it a fresh generation, so
 * the previous handle can never be revived. Only when no tombstone exists does
 * the issued-slot count grow.
 *
 * CONTAINER INVENTORIES. Spawning a container type attaches an inventory whose
 * grids mirror the type's container_wh; destroying the container leaves that
 * inventory in place but DETACHED — its owner_item handle no longer resolves to
 * a live item. Inventory, grid and cell ids are therefore permanent, which is
 * what makes the blob canonical (records are emitted in id order). A later
 * container reuses the lowest-id detached inventory whose grid shape matches
 * its type exactly and whose cells are all free; otherwise a new one is
 * carved. Capacity is thus
 * bounded under spawn/destroy churn without ever renumbering.
 *
 * TRANSACTIONS. Every mutator appends inverse records to a fixed-size journal
 * before it touches state, and fbs_inv_txn_abort replays them backwards. All
 * bump counters (type/inventory/grid/cell/item/slot/key/container-wh tops, the
 * generation counter and the seal flag) grow monotonically inside a
 * transaction, so they are snapshotted at begin and restored wholesale at
 * abort instead of being journalled per operation. That makes the setup calls
 * (type_add, inventory_add, slot_add, seal) undoable too, at zero journal cost,
 * and abort restores byte-identical serialized state (witness T-7).
 *
 * SCHEMA. Magic "FBIV" version 1, little-endian, every record written field
 * by field (never a struct memcpy). An item record is 28 bytes, the sum of its
 * fields (an early draft of the schema said 24); every other record's size is
 * likewise the sum of its fields.
 */

#include "fbs/inventory.h"

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------- */
/* Limits                                                                    */
/* ------------------------------------------------------------------------- */

#define INV_SCHEMA_VERSION 1u

#define INV_MAX_TYPES 4096u
#define INV_MAX_INVENTORIES 4096u
#define INV_MAX_GRIDS 16384u
#define INV_MAX_CELLS 4194304u /* 1 << 22 */
#define INV_MAX_ITEMS 65535u
#define INV_MAX_SLOTS 1024u
#define INV_MAX_KEY_BYTES 4194304u /* 1 << 22 */
#define INV_MIN_TXN_OPS 8u
#define INV_MAX_TXN_OPS 65536u
#define INV_MAX_GRID_DIM 1024u
#define INV_MAX_STACK 16777216u /* 1 << 24 */
#define INV_MAX_KEY_LEN 255u
#define INV_MAX_CONTAINER_GRIDS 64u

#define INV_GEN_MIN 1u
#define INV_GEN_MAX 0xFFFEu

#define INV_HEADER_BYTES 48u
#define INV_TYPE_BYTES 32u
#define INV_INVENTORY_BYTES 16u
#define INV_GRID_BYTES 8u
#define INV_ITEM_BYTES 28u
#define INV_SLOT_BYTES 24u

#define INV_STATE_NONE 0u /* tombstone            */
#define INV_STATE_GRID 1u /* placed in a grid     */
#define INV_STATE_SLOT 2u /* in an equipment slot */

#define INV_BLOCK_ALIGN 8u

static size_t inv_align_up(size_t v) {
  return (v + (INV_BLOCK_ALIGN - 1u)) & ~(size_t)(INV_BLOCK_ALIGN - 1u);
}

static void *inv_default_alloc(void *user, size_t bytes) {
  (void)user;
  return malloc(bytes);
}

static void inv_default_free(void *user, void *ptr) {
  (void)user;
  free(ptr);
}

/* ------------------------------------------------------------------------- */
/* Internal representation                                                   */
/* ------------------------------------------------------------------------- */

typedef struct inv_type_rec {
  uint64_t tags;
  uint32_t key_off;
  uint32_t key_len;
  uint32_t max_stack;
  uint32_t cwh_off; /* index into the container_wh arena */
  uint16_t width;
  uint16_t height;
  uint16_t container_grids;
  uint16_t pad;
} inv_type_rec;

typedef struct inv_slot_rec {
  uint64_t accept_tags;
  uint32_t key_off;
  uint32_t key_len;
  uint32_t item; /* handle, or FBS_INV_NONE */
  uint32_t pad;
} inv_slot_rec;

typedef struct inv_inv_rec {
  uint32_t first_grid;
  uint32_t owner; /* handle of the owning container item, or FBS_INV_NONE */
  uint16_t grid_count;
  uint16_t pad;
} inv_inv_rec;

typedef struct inv_grid_rec {
  uint32_t cell_off;
  uint16_t width;
  uint16_t height;
} inv_grid_rec;

typedef struct inv_item_rec {
  uint32_t type;       /* FBS_INV_NONE for a tombstone            */
  uint32_t generation; /* INV_GEN_MIN .. INV_GEN_MAX              */
  uint32_t inventory;  /* FBS_INV_NONE unless state == GRID       */
  uint32_t grid;       /* grid index within the inventory         */
  uint32_t stack;
  uint32_t container; /* inventory owned by this item, or NONE    */
  uint32_t slot;      /* equipment slot holding it, or NONE       */
  uint16_t x;
  uint16_t y;
  uint8_t rot;
  uint8_t state;
  uint16_t pad;
} inv_item_rec;

/* Undo journal ------------------------------------------------------------ */

#define INV_J_ITEM 1u   /* restore one item record                            */
#define INV_J_CELLS 2u  /* refill one rectangle of the cell array             */
#define INV_J_SLOT 3u   /* restore one equipment slot's occupant              */
#define INV_J_INVOWN 4u /* restore one inventory's owner handle               */

typedef struct inv_jrec {
  uint32_t op;
  uint32_t idx; /* item index / inventory id / slot id */
  union {
    inv_item_rec item;
    struct {
      uint32_t grid, x, y, w, h, val;
    } cells;
    uint32_t val;
  } u;
} inv_jrec;

/* Everything that grows monotonically inside a transaction. */
typedef struct inv_counters {
  uint32_t type_count;
  uint32_t inventory_count;
  uint32_t grid_count;
  uint32_t cell_top;
  uint32_t item_count;
  uint32_t slot_count;
  uint32_t key_top; /* type keys, growing from the front */
  uint32_t key_end; /* slot keys, growing from the back  */
  uint32_t cwh_top;
  uint32_t next_gen;
} inv_counters;

struct fbs_inv_store {
  fbs_inv_allocator alloc;
  size_t block_size;

  unsigned max_types;
  unsigned max_inventories;
  unsigned max_grids;
  unsigned max_cells;
  unsigned max_items;
  unsigned max_slots;
  unsigned max_key_bytes;
  unsigned max_txn_ops;
  unsigned max_cwh;
  unsigned type_hash_cap;
  unsigned slot_hash_cap;
  unsigned scratch_cap;
  uint16_t max_grid_dim;

  inv_counters c;

  /* Not part of the rewound counter block, and deliberately so.
     gen_floor is the unserialized generation high-water mark: it only ever
     grows, so a handle minted inside a transaction that is later aborted can
     never be reissued, while c.next_gen still rewinds and the blob stays
     byte-identical across an abort (header "handles", T-7).
     sealed is not transactional either: fbs_inv_seal freezes the catalog for
     good and fbs_inv_txn_abort does not lift it. */
  uint32_t gen_floor;
  uint32_t sealed;

  unsigned free_hint; /* lowest item index that may be a tombstone */

  int txn_active;
  int txn_poisoned;
  unsigned journal_len;
  inv_counters snapshot;

  inv_type_rec *types;
  inv_slot_rec *slots;
  inv_inv_rec *inventories;
  inv_grid_rec *grids;
  inv_item_rec *items;
  inv_jrec *journal;
  uint32_t *cells;
  uint32_t *scratch;
  uint32_t *type_hash; /* open addressing, 0 empty, else type id + 1 */
  uint32_t *slot_hash; /* open addressing, 0 empty, else slot id + 1 */
  uint16_t *cwh;
  char *keys;
};

/* ------------------------------------------------------------------------- */
/* Status names, version, config                                             */
/* ------------------------------------------------------------------------- */

const char *fbs_inv_status_name(int status) {
  switch (status) {
    case FBS_INV_OK: return "ok";
    case FBS_INV_E_INVALID: return "invalid";
    case FBS_INV_E_NOT_FOUND: return "not_found";
    case FBS_INV_E_EXISTS: return "exists";
    case FBS_INV_E_FULL: return "full";
    case FBS_INV_E_RANGE: return "range";
    case FBS_INV_E_NO_SPACE: return "no_space";
    case FBS_INV_E_OCCUPIED: return "occupied";
    case FBS_INV_E_REJECTED: return "rejected";
    case FBS_INV_E_CYCLE: return "cycle";
    case FBS_INV_E_STALE: return "stale";
    case FBS_INV_E_SCHEMA: return "schema";
    case FBS_INV_E_TRUNCATED: return "truncated";
    case FBS_INV_E_SEALED: return "sealed";
    case FBS_INV_E_TXN: return "txn";
    case FBS_INV_E_MEMORY: return "memory";
    default: return "unknown";
  }
}

unsigned fbs_inv_version(void) { return FBS_INV_VERSION; }

fbs_inv_config fbs_inv_config_default(void) {
  fbs_inv_config cfg;
  cfg.max_types = 64u;
  cfg.max_inventories = 32u;
  cfg.max_grids = 128u;
  cfg.max_cells = 8192u;
  cfg.max_items = 1024u;
  cfg.max_slots = 32u;
  cfg.max_key_bytes = 4096u;
  cfg.max_txn_ops = 256u;
  cfg.max_grid_dim = 64u;
  return cfg;
}

static int inv_config_valid(const fbs_inv_config *cfg) {
  if (cfg->max_types < 1u || cfg->max_types > INV_MAX_TYPES) return 0;
  if (cfg->max_inventories < 1u || cfg->max_inventories > INV_MAX_INVENTORIES) return 0;
  if (cfg->max_grids < 1u || cfg->max_grids > INV_MAX_GRIDS) return 0;
  if (cfg->max_cells < 1u || cfg->max_cells > INV_MAX_CELLS) return 0;
  if (cfg->max_items < 1u || cfg->max_items > INV_MAX_ITEMS) return 0;
  if (cfg->max_slots > INV_MAX_SLOTS) return 0;
  if (cfg->max_key_bytes < 1u || cfg->max_key_bytes > INV_MAX_KEY_BYTES) return 0;
  if (cfg->max_txn_ops < INV_MIN_TXN_OPS || cfg->max_txn_ops > INV_MAX_TXN_OPS) return 0;
  if (cfg->max_grid_dim < 1u || cfg->max_grid_dim > INV_MAX_GRID_DIM) return 0;
  return 1;
}

/* ------------------------------------------------------------------------- */
/* Key index (FNV-1a, open addressing; entries are never deleted individually) */
/* ------------------------------------------------------------------------- */

static uint32_t inv_key_hash(const char *key, size_t len) {
  uint32_t h = 2166136261u;
  size_t i;
  for (i = 0; i < len; ++i) {
    h ^= (uint32_t)(unsigned char)key[i];
    h *= 16777619u;
  }
  return h;
}

static unsigned inv_hash_cap_for(unsigned n) {
  unsigned need = n * 2u;
  unsigned cap = 8u;
  while (cap < need) cap <<= 1;
  return cap;
}

static void inv_type_hash_insert(fbs_inv_store *s, uint32_t t) {
  const inv_type_rec *r = &s->types[t];
  unsigned mask = s->type_hash_cap - 1u;
  unsigned i = (unsigned)(inv_key_hash(s->keys + r->key_off, r->key_len) & mask);
  while (s->type_hash[i] != 0u) i = (i + 1u) & mask;
  s->type_hash[i] = t + 1u;
}

static uint32_t inv_type_hash_find(const fbs_inv_store *s, const char *key, size_t len) {
  unsigned mask = s->type_hash_cap - 1u;
  unsigned i = (unsigned)(inv_key_hash(key, len) & mask);
  while (s->type_hash[i] != 0u) {
    uint32_t t = s->type_hash[i] - 1u;
    if (t < s->c.type_count) {
      const inv_type_rec *r = &s->types[t];
      if ((size_t)r->key_len == len && memcmp(s->keys + r->key_off, key, len) == 0) return t;
    }
    i = (i + 1u) & mask;
  }
  return FBS_INV_NONE;
}

static void inv_slot_hash_insert(fbs_inv_store *s, uint32_t sl) {
  const inv_slot_rec *r = &s->slots[sl];
  unsigned mask = s->slot_hash_cap - 1u;
  unsigned i = (unsigned)(inv_key_hash(s->keys + r->key_off, r->key_len) & mask);
  while (s->slot_hash[i] != 0u) i = (i + 1u) & mask;
  s->slot_hash[i] = sl + 1u;
}

static uint32_t inv_slot_hash_find(const fbs_inv_store *s, const char *key, size_t len) {
  unsigned mask = s->slot_hash_cap - 1u;
  unsigned i = (unsigned)(inv_key_hash(key, len) & mask);
  while (s->slot_hash[i] != 0u) {
    uint32_t sl = s->slot_hash[i] - 1u;
    if (sl < s->c.slot_count) {
      const inv_slot_rec *r = &s->slots[sl];
      if ((size_t)r->key_len == len && memcmp(s->keys + r->key_off, key, len) == 0) return sl;
    }
    i = (i + 1u) & mask;
  }
  return FBS_INV_NONE;
}

static void inv_type_hash_rebuild(fbs_inv_store *s) {
  uint32_t i;
  memset(s->type_hash, 0, (size_t)s->type_hash_cap * sizeof(uint32_t));
  for (i = 0u; i < s->c.type_count; ++i) inv_type_hash_insert(s, i);
}

static void inv_slot_hash_rebuild(fbs_inv_store *s) {
  uint32_t i;
  memset(s->slot_hash, 0, (size_t)s->slot_hash_cap * sizeof(uint32_t));
  for (i = 0u; i < s->c.slot_count; ++i) inv_slot_hash_insert(s, i);
}

/* ------------------------------------------------------------------------- */
/* Handles                                                                   */
/* ------------------------------------------------------------------------- */

static fbs_inv_item inv_handle(uint32_t generation, uint32_t index) {
  return (fbs_inv_item)((generation << 16) | (index & 0xFFFFu));
}

static uint32_t inv_handle_index(fbs_inv_item h) { return h & 0xFFFFu; }
static uint32_t inv_handle_gen(fbs_inv_item h) { return (h >> 16) & 0xFFFFu; }

/* OK, E_INVALID (index never issued) or E_STALE (destroyed / wrong generation). */
static fbs_inv_status inv_resolve(const fbs_inv_store *s, fbs_inv_item it, uint32_t *out_idx) {
  uint32_t idx;
  if (it == FBS_INV_NONE) return FBS_INV_E_INVALID;
  idx = inv_handle_index(it);
  if (idx >= s->c.item_count) return FBS_INV_E_INVALID;
  if (s->items[idx].generation != inv_handle_gen(it)) return FBS_INV_E_STALE;
  if (s->items[idx].state == INV_STATE_NONE) return FBS_INV_E_STALE;
  *out_idx = idx;
  return FBS_INV_OK;
}

static fbs_inv_item inv_handle_of(const fbs_inv_store *s, uint32_t idx) {
  return inv_handle(s->items[idx].generation, idx);
}

/* True when `h` still names a live item. */
static int inv_handle_live(const fbs_inv_store *s, fbs_inv_item h) {
  uint32_t idx;
  if (h == FBS_INV_NONE) return 0;
  idx = inv_handle_index(h);
  if (idx >= s->c.item_count) return 0;
  if (s->items[idx].generation != inv_handle_gen(h)) return 0;
  return s->items[idx].state != INV_STATE_NONE;
}

/* The generation a fresh handle gets: the serialized counter, floored by the
 * unserialized high-water mark so that an aborted transaction's handles are
 * never handed out again. Both advance together; they differ only between an
 * abort (which rewinds c.next_gen but not the floor) and the next mint. */
static uint32_t inv_peek_generation(const fbs_inv_store *s) {
  return s->c.next_gen > s->gen_floor ? s->c.next_gen : s->gen_floor;
}

static uint32_t inv_next_generation(fbs_inv_store *s) {
  uint32_t g = inv_peek_generation(s);
  s->c.next_gen = (g >= INV_GEN_MAX) ? INV_GEN_MIN : g + 1u;
  s->gen_floor = s->c.next_gen;
  return g;
}

/* ------------------------------------------------------------------------- */
/* Lifetime                                                                  */
/* ------------------------------------------------------------------------- */

static size_t inv_block_layout(const fbs_inv_config *cfg, unsigned type_hash_cap,
                               unsigned slot_hash_cap, unsigned scratch_cap, unsigned max_cwh,
                               size_t *off) {
  size_t at = inv_align_up(sizeof(struct fbs_inv_store));
  off[0] = at; /* types */
  at = inv_align_up(at + (size_t)cfg->max_types * sizeof(inv_type_rec));
  off[1] = at; /* slots */
  at = inv_align_up(at + (size_t)cfg->max_slots * sizeof(inv_slot_rec));
  off[2] = at; /* inventories */
  at = inv_align_up(at + (size_t)cfg->max_inventories * sizeof(inv_inv_rec));
  off[3] = at; /* grids */
  at = inv_align_up(at + (size_t)cfg->max_grids * sizeof(inv_grid_rec));
  off[4] = at; /* items */
  at = inv_align_up(at + (size_t)cfg->max_items * sizeof(inv_item_rec));
  off[5] = at; /* journal */
  at = inv_align_up(at + (size_t)cfg->max_txn_ops * sizeof(inv_jrec));
  off[6] = at; /* cells */
  at = inv_align_up(at + (size_t)cfg->max_cells * sizeof(uint32_t));
  off[7] = at; /* scratch */
  at = inv_align_up(at + (size_t)scratch_cap * sizeof(uint32_t));
  off[8] = at; /* type hash */
  at = inv_align_up(at + (size_t)type_hash_cap * sizeof(uint32_t));
  off[9] = at; /* slot hash */
  at = inv_align_up(at + (size_t)slot_hash_cap * sizeof(uint32_t));
  off[10] = at; /* container_wh arena */
  at = inv_align_up(at + (size_t)max_cwh * sizeof(uint16_t));
  off[11] = at; /* keys */
  at = inv_align_up(at + (size_t)cfg->max_key_bytes);
  return at;
}

static fbs_inv_status inv_store_alloc(const fbs_inv_config *cfg, const fbs_inv_allocator *alloc,
                                      fbs_inv_store **out) {
  fbs_inv_allocator a;
  size_t off[12], total;
  unsigned type_hash_cap, slot_hash_cap, scratch_cap, max_cwh;
  unsigned char *block;
  fbs_inv_store *s;

  if (alloc) {
    if (!alloc->alloc || !alloc->free) return FBS_INV_E_INVALID;
    a = *alloc;
  } else {
    a.alloc = inv_default_alloc;
    a.free = inv_default_free;
    a.user = NULL;
  }

  type_hash_cap = inv_hash_cap_for(cfg->max_types);
  slot_hash_cap = inv_hash_cap_for(cfg->max_slots);
  scratch_cap = cfg->max_items > cfg->max_inventories ? cfg->max_items : cfg->max_inventories;
  max_cwh = cfg->max_types * (2u * INV_MAX_CONTAINER_GRIDS);

  total = inv_block_layout(cfg, type_hash_cap, slot_hash_cap, scratch_cap, max_cwh, off);
  block = (unsigned char *)a.alloc(a.user, total);
  if (!block) return FBS_INV_E_MEMORY;
  memset(block, 0, total);

  s = (fbs_inv_store *)(void *)block;
  s->alloc = a;
  s->block_size = total;
  s->max_types = cfg->max_types;
  s->max_inventories = cfg->max_inventories;
  s->max_grids = cfg->max_grids;
  s->max_cells = cfg->max_cells;
  s->max_items = cfg->max_items;
  s->max_slots = cfg->max_slots;
  s->max_key_bytes = cfg->max_key_bytes;
  s->max_txn_ops = cfg->max_txn_ops;
  s->max_cwh = max_cwh;
  s->type_hash_cap = type_hash_cap;
  s->slot_hash_cap = slot_hash_cap;
  s->scratch_cap = scratch_cap;
  s->max_grid_dim = cfg->max_grid_dim;

  s->c.key_end = cfg->max_key_bytes;
  s->c.next_gen = INV_GEN_MIN;
  s->gen_floor = INV_GEN_MIN;

  s->types = (inv_type_rec *)(void *)(block + off[0]);
  s->slots = (inv_slot_rec *)(void *)(block + off[1]);
  s->inventories = (inv_inv_rec *)(void *)(block + off[2]);
  s->grids = (inv_grid_rec *)(void *)(block + off[3]);
  s->items = (inv_item_rec *)(void *)(block + off[4]);
  s->journal = (inv_jrec *)(void *)(block + off[5]);
  s->cells = (uint32_t *)(void *)(block + off[6]);
  s->scratch = (uint32_t *)(void *)(block + off[7]);
  s->type_hash = (uint32_t *)(void *)(block + off[8]);
  s->slot_hash = (uint32_t *)(void *)(block + off[9]);
  s->cwh = (uint16_t *)(void *)(block + off[10]);
  s->keys = (char *)(void *)(block + off[11]);

  *out = s;
  return FBS_INV_OK;
}

fbs_inv_status fbs_inv_store_create(const fbs_inv_config *cfg, const fbs_inv_allocator *alloc,
                                    fbs_inv_store **out) {
  fbs_inv_config c;
  fbs_inv_store *s = NULL;
  fbs_inv_status st;

  if (!out) return FBS_INV_E_INVALID;
  c = cfg ? *cfg : fbs_inv_config_default();
  if (!inv_config_valid(&c)) return FBS_INV_E_INVALID;

  st = inv_store_alloc(&c, alloc, &s);
  if (st != FBS_INV_OK) return st;
  *out = s;
  return FBS_INV_OK;
}

void fbs_inv_store_destroy(fbs_inv_store *s) {
  fbs_inv_allocator a;
  if (!s) return;
  a = s->alloc;
  a.free(a.user, s);
}

void fbs_inv_store_clear(fbs_inv_store *s) {
  if (!s) return;
  s->txn_active = 0;
  s->txn_poisoned = 0;
  s->journal_len = 0u;
  s->c.inventory_count = 0u;
  s->c.grid_count = 0u;
  s->c.cell_top = 0u;
  s->c.item_count = 0u;
  s->c.slot_count = 0u;
  s->c.key_end = s->max_key_bytes;
  s->free_hint = 0u;
  /* type catalog, its keys and the seal survive; so does next_gen, so handles
     issued before the clear can never resolve again. */
  memset(s->items, 0, (size_t)s->max_items * sizeof(inv_item_rec));
  memset(s->slots, 0, (size_t)s->max_slots * sizeof(inv_slot_rec));
  memset(s->inventories, 0, (size_t)s->max_inventories * sizeof(inv_inv_rec));
  memset(s->grids, 0, (size_t)s->max_grids * sizeof(inv_grid_rec));
  inv_slot_hash_rebuild(s);
}

size_t fbs_inv_store_memory(const fbs_inv_store *s) { return s ? s->block_size : 0u; }

/* ------------------------------------------------------------------------- */
/* Item types                                                                */
/* ------------------------------------------------------------------------- */

fbs_inv_status fbs_inv_type_add(fbs_inv_store *s, const char *key, size_t key_len,
                                const fbs_inv_type_desc *desc, fbs_inv_type *out) {
  inv_type_rec *r;
  uint32_t t;
  unsigned i, wh_entries;

  if (!s || !key || !desc || !out) return FBS_INV_E_INVALID;
  if (key_len == 0u || key_len > INV_MAX_KEY_LEN) return FBS_INV_E_INVALID;
  if (s->sealed) return FBS_INV_E_SEALED;
  if (desc->width < 1u || desc->width > s->max_grid_dim) return FBS_INV_E_RANGE;
  if (desc->height < 1u || desc->height > s->max_grid_dim) return FBS_INV_E_RANGE;
  if (desc->max_stack < 1u || desc->max_stack > INV_MAX_STACK) return FBS_INV_E_RANGE;
  if (desc->container_grids > INV_MAX_CONTAINER_GRIDS) return FBS_INV_E_RANGE;
  /* A stackable container would let fbs_inv_stack_merge destroy a non-empty
     inventory when the giver is drained, breaking the conservation invariant
     the header states for merges. The contract forbids the combination. */
  if (desc->container_grids > 0u && desc->max_stack != 1u) return FBS_INV_E_RANGE;
  if (desc->container_grids > 0u && !desc->container_wh) return FBS_INV_E_INVALID;
  wh_entries = (unsigned)desc->container_grids * 2u;
  for (i = 0u; i < wh_entries; ++i) {
    if (desc->container_wh[i] < 1u || desc->container_wh[i] > s->max_grid_dim)
      return FBS_INV_E_RANGE;
  }
  if (inv_type_hash_find(s, key, key_len) != FBS_INV_NONE) return FBS_INV_E_EXISTS;
  if (s->c.type_count >= s->max_types) return FBS_INV_E_FULL;
  if ((size_t)key_len > (size_t)(s->c.key_end - s->c.key_top)) return FBS_INV_E_FULL;
  if (wh_entries > s->max_cwh - s->c.cwh_top) return FBS_INV_E_FULL;

  t = s->c.type_count;
  r = &s->types[t];
  r->tags = desc->tags;
  r->key_off = s->c.key_top;
  r->key_len = (uint32_t)key_len;
  r->max_stack = desc->max_stack;
  r->cwh_off = s->c.cwh_top;
  r->width = desc->width;
  r->height = desc->height;
  r->container_grids = desc->container_grids;
  r->pad = 0u;
  memcpy(s->keys + s->c.key_top, key, key_len);
  s->c.key_top += (uint32_t)key_len;
  for (i = 0u; i < wh_entries; ++i) s->cwh[s->c.cwh_top + i] = desc->container_wh[i];
  s->c.cwh_top += wh_entries;
  s->c.type_count += 1u;
  inv_type_hash_insert(s, t);

  *out = t;
  return FBS_INV_OK;
}

fbs_inv_status fbs_inv_type_find(const fbs_inv_store *s, const char *key, size_t key_len,
                                 fbs_inv_type *out) {
  uint32_t t;
  if (!s || !key || !out) return FBS_INV_E_INVALID;
  if (key_len == 0u || key_len > INV_MAX_KEY_LEN) return FBS_INV_E_INVALID;
  t = inv_type_hash_find(s, key, key_len);
  if (t == FBS_INV_NONE) return FBS_INV_E_NOT_FOUND;
  *out = t;
  return FBS_INV_OK;
}

fbs_inv_status fbs_inv_type_key(const fbs_inv_store *s, fbs_inv_type t, const char **out_key,
                                size_t *out_len) {
  if (!s || !out_key || !out_len) return FBS_INV_E_INVALID;
  if (t >= s->c.type_count) return FBS_INV_E_INVALID;
  *out_key = s->keys + s->types[t].key_off;
  *out_len = (size_t)s->types[t].key_len;
  return FBS_INV_OK;
}

fbs_inv_status fbs_inv_type_desc_get(const fbs_inv_store *s, fbs_inv_type t,
                                     fbs_inv_type_desc *out) {
  const inv_type_rec *r;
  if (!s || !out) return FBS_INV_E_INVALID;
  if (t >= s->c.type_count) return FBS_INV_E_INVALID;
  r = &s->types[t];
  out->width = r->width;
  out->height = r->height;
  out->max_stack = r->max_stack;
  out->tags = r->tags;
  out->container_wh = r->container_grids ? (const uint16_t *)(s->cwh + r->cwh_off) : NULL;
  out->container_grids = r->container_grids;
  return FBS_INV_OK;
}

unsigned fbs_inv_type_count(const fbs_inv_store *s) { return s ? (unsigned)s->c.type_count : 0u; }

fbs_inv_status fbs_inv_seal(fbs_inv_store *s) {
  if (!s) return FBS_INV_E_INVALID;
  s->sealed = 1u;
  return FBS_INV_OK;
}

int fbs_inv_is_sealed(const fbs_inv_store *s) { return s ? (int)s->sealed : 0; }

/* ------------------------------------------------------------------------- */
/* Inventories and grids                                                     */
/* ------------------------------------------------------------------------- */

/* Carves grid_count grids of the given sizes plus their cells. The caller has
 * validated every dimension. Returns FBS_INV_NONE (and the reason in *st) when
 * a capacity is exhausted; nothing is changed in that case. */
static uint32_t inv_inventory_carve(fbs_inv_store *s, const uint16_t *wh, unsigned grid_count,
                                    fbs_inv_status *st) {
  uint32_t inv;
  unsigned i;
  size_t cells = 0u;

  for (i = 0u; i < grid_count; ++i) cells += (size_t)wh[i * 2u] * (size_t)wh[i * 2u + 1u];

  if (s->c.inventory_count >= s->max_inventories) {
    *st = FBS_INV_E_FULL;
    return FBS_INV_NONE;
  }
  if (grid_count > s->max_grids - s->c.grid_count) {
    *st = FBS_INV_E_FULL;
    return FBS_INV_NONE;
  }
  if (cells > (size_t)(s->max_cells - s->c.cell_top)) {
    *st = FBS_INV_E_FULL;
    return FBS_INV_NONE;
  }

  inv = s->c.inventory_count;
  s->inventories[inv].first_grid = s->c.grid_count;
  s->inventories[inv].grid_count = (uint16_t)grid_count;
  s->inventories[inv].owner = FBS_INV_NONE;
  s->inventories[inv].pad = 0u;
  for (i = 0u; i < grid_count; ++i) {
    inv_grid_rec *g = &s->grids[s->c.grid_count + i];
    unsigned n = (unsigned)wh[i * 2u] * (unsigned)wh[i * 2u + 1u];
    unsigned k;
    g->width = wh[i * 2u];
    g->height = wh[i * 2u + 1u];
    g->cell_off = s->c.cell_top;
    for (k = 0u; k < n; ++k) s->cells[s->c.cell_top + k] = FBS_INV_NONE;
    s->c.cell_top += n;
  }
  s->c.grid_count += grid_count;
  s->c.inventory_count += 1u;
  *st = FBS_INV_OK;
  return inv;
}

fbs_inv_status fbs_inv_inventory_add(fbs_inv_store *s, const uint16_t *grid_wh, uint16_t grid_count,
                                     fbs_inv_inventory *out) {
  fbs_inv_status st = FBS_INV_OK;
  uint32_t inv;
  unsigned i;

  if (!s || !grid_wh || !out) return FBS_INV_E_INVALID;
  if (grid_count == 0u) return FBS_INV_E_RANGE;
  for (i = 0u; i < (unsigned)grid_count * 2u; ++i) {
    if (grid_wh[i] < 1u || grid_wh[i] > s->max_grid_dim) return FBS_INV_E_RANGE;
  }
  inv = inv_inventory_carve(s, grid_wh, grid_count, &st);
  if (inv == FBS_INV_NONE) return st;
  *out = inv;
  return FBS_INV_OK;
}

unsigned fbs_inv_inventory_count(const fbs_inv_store *s) {
  return s ? (unsigned)s->c.inventory_count : 0u;
}

fbs_inv_status fbs_inv_grid_count(const fbs_inv_store *s, fbs_inv_inventory inv, uint16_t *out) {
  if (!s || !out) return FBS_INV_E_INVALID;
  if (inv >= s->c.inventory_count) return FBS_INV_E_INVALID;
  *out = s->inventories[inv].grid_count;
  return FBS_INV_OK;
}

fbs_inv_status fbs_inv_grid_size(const fbs_inv_store *s, fbs_inv_inventory inv, fbs_inv_grid g,
                                 uint16_t *out_w, uint16_t *out_h) {
  const inv_grid_rec *gr;
  if (!s || !out_w || !out_h) return FBS_INV_E_INVALID;
  if (inv >= s->c.inventory_count) return FBS_INV_E_INVALID;
  if (g >= (uint32_t)s->inventories[inv].grid_count) return FBS_INV_E_INVALID;
  gr = &s->grids[s->inventories[inv].first_grid + g];
  *out_w = gr->width;
  *out_h = gr->height;
  return FBS_INV_OK;
}

fbs_inv_status fbs_inv_item_container(const fbs_inv_store *s, fbs_inv_item it,
                                      fbs_inv_inventory *out) {
  uint32_t idx;
  fbs_inv_status st;
  if (!s || !out) return FBS_INV_E_INVALID;
  st = inv_resolve(s, it, &idx);
  if (st != FBS_INV_OK) return st;
  if (s->items[idx].container == FBS_INV_NONE) return FBS_INV_E_NOT_FOUND;
  *out = s->items[idx].container;
  return FBS_INV_OK;
}

fbs_inv_status fbs_inv_inventory_owner(const fbs_inv_store *s, fbs_inv_inventory inv,
                                       fbs_inv_item *out) {
  if (!s || !out) return FBS_INV_E_INVALID;
  if (inv >= s->c.inventory_count) return FBS_INV_E_INVALID;
  if (s->inventories[inv].owner == FBS_INV_NONE) return FBS_INV_E_NOT_FOUND;
  *out = s->inventories[inv].owner;
  return FBS_INV_OK;
}

int fbs_inv_item_live(const fbs_inv_store *s, fbs_inv_item it) {
  uint32_t idx;
  fbs_inv_status st;
  if (!s) return FBS_INV_E_INVALID;
  st = inv_resolve(s, it, &idx);
  if (st == FBS_INV_OK) return 1;
  if (st == FBS_INV_E_STALE) return 0;
  return (int)st;
}

unsigned fbs_inv_item_count(const fbs_inv_store *s) { return s ? (unsigned)s->c.item_count : 0u; }

fbs_inv_status fbs_inv_item_slot(const fbs_inv_store *s, fbs_inv_item it, fbs_inv_slot *out) {
  uint32_t idx;
  fbs_inv_status st;
  if (!s || !out) return FBS_INV_E_INVALID;
  st = inv_resolve(s, it, &idx);
  if (st != FBS_INV_OK) return st;
  if (s->items[idx].state != INV_STATE_SLOT) return FBS_INV_E_NOT_FOUND;
  *out = s->items[idx].slot;
  return FBS_INV_OK;
}

/* ------------------------------------------------------------------------- */
/* Geometry                                                                  */
/* ------------------------------------------------------------------------- */

/* OK, or E_RANGE for the reserved 180/270 values, or E_INVALID for anything
 * that is not a member of the enumeration at all. */
static fbs_inv_status inv_check_rot(fbs_inv_rot rot) {
  int r = (int)rot;
  if (r == FBS_INV_ROT_0 || r == FBS_INV_ROT_90) return FBS_INV_OK;
  if (r == 2 || r == 3) return FBS_INV_E_RANGE;
  return FBS_INV_E_INVALID;
}

static void inv_footprint_of(const inv_type_rec *t, unsigned rot, unsigned *fw, unsigned *fh) {
  if (rot == (unsigned)FBS_INV_ROT_0) {
    *fw = t->width;
    *fh = t->height;
  } else {
    *fw = t->height;
    *fh = t->width;
  }
}

fbs_inv_status fbs_inv_footprint(const fbs_inv_store *s, fbs_inv_type t, fbs_inv_rot rot,
                                 uint16_t *out_w, uint16_t *out_h) {
  unsigned fw, fh;
  fbs_inv_status st;
  if (!s || !out_w || !out_h) return FBS_INV_E_INVALID;
  if (t >= s->c.type_count) return FBS_INV_E_INVALID;
  st = inv_check_rot(rot);
  if (st != FBS_INV_OK) return st;
  inv_footprint_of(&s->types[t], (unsigned)rot, &fw, &fh);
  *out_w = (uint16_t)fw;
  *out_h = (uint16_t)fh;
  return FBS_INV_OK;
}

static uint32_t *inv_cell(const fbs_inv_store *s, uint32_t inv, uint32_t g, unsigned x,
                          unsigned y) {
  const inv_grid_rec *gr = &s->grids[s->inventories[inv].first_grid + g];
  return s->cells + gr->cell_off + (size_t)y * (size_t)gr->width + x;
}

/* The whole placement rule (fixes I-1): in bounds, and every covered cell free
 * or held by `ignore_idx`. */
static int inv_rect_free(const fbs_inv_store *s, uint32_t inv, uint32_t g, unsigned x, unsigned y,
                         unsigned fw, unsigned fh, uint32_t ignore_idx) {
  const inv_grid_rec *gr = &s->grids[s->inventories[inv].first_grid + g];
  unsigned dx, dy;
  if (fw > (unsigned)gr->width || fh > (unsigned)gr->height) return 0;
  if (x > (unsigned)gr->width - fw || y > (unsigned)gr->height - fh) return 0;
  for (dy = 0u; dy < fh; ++dy) {
    const uint32_t *row = s->cells + gr->cell_off + (size_t)(y + dy) * (size_t)gr->width + x;
    for (dx = 0u; dx < fw; ++dx) {
      if (row[dx] != FBS_INV_NONE && row[dx] != ignore_idx) return 0;
    }
  }
  return 1;
}

static void inv_stamp(fbs_inv_store *s, uint32_t inv, uint32_t g, unsigned x, unsigned y,
                      unsigned fw, unsigned fh, uint32_t val) {
  const inv_grid_rec *gr = &s->grids[s->inventories[inv].first_grid + g];
  unsigned dx, dy;
  for (dy = 0u; dy < fh; ++dy) {
    uint32_t *row = s->cells + gr->cell_off + (size_t)(y + dy) * (size_t)gr->width + x;
    for (dx = 0u; dx < fw; ++dx) row[dx] = val;
  }
}

/* Full argument + placement validation shared by can_place and every mutator. */
static fbs_inv_status inv_check_place(const fbs_inv_store *s, uint32_t inv, uint32_t g, uint32_t t,
                                      fbs_inv_rot rot, unsigned x, unsigned y,
                                      uint32_t ignore_idx) {
  unsigned fw, fh;
  fbs_inv_status st;
  if (inv >= s->c.inventory_count) return FBS_INV_E_INVALID;
  if (g >= (uint32_t)s->inventories[inv].grid_count) return FBS_INV_E_INVALID;
  if (t >= s->c.type_count) return FBS_INV_E_INVALID;
  st = inv_check_rot(rot);
  if (st != FBS_INV_OK) return st;
  if (x >= (unsigned)s->max_grid_dim || y >= (unsigned)s->max_grid_dim) return FBS_INV_E_RANGE;
  inv_footprint_of(&s->types[t], (unsigned)rot, &fw, &fh);
  if (!inv_rect_free(s, inv, g, x, y, fw, fh, ignore_idx)) return FBS_INV_E_NO_SPACE;
  return FBS_INV_OK;
}

fbs_inv_status fbs_inv_can_place(const fbs_inv_store *s, fbs_inv_inventory inv, fbs_inv_grid g,
                                 fbs_inv_type t, fbs_inv_rot rot, uint16_t x, uint16_t y,
                                 fbs_inv_item ignore) {
  uint32_t ignore_idx = FBS_INV_NONE;
  if (!s) return FBS_INV_E_INVALID;
  if (ignore != FBS_INV_NONE) {
    fbs_inv_status st = inv_resolve(s, ignore, &ignore_idx);
    if (st != FBS_INV_OK) return st;
  }
  return inv_check_place(s, inv, g, t, rot, (unsigned)x, (unsigned)y, ignore_idx);
}

/* First fit in the documented, contractual scan order: grids in index order;
 * within a grid ROT_0 over every anchor row-major (y outer, x inner), then
 * ROT_90 over the same grid when try_rotate. Mutates nothing (fixes I-11). */
static fbs_inv_status inv_find_place(const fbs_inv_store *s, uint32_t inv, uint32_t t,
                                     int try_rotate, uint32_t ignore_idx, uint32_t *out_grid,
                                     unsigned *out_x, unsigned *out_y, unsigned *out_rot) {
  const inv_inv_rec *ir = &s->inventories[inv];
  unsigned g, rots = try_rotate ? 2u : 1u;
  for (g = 0u; g < (unsigned)ir->grid_count; ++g) {
    const inv_grid_rec *gr = &s->grids[ir->first_grid + g];
    unsigned r;
    for (r = 0u; r < rots; ++r) {
      unsigned fw, fh, x, y;
      inv_footprint_of(&s->types[t], r, &fw, &fh);
      if (fw > (unsigned)gr->width || fh > (unsigned)gr->height) continue;
      for (y = 0u; y + fh <= (unsigned)gr->height; ++y) {
        for (x = 0u; x + fw <= (unsigned)gr->width; ++x) {
          if (inv_rect_free(s, inv, g, x, y, fw, fh, ignore_idx)) {
            *out_grid = g;
            *out_x = x;
            *out_y = y;
            *out_rot = r;
            return FBS_INV_OK;
          }
        }
      }
    }
  }
  return FBS_INV_E_NO_SPACE;
}

fbs_inv_status fbs_inv_find_place(const fbs_inv_store *s, fbs_inv_inventory inv, fbs_inv_type t,
                                  int try_rotate, fbs_inv_item ignore, fbs_inv_grid *out_grid,
                                  uint16_t *out_x, uint16_t *out_y, fbs_inv_rot *out_rot) {
  uint32_t ignore_idx = FBS_INV_NONE, g;
  unsigned x, y, r;
  fbs_inv_status st;

  if (!s || !out_grid || !out_x || !out_y || !out_rot) return FBS_INV_E_INVALID;
  if (inv >= s->c.inventory_count) return FBS_INV_E_INVALID;
  if (t >= s->c.type_count) return FBS_INV_E_INVALID;
  if (ignore != FBS_INV_NONE) {
    st = inv_resolve(s, ignore, &ignore_idx);
    if (st != FBS_INV_OK) return st;
  }
  st = inv_find_place(s, inv, t, try_rotate, ignore_idx, &g, &x, &y, &r);
  if (st != FBS_INV_OK) return st;
  *out_grid = g;
  *out_x = (uint16_t)x;
  *out_y = (uint16_t)y;
  *out_rot = (r == 0u) ? FBS_INV_ROT_0 : FBS_INV_ROT_90;
  return FBS_INV_OK;
}

/* ------------------------------------------------------------------------- */
/* Queries                                                                   */
/* ------------------------------------------------------------------------- */

fbs_inv_status fbs_inv_cell_item(const fbs_inv_store *s, fbs_inv_inventory inv, fbs_inv_grid g,
                                 uint16_t x, uint16_t y, fbs_inv_item *out) {
  const inv_grid_rec *gr;
  uint32_t idx;
  if (!s || !out) return FBS_INV_E_INVALID;
  if (inv >= s->c.inventory_count) return FBS_INV_E_INVALID;
  if (g >= (uint32_t)s->inventories[inv].grid_count) return FBS_INV_E_INVALID;
  gr = &s->grids[s->inventories[inv].first_grid + g];
  if (x >= gr->width || y >= gr->height) return FBS_INV_E_RANGE;
  idx = *inv_cell(s, inv, g, (unsigned)x, (unsigned)y);
  if (idx == FBS_INV_NONE) return FBS_INV_E_NOT_FOUND;
  *out = inv_handle_of(s, idx);
  return FBS_INV_OK;
}

fbs_inv_status fbs_inv_item_place(const fbs_inv_store *s, fbs_inv_item it,
                                  fbs_inv_inventory *out_inv, fbs_inv_grid *out_grid,
                                  uint16_t *out_x, uint16_t *out_y, fbs_inv_rot *out_rot) {
  const inv_item_rec *r;
  uint32_t idx;
  fbs_inv_status st;
  if (!s || !out_inv || !out_grid || !out_x || !out_y || !out_rot) return FBS_INV_E_INVALID;
  st = inv_resolve(s, it, &idx);
  if (st != FBS_INV_OK) return st;
  r = &s->items[idx];
  if (r->state != INV_STATE_GRID) return FBS_INV_E_NOT_FOUND; /* equipped */
  *out_inv = r->inventory;
  *out_grid = r->grid;
  *out_x = r->x;
  *out_y = r->y;
  *out_rot = (r->rot == 0u) ? FBS_INV_ROT_0 : FBS_INV_ROT_90;
  return FBS_INV_OK;
}

fbs_inv_status fbs_inv_item_type_of(const fbs_inv_store *s, fbs_inv_item it, fbs_inv_type *out) {
  uint32_t idx;
  fbs_inv_status st;
  if (!s || !out) return FBS_INV_E_INVALID;
  st = inv_resolve(s, it, &idx);
  if (st != FBS_INV_OK) return st;
  *out = s->items[idx].type;
  return FBS_INV_OK;
}

fbs_inv_status fbs_inv_item_stack(const fbs_inv_store *s, fbs_inv_item it, uint32_t *out) {
  uint32_t idx;
  fbs_inv_status st;
  if (!s || !out) return FBS_INV_E_INVALID;
  st = inv_resolve(s, it, &idx);
  if (st != FBS_INV_OK) return st;
  *out = s->items[idx].stack;
  return FBS_INV_OK;
}

fbs_inv_status fbs_inv_list_items(const fbs_inv_store *s, fbs_inv_inventory inv, fbs_inv_item *out,
                                  size_t cap, size_t *out_count) {
  size_t n = 0u;
  uint32_t i;
  if (!s || !out_count) return FBS_INV_E_INVALID;
  if (!out && cap > 0u) return FBS_INV_E_INVALID;
  if (inv >= s->c.inventory_count) return FBS_INV_E_INVALID;
  for (i = 0u; i < s->c.item_count; ++i) {
    if (s->items[i].state == INV_STATE_GRID && s->items[i].inventory == inv) ++n;
  }
  if (n > cap) {
    *out_count = n;
    return FBS_INV_E_TRUNCATED;
  }
  n = 0u;
  for (i = 0u; i < s->c.item_count; ++i) {
    if (s->items[i].state == INV_STATE_GRID && s->items[i].inventory == inv)
      out[n++] = inv_handle_of(s, i);
  }
  *out_count = n;
  return FBS_INV_OK;
}

/* Is `inv` `ancestor`, or nested (at any depth) inside it? Walks up the owner
 * chain, so no scratch memory is needed and const queries stay thread-safe. */
static int inv_within(const fbs_inv_store *s, uint32_t inv, uint32_t ancestor) {
  uint32_t cur = inv;
  unsigned guard = 0u;
  while (guard++ <= s->c.inventory_count) {
    uint32_t owner, oidx;
    if (cur == ancestor) return 1;
    owner = s->inventories[cur].owner;
    if (owner == FBS_INV_NONE || !inv_handle_live(s, owner)) return 0;
    oidx = inv_handle_index(owner);
    if (s->items[oidx].state != INV_STATE_GRID) return 0; /* equipped: chain ends */
    cur = s->items[oidx].inventory;
  }
  return 0;
}

fbs_inv_status fbs_inv_count_of(const fbs_inv_store *s, fbs_inv_inventory inv, fbs_inv_type t,
                                int recurse, uint64_t *out) {
  uint64_t total = 0u;
  uint32_t i;
  if (!s || !out) return FBS_INV_E_INVALID;
  if (inv >= s->c.inventory_count) return FBS_INV_E_INVALID;
  if (t >= s->c.type_count) return FBS_INV_E_INVALID;

  for (i = 0u; i < s->c.item_count; ++i) {
    const inv_item_rec *r = &s->items[i];
    if (r->state != INV_STATE_GRID || r->type != t) continue;
    if (recurse ? inv_within(s, r->inventory, inv) : (r->inventory == inv))
      total += (uint64_t)r->stack;
  }
  *out = total;
  return FBS_INV_OK;
}

uint64_t fbs_inv_total_units(const fbs_inv_store *s) {
  uint64_t total = 0u;
  uint32_t i;
  if (!s) return 0u;
  for (i = 0u; i < s->c.item_count; ++i) {
    if (s->items[i].state != INV_STATE_NONE) total += (uint64_t)s->items[i].stack;
  }
  return total;
}

/* ------------------------------------------------------------------------- */
/* Transactions                                                              */
/* ------------------------------------------------------------------------- */

fbs_inv_status fbs_inv_txn_begin(fbs_inv_store *s) {
  if (!s) return FBS_INV_E_INVALID;
  if (s->txn_active) return FBS_INV_E_TXN;
  s->txn_active = 1;
  s->txn_poisoned = 0;
  s->journal_len = 0u;
  s->snapshot = s->c;
  return FBS_INV_OK;
}

fbs_inv_status fbs_inv_txn_commit(fbs_inv_store *s) {
  if (!s) return FBS_INV_E_INVALID;
  if (!s->txn_active || s->txn_poisoned) return FBS_INV_E_TXN;
  s->txn_active = 0;
  s->journal_len = 0u;
  return FBS_INV_OK;
}

fbs_inv_status fbs_inv_txn_abort(fbs_inv_store *s) {
  unsigned i;
  uint32_t old_types, old_slots;
  if (!s) return FBS_INV_E_INVALID;
  if (!s->txn_active) return FBS_INV_E_TXN;

  for (i = s->journal_len; i > 0u; --i) {
    const inv_jrec *j = &s->journal[i - 1u];
    switch (j->op) {
      case INV_J_ITEM: s->items[j->idx] = j->u.item; break;
      case INV_J_CELLS:
        inv_stamp(s, j->idx, j->u.cells.grid, j->u.cells.x, j->u.cells.y, j->u.cells.w,
                  j->u.cells.h, j->u.cells.val);
        break;
      case INV_J_SLOT: s->slots[j->idx].item = j->u.val; break;
      case INV_J_INVOWN: s->inventories[j->idx].owner = j->u.val; break;
      default: break;
    }
  }

  old_types = s->c.type_count;
  old_slots = s->c.slot_count;
  s->c = s->snapshot;
  if (s->c.type_count != old_types) inv_type_hash_rebuild(s);
  if (s->c.slot_count != old_slots) inv_slot_hash_rebuild(s);

  s->free_hint = 0u;
  s->txn_active = 0;
  s->txn_poisoned = 0;
  s->journal_len = 0u;
  return FBS_INV_OK;
}

int fbs_inv_txn_active(const fbs_inv_store *s) { return s ? s->txn_active : 0; }

/* Reserves `n` journal records. E_TXN with no (or a poisoned) transaction;
 * E_FULL and a poisoned transaction when the journal cannot take them. */
static fbs_inv_status inv_reserve(fbs_inv_store *s, unsigned n) {
  if (!s->txn_active || s->txn_poisoned) return FBS_INV_E_TXN;
  if (n > s->max_txn_ops - s->journal_len) {
    s->txn_poisoned = 1;
    return FBS_INV_E_FULL;
  }
  return FBS_INV_OK;
}

static void inv_j_item(fbs_inv_store *s, uint32_t idx) {
  inv_jrec *j = &s->journal[s->journal_len++];
  j->op = INV_J_ITEM;
  j->idx = idx;
  j->u.item = s->items[idx];
}

static void inv_j_cells(fbs_inv_store *s, uint32_t inv, uint32_t g, unsigned x, unsigned y,
                        unsigned w, unsigned h, uint32_t val) {
  inv_jrec *j = &s->journal[s->journal_len++];
  j->op = INV_J_CELLS;
  j->idx = inv;
  j->u.cells.grid = g;
  j->u.cells.x = x;
  j->u.cells.y = y;
  j->u.cells.w = w;
  j->u.cells.h = h;
  j->u.cells.val = val;
}

static void inv_j_slot(fbs_inv_store *s, uint32_t sl) {
  inv_jrec *j = &s->journal[s->journal_len++];
  j->op = INV_J_SLOT;
  j->idx = sl;
  j->u.val = s->slots[sl].item;
}

static void inv_j_invown(fbs_inv_store *s, uint32_t inv) {
  inv_jrec *j = &s->journal[s->journal_len++];
  j->op = INV_J_INVOWN;
  j->idx = inv;
  j->u.val = s->inventories[inv].owner;
}

/* ------------------------------------------------------------------------- */
/* Mutation helpers                                                          */
/* ------------------------------------------------------------------------- */

/* An inventory is detached when its owner handle no longer names a live item. */
static int inv_detached(const fbs_inv_store *s, uint32_t inv) {
  uint32_t owner = s->inventories[inv].owner;
  return owner != FBS_INV_NONE && !inv_handle_live(s, owner);
}

static int inv_grids_empty(const fbs_inv_store *s, uint32_t inv) {
  const inv_inv_rec *ir = &s->inventories[inv];
  unsigned g;
  for (g = 0u; g < (unsigned)ir->grid_count; ++g) {
    const inv_grid_rec *gr = &s->grids[ir->first_grid + g];
    unsigned n = (unsigned)gr->width * (unsigned)gr->height, k;
    for (k = 0u; k < n; ++k) {
      if (s->cells[gr->cell_off + k] != FBS_INV_NONE) return 0;
    }
  }
  return 1;
}

static int inv_shape_matches(const fbs_inv_store *s, uint32_t inv, const inv_type_rec *t) {
  const inv_inv_rec *ir = &s->inventories[inv];
  unsigned g;
  if ((unsigned)ir->grid_count != (unsigned)t->container_grids) return 0;
  for (g = 0u; g < (unsigned)ir->grid_count; ++g) {
    const inv_grid_rec *gr = &s->grids[ir->first_grid + g];
    if (gr->width != s->cwh[t->cwh_off + g * 2u]) return 0;
    if (gr->height != s->cwh[t->cwh_off + g * 2u + 1u]) return 0;
  }
  return 1;
}

/* Attaches an inventory to a freshly spawned container item. Reuses the
 * lowest-id detached inventory of exactly the right shape whose cells are all
 * free, otherwise carves a new one. Consumes at most one journal record, which
 * the caller has already reserved.
 *
 * `dest` is the inventory the new item is being placed into, and is never a
 * reuse candidate: handing an item the very shell it is standing in would put
 * it inside itself, the cycle E_CYCLE exists to prevent. No other candidate can
 * create a cycle, because an ancestor of `dest` deeper than `dest` itself has a
 * live owner and a reuse candidate by definition does not. */
static uint32_t inv_container_attach(fbs_inv_store *s, const inv_type_rec *t, fbs_inv_item handle,
                                     uint32_t dest, fbs_inv_status *st) {
  uint32_t inv;
  for (inv = 0u; inv < s->c.inventory_count; ++inv) {
    if (inv == dest) continue;
    if (!inv_detached(s, inv)) continue;
    if (!inv_shape_matches(s, inv, t)) continue;
    if (!inv_grids_empty(s, inv)) continue;
    inv_j_invown(s, inv);
    s->inventories[inv].owner = handle;
    *st = FBS_INV_OK;
    return inv;
  }
  inv = inv_inventory_carve(s, s->cwh + t->cwh_off, (unsigned)t->container_grids, st);
  if (inv == FBS_INV_NONE) return FBS_INV_NONE;
  s->inventories[inv].owner = handle;
  return inv;
}

/* Lowest tombstoned slot, else a fresh one. FBS_INV_NONE when max_items is
 * exhausted. Pure: free_hint is advanced only once the caller commits, so a
 * failed spawn cannot perturb which index the next one picks. Every slot below
 * free_hint is live, so this really is the globally lowest tombstone. */
static uint32_t inv_item_slot_pick(const fbs_inv_store *s) {
  uint32_t i;
  for (i = s->free_hint; i < s->c.item_count; ++i) {
    if (s->items[i].state == INV_STATE_NONE) return i;
  }
  if (s->c.item_count >= s->max_items) return FBS_INV_NONE;
  return s->c.item_count;
}

/* Does the ancestor chain of `inv` pass through item `idx`? Fixes I-10 at any
 * depth: owner item -> the inventory holding it -> its owner -> ... */
static int inv_is_descendant(const fbs_inv_store *s, uint32_t inv, uint32_t idx) {
  uint32_t cur = inv;
  unsigned guard = 0u;
  while (guard++ <= s->c.inventory_count) {
    uint32_t owner = s->inventories[cur].owner;
    uint32_t oidx;
    if (owner == FBS_INV_NONE || !inv_handle_live(s, owner)) return 0;
    oidx = inv_handle_index(owner);
    if (oidx == idx) return 1;
    if (s->items[oidx].state != INV_STATE_GRID) return 0; /* equipped: chain ends */
    cur = s->items[oidx].inventory;
  }
  return 0;
}

/* Collects `idx` and, recursively, everything inside it into s->scratch.
 * Returns the number of items collected. */
static unsigned inv_destroy_collect(fbs_inv_store *s, uint32_t idx) {
  unsigned head = 0u, n = 0u;
  s->scratch[n++] = idx;
  while (head < n) {
    uint32_t cur = s->scratch[head++];
    uint32_t inside = s->items[cur].container;
    uint32_t i;
    if (inside == FBS_INV_NONE) continue;
    for (i = 0u; i < s->c.item_count; ++i) {
      if (s->items[i].state == INV_STATE_GRID && s->items[i].inventory == inside &&
          n < s->scratch_cap)
        s->scratch[n++] = i;
    }
  }
  return n;
}

/* Detaches one item from wherever it is (grid cells or equipment slot) and
 * tombstones it. Consumes two journal records, already reserved. */
static void inv_destroy_one(fbs_inv_store *s, uint32_t idx) {
  inv_item_rec *r = &s->items[idx];
  inv_j_item(s, idx);
  if (r->state == INV_STATE_GRID) {
    unsigned fw, fh;
    inv_footprint_of(&s->types[r->type], r->rot, &fw, &fh);
    inv_j_cells(s, r->inventory, r->grid, r->x, r->y, fw, fh, idx);
    inv_stamp(s, r->inventory, r->grid, r->x, r->y, fw, fh, FBS_INV_NONE);
  } else if (r->state == INV_STATE_SLOT) {
    inv_j_slot(s, r->slot);
    s->slots[r->slot].item = FBS_INV_NONE;
  }
  r->type = FBS_INV_NONE;
  r->state = INV_STATE_NONE;
  r->inventory = FBS_INV_NONE;
  r->grid = FBS_INV_NONE;
  r->container = FBS_INV_NONE;
  r->slot = FBS_INV_NONE;
  r->stack = 0u;
  r->x = 0u;
  r->y = 0u;
  r->rot = 0u;
  if (idx < s->free_hint) s->free_hint = idx;
}

/* The whole recursive destroy, including the journal reservation. */
static fbs_inv_status inv_destroy_tree(fbs_inv_store *s, uint32_t idx) {
  unsigned n = inv_destroy_collect(s, idx);
  unsigned i;
  fbs_inv_status st = inv_reserve(s, n * 2u);
  if (st != FBS_INV_OK) return st;
  for (i = 0u; i < n; ++i) inv_destroy_one(s, s->scratch[i]);
  return FBS_INV_OK;
}

/* ------------------------------------------------------------------------- */
/* Mutation                                                                  */
/* ------------------------------------------------------------------------- */

static fbs_inv_status inv_spawn_at(fbs_inv_store *s, uint32_t inv, uint32_t g, uint32_t t,
                                   uint32_t stack, fbs_inv_rot rot, unsigned x, unsigned y,
                                   fbs_inv_item *out) {
  const inv_type_rec *tr;
  inv_item_rec *r;
  fbs_inv_status st;
  uint32_t idx, container = FBS_INV_NONE;
  fbs_inv_item handle;
  unsigned fw, fh;

  st = inv_check_place(s, inv, g, t, rot, x, y, FBS_INV_NONE);
  if (st != FBS_INV_OK) return st;
  tr = &s->types[t];
  if (stack < 1u || stack > tr->max_stack) return FBS_INV_E_RANGE;

  /* One record for the item, one for its cells, one for a reused container
     inventory's owner field. */
  st = inv_reserve(s, tr->container_grids ? 3u : 2u);
  if (st != FBS_INV_OK) return st;

  idx = inv_item_slot_pick(s);
  if (idx == FBS_INV_NONE) return FBS_INV_E_FULL;

  handle = inv_handle(inv_peek_generation(s), idx);
  if (tr->container_grids) {
    container = inv_container_attach(s, tr, handle, inv, &st);
    if (container == FBS_INV_NONE) return st; /* nothing has changed yet */
  }
  (void)inv_next_generation(s);
  if (idx == s->c.item_count) s->c.item_count += 1u;
  s->free_hint = idx + 1u;

  inv_j_item(s, idx);
  r = &s->items[idx];
  r->type = t;
  r->generation = inv_handle_gen(handle);
  r->inventory = inv;
  r->grid = g;
  r->stack = stack;
  r->container = container;
  r->slot = FBS_INV_NONE;
  r->x = (uint16_t)x;
  r->y = (uint16_t)y;
  r->rot = (uint8_t)rot;
  r->state = (uint8_t)INV_STATE_GRID;
  r->pad = 0u;

  inv_footprint_of(tr, (unsigned)rot, &fw, &fh);
  inv_j_cells(s, inv, g, x, y, fw, fh, FBS_INV_NONE);
  inv_stamp(s, inv, g, x, y, fw, fh, idx);

  *out = handle;
  return FBS_INV_OK;
}

fbs_inv_status fbs_inv_spawn_at(fbs_inv_store *s, fbs_inv_inventory inv, fbs_inv_grid g,
                                fbs_inv_type t, uint32_t stack, fbs_inv_rot rot, uint16_t x,
                                uint16_t y, fbs_inv_item *out) {
  fbs_inv_status st;
  if (!s || !out) return FBS_INV_E_INVALID;
  st = inv_reserve(s, 0u);
  if (st != FBS_INV_OK) return st;
  return inv_spawn_at(s, inv, g, t, stack, rot, (unsigned)x, (unsigned)y, out);
}

fbs_inv_status fbs_inv_spawn(fbs_inv_store *s, fbs_inv_inventory inv, fbs_inv_type t,
                             uint32_t stack, int try_rotate, fbs_inv_item *out) {
  fbs_inv_status st;
  uint32_t g;
  unsigned x, y, r;

  if (!s || !out) return FBS_INV_E_INVALID;
  st = inv_reserve(s, 0u);
  if (st != FBS_INV_OK) return st;
  if (inv >= s->c.inventory_count) return FBS_INV_E_INVALID;
  if (t >= s->c.type_count) return FBS_INV_E_INVALID;
  if (stack < 1u || stack > s->types[t].max_stack) return FBS_INV_E_RANGE;
  st = inv_find_place(s, inv, t, try_rotate, FBS_INV_NONE, &g, &x, &y, &r);
  if (st != FBS_INV_OK) return st;
  return inv_spawn_at(s, inv, g, t, stack, (r == 0u) ? FBS_INV_ROT_0 : FBS_INV_ROT_90, x, y, out);
}

fbs_inv_status fbs_inv_destroy(fbs_inv_store *s, fbs_inv_item it) {
  uint32_t idx;
  fbs_inv_status st;
  if (!s) return FBS_INV_E_INVALID;
  st = inv_reserve(s, 0u);
  if (st != FBS_INV_OK) return st;
  st = inv_resolve(s, it, &idx);
  if (st != FBS_INV_OK) return st;
  return inv_destroy_tree(s, idx);
}

fbs_inv_status fbs_inv_move_to(fbs_inv_store *s, fbs_inv_item it, fbs_inv_inventory inv,
                               fbs_inv_grid g, fbs_inv_rot rot, uint16_t x, uint16_t y) {
  inv_item_rec *r;
  uint32_t idx;
  fbs_inv_status st;
  unsigned fw, fh, ofw, ofh;

  if (!s) return FBS_INV_E_INVALID;
  st = inv_reserve(s, 0u);
  if (st != FBS_INV_OK) return st;
  st = inv_resolve(s, it, &idx);
  if (st != FBS_INV_OK) return st;

  if (inv >= s->c.inventory_count) return FBS_INV_E_INVALID;
  if (inv == s->items[idx].container || inv_is_descendant(s, inv, idx)) return FBS_INV_E_CYCLE;
  st = inv_check_place(s, inv, g, s->items[idx].type, rot, (unsigned)x, (unsigned)y, idx);
  if (st != FBS_INV_OK) return st;

  st = inv_reserve(s, 3u);
  if (st != FBS_INV_OK) return st;

  r = &s->items[idx];
  inv_j_item(s, idx);
  if (r->state == INV_STATE_GRID) {
    inv_footprint_of(&s->types[r->type], r->rot, &ofw, &ofh);
    inv_j_cells(s, r->inventory, r->grid, r->x, r->y, ofw, ofh, idx);
    inv_stamp(s, r->inventory, r->grid, r->x, r->y, ofw, ofh, FBS_INV_NONE);
  } else {
    inv_j_slot(s, r->slot);
    s->slots[r->slot].item = FBS_INV_NONE;
  }
  r->inventory = inv;
  r->grid = g;
  r->x = x;
  r->y = y;
  r->rot = (uint8_t)rot;
  r->slot = FBS_INV_NONE;
  r->state = (uint8_t)INV_STATE_GRID;
  inv_footprint_of(&s->types[r->type], (unsigned)rot, &fw, &fh);
  inv_j_cells(s, inv, g, (unsigned)x, (unsigned)y, fw, fh, FBS_INV_NONE);
  inv_stamp(s, inv, g, (unsigned)x, (unsigned)y, fw, fh, idx);
  return FBS_INV_OK;
}

fbs_inv_status fbs_inv_move_auto(fbs_inv_store *s, fbs_inv_item it, fbs_inv_inventory inv,
                                 int try_rotate) {
  uint32_t idx, g;
  unsigned x, y, r;
  fbs_inv_status st;

  if (!s) return FBS_INV_E_INVALID;
  st = inv_reserve(s, 0u);
  if (st != FBS_INV_OK) return st;
  st = inv_resolve(s, it, &idx);
  if (st != FBS_INV_OK) return st;
  if (inv >= s->c.inventory_count) return FBS_INV_E_INVALID;
  if (inv == s->items[idx].container || inv_is_descendant(s, inv, idx)) return FBS_INV_E_CYCLE;
  st = inv_find_place(s, inv, s->items[idx].type, try_rotate, idx, &g, &x, &y, &r);
  if (st != FBS_INV_OK) return st;
  return fbs_inv_move_to(s, it, inv, g, (r == 0u) ? FBS_INV_ROT_0 : FBS_INV_ROT_90, (uint16_t)x,
                         (uint16_t)y);
}

fbs_inv_status fbs_inv_rotate(fbs_inv_store *s, fbs_inv_item it, fbs_inv_rot rot) {
  uint32_t idx;
  fbs_inv_status st;
  if (!s) return FBS_INV_E_INVALID;
  st = inv_reserve(s, 0u);
  if (st != FBS_INV_OK) return st;
  st = inv_resolve(s, it, &idx);
  if (st != FBS_INV_OK) return st;
  st = inv_check_rot(rot);
  if (st != FBS_INV_OK) return st;
  if (s->items[idx].state != INV_STATE_GRID) return FBS_INV_E_NOT_FOUND;
  return fbs_inv_move_to(s, it, s->items[idx].inventory, s->items[idx].grid, rot, s->items[idx].x,
                         s->items[idx].y);
}

/* ------------------------------------------------------------------------- */
/* Stacking                                                                  */
/* ------------------------------------------------------------------------- */

fbs_inv_status fbs_inv_stack_headroom(const fbs_inv_store *s, fbs_inv_item it, uint32_t *out) {
  uint32_t idx;
  fbs_inv_status st;
  if (!s || !out) return FBS_INV_E_INVALID;
  st = inv_resolve(s, it, &idx);
  if (st != FBS_INV_OK) return st;
  *out = s->types[s->items[idx].type].max_stack - s->items[idx].stack;
  return FBS_INV_OK;
}

fbs_inv_status fbs_inv_stack_merge(fbs_inv_store *s, fbs_inv_item dst, fbs_inv_item src,
                                   uint32_t count, uint32_t *out_moved) {
  uint32_t di, si, headroom, moved, want;
  fbs_inv_status st;

  if (!s || !out_moved) return FBS_INV_E_INVALID;
  st = inv_reserve(s, 0u);
  if (st != FBS_INV_OK) return st;
  st = inv_resolve(s, dst, &di);
  if (st != FBS_INV_OK) return st;
  st = inv_resolve(s, src, &si);
  if (st != FBS_INV_OK) return st;
  if (di == si) return FBS_INV_E_INVALID;
  if (s->items[di].type != s->items[si].type) return FBS_INV_E_INVALID; /* fixes I-8 */
  if (count > s->items[si].stack) return FBS_INV_E_RANGE;

  headroom = s->types[s->items[di].type].max_stack - s->items[di].stack; /* fixes I-5 */
  want = count ? count : s->items[si].stack;
  moved = want < s->items[si].stack ? want : s->items[si].stack;
  if (moved > headroom) moved = headroom;
  if (moved == 0u) {
    *out_moved = 0u;
    return FBS_INV_OK;
  }

  if (moved == s->items[si].stack) {
    /* The giver is emptied, so it is destroyed and its handle goes stale
       (fixes I-6). Reserve the destroy's records together with the receiver's. */
    unsigned n = inv_destroy_collect(s, si), i;
    st = inv_reserve(s, 1u + n * 2u);
    if (st != FBS_INV_OK) return st;
    inv_j_item(s, di);
    s->items[di].stack += moved;
    for (i = 0u; i < n; ++i) inv_destroy_one(s, s->scratch[i]);
  } else {
    st = inv_reserve(s, 2u);
    if (st != FBS_INV_OK) return st;
    inv_j_item(s, di);
    inv_j_item(s, si);
    s->items[di].stack += moved;
    s->items[si].stack -= moved;
  }

  *out_moved = moved;
  return FBS_INV_OK;
}

fbs_inv_status fbs_inv_stack_split_to(fbs_inv_store *s, fbs_inv_item src, fbs_inv_inventory inv,
                                      fbs_inv_grid g, fbs_inv_rot rot, uint16_t x, uint16_t y,
                                      uint32_t count, fbs_inv_item *out) {
  uint32_t si;
  fbs_inv_status st;
  fbs_inv_item made = FBS_INV_NONE;

  if (!s || !out) return FBS_INV_E_INVALID;
  st = inv_reserve(s, 0u);
  if (st != FBS_INV_OK) return st;
  st = inv_resolve(s, src, &si);
  if (st != FBS_INV_OK) return st;
  /* A full split is a move, not a split (fixes I-9). */
  if (count < 1u || count >= s->items[si].stack) return FBS_INV_E_RANGE;
  /* Placement is validated before anything is decremented. */
  st = inv_check_place(s, inv, g, s->items[si].type, rot, (unsigned)x, (unsigned)y, FBS_INV_NONE);
  if (st != FBS_INV_OK) return st;
  st = inv_reserve(s, s->types[s->items[si].type].container_grids ? 4u : 3u);
  if (st != FBS_INV_OK) return st;

  st = inv_spawn_at(s, inv, g, s->items[si].type, count, rot, (unsigned)x, (unsigned)y, &made);
  if (st != FBS_INV_OK) return st;
  inv_j_item(s, si);
  s->items[si].stack -= count;
  *out = made;
  return FBS_INV_OK;
}

/* ------------------------------------------------------------------------- */
/* Equipment slots                                                           */
/* ------------------------------------------------------------------------- */

/* A mutator, per the header's transaction paragraph: it needs an open
 * transaction and is undone by abort. Its undo needs no journal record — the
 * slot count and the descending key top are both in the rewound counter block,
 * and abort rebuilds the slot key index whenever the count shrinks. */
fbs_inv_status fbs_inv_slot_add(fbs_inv_store *s, const char *key, size_t key_len,
                                uint64_t accept_tags, fbs_inv_slot *out) {
  inv_slot_rec *r;
  uint32_t sl;
  fbs_inv_status st;

  if (!s || !key || !out) return FBS_INV_E_INVALID;
  st = inv_reserve(s, 0u);
  if (st != FBS_INV_OK) return st;
  if (key_len == 0u || key_len > INV_MAX_KEY_LEN) return FBS_INV_E_INVALID;
  if (inv_slot_hash_find(s, key, key_len) != FBS_INV_NONE) return FBS_INV_E_EXISTS;
  if (s->c.slot_count >= s->max_slots) return FBS_INV_E_FULL;
  if ((size_t)key_len > (size_t)(s->c.key_end - s->c.key_top)) return FBS_INV_E_FULL;

  sl = s->c.slot_count;
  s->c.key_end -= (uint32_t)key_len; /* slot keys grow down, so a clear reclaims them */
  r = &s->slots[sl];
  r->accept_tags = accept_tags;
  r->key_off = s->c.key_end;
  r->key_len = (uint32_t)key_len;
  r->item = FBS_INV_NONE;
  r->pad = 0u;
  memcpy(s->keys + s->c.key_end, key, key_len);
  s->c.slot_count += 1u;
  inv_slot_hash_insert(s, sl);

  *out = sl;
  return FBS_INV_OK;
}

fbs_inv_status fbs_inv_slot_find(const fbs_inv_store *s, const char *key, size_t key_len,
                                 fbs_inv_slot *out) {
  uint32_t sl;
  if (!s || !key || !out) return FBS_INV_E_INVALID;
  if (key_len == 0u || key_len > INV_MAX_KEY_LEN) return FBS_INV_E_INVALID;
  sl = inv_slot_hash_find(s, key, key_len);
  if (sl == FBS_INV_NONE) return FBS_INV_E_NOT_FOUND;
  *out = sl;
  return FBS_INV_OK;
}

fbs_inv_status fbs_inv_slot_item(const fbs_inv_store *s, fbs_inv_slot sl, fbs_inv_item *out) {
  if (!s || !out) return FBS_INV_E_INVALID;
  if (sl >= s->c.slot_count) return FBS_INV_E_INVALID;
  if (s->slots[sl].item == FBS_INV_NONE) return FBS_INV_E_NOT_FOUND;
  *out = s->slots[sl].item;
  return FBS_INV_OK;
}

fbs_inv_status fbs_inv_slot_accepts(const fbs_inv_store *s, fbs_inv_slot sl, fbs_inv_type t) {
  uint64_t mask;
  if (!s) return FBS_INV_E_INVALID;
  if (sl >= s->c.slot_count) return FBS_INV_E_INVALID;
  if (t >= s->c.type_count) return FBS_INV_E_INVALID;
  mask = s->slots[sl].accept_tags;
  if (mask == 0u) return FBS_INV_OK; /* an empty mask accepts anything */
  return (s->types[t].tags & mask) != 0u ? FBS_INV_OK : FBS_INV_E_REJECTED;
}

fbs_inv_status fbs_inv_equip(fbs_inv_store *s, fbs_inv_slot sl, fbs_inv_item it) {
  inv_item_rec *r;
  uint32_t idx;
  fbs_inv_status st;

  if (!s) return FBS_INV_E_INVALID;
  st = inv_reserve(s, 0u);
  if (st != FBS_INV_OK) return st;
  st = inv_resolve(s, it, &idx);
  if (st != FBS_INV_OK) return st;
  if (sl >= s->c.slot_count) return FBS_INV_E_INVALID;
  if (s->slots[sl].item != FBS_INV_NONE) return FBS_INV_E_OCCUPIED; /* fixes I-14 */
  st = fbs_inv_slot_accepts(s, sl, s->items[idx].type);
  if (st != FBS_INV_OK) return st;

  st = inv_reserve(s, 3u);
  if (st != FBS_INV_OK) return st;

  r = &s->items[idx];
  inv_j_item(s, idx);
  if (r->state == INV_STATE_GRID) {
    unsigned fw, fh;
    inv_footprint_of(&s->types[r->type], r->rot, &fw, &fh);
    inv_j_cells(s, r->inventory, r->grid, r->x, r->y, fw, fh, idx);
    inv_stamp(s, r->inventory, r->grid, r->x, r->y, fw, fh, FBS_INV_NONE);
  } else {
    inv_j_slot(s, r->slot);
    s->slots[r->slot].item = FBS_INV_NONE;
  }
  inv_j_slot(s, sl);
  s->slots[sl].item = inv_handle_of(s, idx);
  r->state = (uint8_t)INV_STATE_SLOT;
  r->slot = sl;
  r->inventory = FBS_INV_NONE;
  r->grid = FBS_INV_NONE;
  r->x = 0u;
  r->y = 0u;
  r->rot = 0u;
  return FBS_INV_OK;
}

fbs_inv_status fbs_inv_unequip_to(fbs_inv_store *s, fbs_inv_slot sl, fbs_inv_inventory inv,
                                  int try_rotate) {
  uint32_t idx, g;
  unsigned x, y, r;
  fbs_inv_status st;
  fbs_inv_item it;

  if (!s) return FBS_INV_E_INVALID;
  st = inv_reserve(s, 0u);
  if (st != FBS_INV_OK) return st;
  if (sl >= s->c.slot_count) return FBS_INV_E_INVALID;
  if (inv >= s->c.inventory_count) return FBS_INV_E_INVALID;
  it = s->slots[sl].item;
  if (it == FBS_INV_NONE) return FBS_INV_E_NOT_FOUND;
  st = inv_resolve(s, it, &idx);
  if (st != FBS_INV_OK) return st;
  if (inv == s->items[idx].container || inv_is_descendant(s, inv, idx)) return FBS_INV_E_CYCLE;
  /* Atomic: if it does not fit, the slot is untouched. */
  st = inv_find_place(s, inv, s->items[idx].type, try_rotate, FBS_INV_NONE, &g, &x, &y, &r);
  if (st != FBS_INV_OK) return st;
  return fbs_inv_move_to(s, it, inv, g, (r == 0u) ? FBS_INV_ROT_0 : FBS_INV_ROT_90, (uint16_t)x,
                         (uint16_t)y);
}

/* ------------------------------------------------------------------------- */
/* Serialization (FBIV version 1)                                            */
/* ------------------------------------------------------------------------- */

static void inv_put_u16(unsigned char *p, unsigned v) {
  p[0] = (unsigned char)(v & 0xffu);
  p[1] = (unsigned char)((v >> 8) & 0xffu);
}

static void inv_put_u32(unsigned char *p, uint32_t v) {
  p[0] = (unsigned char)(v & 0xffu);
  p[1] = (unsigned char)((v >> 8) & 0xffu);
  p[2] = (unsigned char)((v >> 16) & 0xffu);
  p[3] = (unsigned char)((v >> 24) & 0xffu);
}

static void inv_put_u64(unsigned char *p, uint64_t v) {
  inv_put_u32(p, (uint32_t)(v & 0xffffffffu));
  inv_put_u32(p + 4, (uint32_t)((v >> 32) & 0xffffffffu));
}

static unsigned inv_get_u16(const unsigned char *p) {
  return (unsigned)p[0] | ((unsigned)p[1] << 8);
}

static uint32_t inv_get_u32(const unsigned char *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t inv_get_u64(const unsigned char *p) {
  return (uint64_t)inv_get_u32(p) | ((uint64_t)inv_get_u32(p + 4) << 32);
}

static size_t inv_key_bytes(const fbs_inv_store *s) {
  size_t n = 0u;
  uint32_t i;
  for (i = 0u; i < s->c.type_count; ++i) n += s->types[i].key_len;
  for (i = 0u; i < s->c.slot_count; ++i) n += s->slots[i].key_len;
  return n;
}

size_t fbs_inv_serialized_size(const fbs_inv_store *s) {
  if (!s) return 0u;
  return (size_t)INV_HEADER_BYTES + (size_t)s->c.type_count * INV_TYPE_BYTES +
         (size_t)s->c.cwh_top * 2u + (size_t)s->c.inventory_count * INV_INVENTORY_BYTES +
         (size_t)s->c.grid_count * INV_GRID_BYTES + (size_t)s->c.item_count * INV_ITEM_BYTES +
         (size_t)s->c.slot_count * INV_SLOT_BYTES + inv_key_bytes(s);
}

fbs_inv_status fbs_inv_serialize(const fbs_inv_store *s, void *buf, size_t cap, size_t *out_len) {
  unsigned char *p;
  size_t need, off;
  uint32_t i, koff;

  if (!s || !out_len) return FBS_INV_E_INVALID;
  if (!buf && cap > 0u) return FBS_INV_E_INVALID;
  need = fbs_inv_serialized_size(s);
  if (cap < need) {
    *out_len = need;
    return FBS_INV_E_TRUNCATED;
  }

  p = (unsigned char *)buf;
  p[0] = 'F';
  p[1] = 'B';
  p[2] = 'I';
  p[3] = 'V';
  inv_put_u16(p + 4, INV_SCHEMA_VERSION);
  inv_put_u16(p + 6, 0u);
  inv_put_u32(p + 8, s->c.type_count);
  inv_put_u32(p + 12, s->c.inventory_count);
  inv_put_u32(p + 16, s->c.grid_count);
  inv_put_u32(p + 20, s->c.item_count);
  inv_put_u32(p + 24, s->c.slot_count);
  inv_put_u32(p + 28, (uint32_t)inv_key_bytes(s));
  inv_put_u32(p + 32, s->c.cwh_top);
  inv_put_u32(p + 36, s->c.next_gen);
  inv_put_u32(p + 40, 0u);
  inv_put_u32(p + 44, 0u);

  off = INV_HEADER_BYTES;
  koff = 0u;
  for (i = 0u; i < s->c.type_count; ++i) {
    const inv_type_rec *r = &s->types[i];
    unsigned char *w = p + off;
    inv_put_u32(w, koff);
    inv_put_u32(w + 4, r->key_len);
    inv_put_u16(w + 8, r->width);
    inv_put_u16(w + 10, r->height);
    inv_put_u32(w + 12, r->max_stack);
    inv_put_u64(w + 16, r->tags);
    inv_put_u32(w + 24, r->container_grids ? r->cwh_off : 0u);
    inv_put_u16(w + 28, r->container_grids);
    inv_put_u16(w + 30, 0u);
    koff += r->key_len;
    off += INV_TYPE_BYTES;
  }

  for (i = 0u; i < s->c.cwh_top; ++i) {
    inv_put_u16(p + off, s->cwh[i]);
    off += 2u;
  }

  for (i = 0u; i < s->c.inventory_count; ++i) {
    const inv_inv_rec *r = &s->inventories[i];
    unsigned char *w = p + off;
    inv_put_u32(w, r->first_grid);
    inv_put_u16(w + 4, r->grid_count);
    inv_put_u16(w + 6, 0u);
    inv_put_u32(w + 8, r->owner);
    inv_put_u32(w + 12, 0u);
    off += INV_INVENTORY_BYTES;
  }

  for (i = 0u; i < s->c.grid_count; ++i) {
    unsigned char *w = p + off;
    inv_put_u16(w, s->grids[i].width);
    inv_put_u16(w + 2, s->grids[i].height);
    inv_put_u32(w + 4, 0u);
    off += INV_GRID_BYTES;
  }

  for (i = 0u; i < s->c.item_count; ++i) {
    const inv_item_rec *r = &s->items[i];
    unsigned char *w = p + off;
    inv_put_u32(w, r->type);
    inv_put_u32(w + 4, r->generation);
    inv_put_u32(w + 8, r->inventory);
    inv_put_u32(w + 12, r->grid);
    inv_put_u16(w + 16, r->x);
    inv_put_u16(w + 18, r->y);
    w[20] = r->rot;
    w[21] = r->state;
    inv_put_u16(w + 22, 0u);
    inv_put_u32(w + 24, r->stack);
    off += INV_ITEM_BYTES;
  }

  for (i = 0u; i < s->c.slot_count; ++i) {
    const inv_slot_rec *r = &s->slots[i];
    unsigned char *w = p + off;
    inv_put_u32(w, koff);
    inv_put_u32(w + 4, r->key_len);
    inv_put_u64(w + 8, r->accept_tags);
    inv_put_u32(w + 16, r->item);
    inv_put_u32(w + 20, 0u);
    koff += r->key_len;
    off += INV_SLOT_BYTES;
  }

  for (i = 0u; i < s->c.type_count; ++i) {
    memcpy(p + off, s->keys + s->types[i].key_off, (size_t)s->types[i].key_len);
    off += s->types[i].key_len;
  }
  for (i = 0u; i < s->c.slot_count; ++i) {
    memcpy(p + off, s->keys + s->slots[i].key_off, (size_t)s->slots[i].key_len);
    off += s->slots[i].key_len;
  }

  *out_len = need;
  return FBS_INV_OK;
}

/* Blob cursor set, filled in once the header has been validated. */
typedef struct inv_blob {
  const unsigned char *types;
  const unsigned char *cwh;
  const unsigned char *invs;
  const unsigned char *grids;
  const unsigned char *items;
  const unsigned char *slots;
  const unsigned char *keys;
  uint32_t type_count, inventory_count, grid_count, item_count, slot_count, key_bytes, cwh_len,
      next_gen;
} inv_blob;

static const unsigned char *inv_rec(const unsigned char *base, uint32_t i, unsigned stride) {
  return base + (size_t)i * stride;
}

/* Full structural validation, allocation-free. */
static fbs_inv_status inv_blob_validate(const inv_blob *b, unsigned *out_max_dim,
                                        size_t *out_cells) {
  uint32_t i, j, koff, cwh_off, first_grid;
  size_t total_cells = 0u;
  unsigned max_dim = 1u;

  if (b->next_gen < INV_GEN_MIN || b->next_gen > INV_GEN_MAX) return FBS_INV_E_SCHEMA;

  /* Types: canonical key and container_wh layout, every field in range. */
  koff = 0u;
  cwh_off = 0u;
  for (i = 0u; i < b->type_count; ++i) {
    const unsigned char *r = inv_rec(b->types, i, INV_TYPE_BYTES);
    uint32_t ko = inv_get_u32(r), kl = inv_get_u32(r + 4);
    unsigned w = inv_get_u16(r + 8), h = inv_get_u16(r + 10);
    uint32_t ms = inv_get_u32(r + 12);
    uint32_t co = inv_get_u32(r + 24);
    unsigned cg = inv_get_u16(r + 28);
    if (inv_get_u16(r + 30) != 0u) return FBS_INV_E_SCHEMA;
    if (kl == 0u || kl > INV_MAX_KEY_LEN || ko != koff || kl > b->key_bytes - koff)
      return FBS_INV_E_SCHEMA;
    koff += kl;
    if (w < 1u || w > INV_MAX_GRID_DIM || h < 1u || h > INV_MAX_GRID_DIM) return FBS_INV_E_SCHEMA;
    if (ms < 1u || ms > INV_MAX_STACK) return FBS_INV_E_SCHEMA;
    if (cg > INV_MAX_CONTAINER_GRIDS) return FBS_INV_E_SCHEMA;
    if (cg > 0u && ms != 1u) return FBS_INV_E_SCHEMA; /* no stackable containers */
    if (cg == 0u) {
      if (co != 0u) return FBS_INV_E_SCHEMA;
    } else {
      if (co != cwh_off || cg * 2u > b->cwh_len - cwh_off) return FBS_INV_E_SCHEMA;
      cwh_off += cg * 2u;
    }
    if (w > max_dim) max_dim = w;
    if (h > max_dim) max_dim = h;
  }
  if (cwh_off != b->cwh_len) return FBS_INV_E_SCHEMA;

  for (i = 0u; i < b->cwh_len; ++i) {
    unsigned v = inv_get_u16(b->cwh + (size_t)i * 2u);
    if (v < 1u || v > INV_MAX_GRID_DIM) return FBS_INV_E_SCHEMA;
    if (v > max_dim) max_dim = v;
  }

  /* Grids. */
  for (i = 0u; i < b->grid_count; ++i) {
    const unsigned char *r = inv_rec(b->grids, i, INV_GRID_BYTES);
    unsigned w = inv_get_u16(r), h = inv_get_u16(r + 2);
    if (inv_get_u32(r + 4) != 0u) return FBS_INV_E_SCHEMA;
    if (w < 1u || w > INV_MAX_GRID_DIM || h < 1u || h > INV_MAX_GRID_DIM) return FBS_INV_E_SCHEMA;
    total_cells += (size_t)w * (size_t)h;
    if (w > max_dim) max_dim = w;
    if (h > max_dim) max_dim = h;
  }
  if (total_cells > INV_MAX_CELLS) return FBS_INV_E_SCHEMA;

  /* Inventories: contiguous grid ranges in id order. */
  first_grid = 0u;
  for (i = 0u; i < b->inventory_count; ++i) {
    const unsigned char *r = inv_rec(b->invs, i, INV_INVENTORY_BYTES);
    uint32_t fg = inv_get_u32(r);
    unsigned gc = inv_get_u16(r + 4);
    uint32_t owner = inv_get_u32(r + 8);
    if (inv_get_u16(r + 6) != 0u || inv_get_u32(r + 12) != 0u) return FBS_INV_E_SCHEMA;
    if (gc == 0u || fg != first_grid || gc > b->grid_count - first_grid) return FBS_INV_E_SCHEMA;
    first_grid += gc;
    if (owner != FBS_INV_NONE && inv_handle_index(owner) >= b->item_count) return FBS_INV_E_SCHEMA;
    if (owner != FBS_INV_NONE) {
      uint32_t g = inv_handle_gen(owner);
      if (g < INV_GEN_MIN || g > INV_GEN_MAX) return FBS_INV_E_SCHEMA;
    }
  }
  if (first_grid != b->grid_count) return FBS_INV_E_SCHEMA;

  /* Items. */
  for (i = 0u; i < b->item_count; ++i) {
    const unsigned char *r = inv_rec(b->items, i, INV_ITEM_BYTES);
    uint32_t type = inv_get_u32(r), gen = inv_get_u32(r + 4);
    uint32_t inv = inv_get_u32(r + 8), grid = inv_get_u32(r + 12);
    unsigned x = inv_get_u16(r + 16), y = inv_get_u16(r + 18);
    unsigned rot = r[20], state = r[21];
    uint32_t stack = inv_get_u32(r + 24);
    if (inv_get_u16(r + 22) != 0u) return FBS_INV_E_SCHEMA;
    if (gen < INV_GEN_MIN || gen > INV_GEN_MAX) return FBS_INV_E_SCHEMA;
    if (rot > 1u || state > INV_STATE_SLOT) return FBS_INV_E_SCHEMA;
    if (state == INV_STATE_NONE) {
      if (type != FBS_INV_NONE || inv != FBS_INV_NONE || grid != FBS_INV_NONE) return FBS_INV_E_SCHEMA;
      if (x != 0u || y != 0u || rot != 0u || stack != 0u) return FBS_INV_E_SCHEMA;
      continue;
    }
    if (type >= b->type_count) return FBS_INV_E_SCHEMA;
    if (stack < 1u || stack > inv_get_u32(inv_rec(b->types, type, INV_TYPE_BYTES) + 12))
      return FBS_INV_E_SCHEMA;
    if (state == INV_STATE_SLOT) {
      if (inv != FBS_INV_NONE || grid != FBS_INV_NONE) return FBS_INV_E_SCHEMA;
      if (x != 0u || y != 0u || rot != 0u) return FBS_INV_E_SCHEMA;
    } else {
      const unsigned char *ir;
      const unsigned char *gr;
      unsigned gw, gh, tw, th, fw, fh;
      if (inv >= b->inventory_count) return FBS_INV_E_SCHEMA;
      ir = inv_rec(b->invs, inv, INV_INVENTORY_BYTES);
      if (grid >= (uint32_t)inv_get_u16(ir + 4)) return FBS_INV_E_SCHEMA;
      gr = inv_rec(b->grids, inv_get_u32(ir) + grid, INV_GRID_BYTES);
      gw = inv_get_u16(gr);
      gh = inv_get_u16(gr + 2);
      tw = inv_get_u16(inv_rec(b->types, type, INV_TYPE_BYTES) + 8);
      th = inv_get_u16(inv_rec(b->types, type, INV_TYPE_BYTES) + 10);
      fw = rot == 0u ? tw : th;
      fh = rot == 0u ? th : tw;
      if (fw > gw || fh > gh || x > gw - fw || y > gh - fh) return FBS_INV_E_SCHEMA;
    }
  }

  /* No two placed items may overlap. Quadratic in the number of placed items
   * sharing a grid, which is what keeps the check allocation-free; blobs are
   * validated before a single byte is allocated (T-8b). */
  for (i = 0u; i < b->item_count; ++i) {
    const unsigned char *a = inv_rec(b->items, i, INV_ITEM_BYTES);
    unsigned ax, ay, afw, afh, arot, tw, th;
    uint32_t ainv, agrid, atype;
    if (a[21] != INV_STATE_GRID) continue;
    atype = inv_get_u32(a);
    ainv = inv_get_u32(a + 8);
    agrid = inv_get_u32(a + 12);
    ax = inv_get_u16(a + 16);
    ay = inv_get_u16(a + 18);
    arot = a[20];
    tw = inv_get_u16(inv_rec(b->types, atype, INV_TYPE_BYTES) + 8);
    th = inv_get_u16(inv_rec(b->types, atype, INV_TYPE_BYTES) + 10);
    afw = arot == 0u ? tw : th;
    afh = arot == 0u ? th : tw;
    for (j = 0u; j < i; ++j) {
      const unsigned char *c = inv_rec(b->items, j, INV_ITEM_BYTES);
      unsigned cx, cy, cfw, cfh, crot;
      uint32_t ctype;
      if (c[21] != INV_STATE_GRID) continue;
      if (inv_get_u32(c + 8) != ainv || inv_get_u32(c + 12) != agrid) continue;
      ctype = inv_get_u32(c);
      cx = inv_get_u16(c + 16);
      cy = inv_get_u16(c + 18);
      crot = c[20];
      tw = inv_get_u16(inv_rec(b->types, ctype, INV_TYPE_BYTES) + 8);
      th = inv_get_u16(inv_rec(b->types, ctype, INV_TYPE_BYTES) + 10);
      cfw = crot == 0u ? tw : th;
      cfh = crot == 0u ? th : tw;
      if (ax < cx + cfw && cx < ax + afw && ay < cy + cfh && cy < ay + afh)
        return FBS_INV_E_SCHEMA;
    }
  }

  /* Equipment slots: canonical keys, and at most one slot per item. */
  for (i = 0u; i < b->slot_count; ++i) {
    const unsigned char *r = inv_rec(b->slots, i, INV_SLOT_BYTES);
    uint32_t ko = inv_get_u32(r), kl = inv_get_u32(r + 4), item = inv_get_u32(r + 16);
    if (inv_get_u32(r + 20) != 0u) return FBS_INV_E_SCHEMA;
    if (kl == 0u || kl > INV_MAX_KEY_LEN || ko != koff || kl > b->key_bytes - koff)
      return FBS_INV_E_SCHEMA;
    koff += kl;
    if (item == FBS_INV_NONE) continue;
    {
      uint32_t idx = inv_handle_index(item);
      const unsigned char *ir;
      if (idx >= b->item_count) return FBS_INV_E_SCHEMA;
      ir = inv_rec(b->items, idx, INV_ITEM_BYTES);
      if (ir[21] != INV_STATE_SLOT) return FBS_INV_E_SCHEMA;
      if (inv_get_u32(ir + 4) != inv_handle_gen(item)) return FBS_INV_E_SCHEMA;
      for (j = 0u; j < i; ++j) {
        if (inv_get_u32(inv_rec(b->slots, j, INV_SLOT_BYTES) + 16) == item)
          return FBS_INV_E_SCHEMA;
      }
    }
  }
  if (koff != b->key_bytes) return FBS_INV_E_SCHEMA;

  /* Every equipped item is held by exactly one slot. */
  for (i = 0u; i < b->item_count; ++i) {
    const unsigned char *r = inv_rec(b->items, i, INV_ITEM_BYTES);
    int found = 0;
    if (r[21] != INV_STATE_SLOT) continue;
    for (j = 0u; j < b->slot_count && !found; ++j) {
      /* an empty slot is FBS_INV_NONE, whose index bits are 0xFFFF: never a
         match, whatever max_items allows */
      uint32_t held = inv_get_u32(inv_rec(b->slots, j, INV_SLOT_BYTES) + 16);
      if (held != FBS_INV_NONE && inv_handle_index(held) == i) found = 1;
    }
    if (!found) return FBS_INV_E_SCHEMA;
  }

  /* Container links: at most one live owner per inventory, and exactly one
   * inventory per live container item. A DETACHED inventory (its owner handle
   * no longer resolves) may hold items: nothing stops a caller placing items
   * into a shell whose container has been destroyed, so the serializer can
   * legitimately emit that state and the loader must accept it. The runtime
   * recycling rule protects itself instead, by refusing to reuse a shell whose
   * cells are not all free. */
  for (i = 0u; i < b->inventory_count; ++i) {
    uint32_t owner = inv_get_u32(inv_rec(b->invs, i, INV_INVENTORY_BYTES) + 8);
    uint32_t idx;
    const unsigned char *ir;
    int live;
    if (owner == FBS_INV_NONE) continue;
    idx = inv_handle_index(owner);
    ir = inv_rec(b->items, idx, INV_ITEM_BYTES);
    live = ir[21] != INV_STATE_NONE && inv_get_u32(ir + 4) == inv_handle_gen(owner);
    if (live) {
      const unsigned char *tr = inv_rec(b->types, inv_get_u32(ir), INV_TYPE_BYTES);
      unsigned cg = inv_get_u16(tr + 28), gc = inv_get_u16(inv_rec(b->invs, i, INV_INVENTORY_BYTES) + 4);
      uint32_t co = inv_get_u32(tr + 24), fg = inv_get_u32(inv_rec(b->invs, i, INV_INVENTORY_BYTES));
      unsigned k;
      if (cg == 0u || cg != gc) return FBS_INV_E_SCHEMA;
      for (k = 0u; k < gc; ++k) {
        const unsigned char *gr = inv_rec(b->grids, fg + k, INV_GRID_BYTES);
        if (inv_get_u16(gr) != inv_get_u16(b->cwh + (size_t)(co + k * 2u) * 2u))
          return FBS_INV_E_SCHEMA;
        if (inv_get_u16(gr + 2) != inv_get_u16(b->cwh + (size_t)(co + k * 2u + 1u) * 2u))
          return FBS_INV_E_SCHEMA;
      }
      for (j = 0u; j < i; ++j) {
        if (inv_get_u32(inv_rec(b->invs, j, INV_INVENTORY_BYTES) + 8) == owner)
          return FBS_INV_E_SCHEMA;
      }
    }
  }
  for (i = 0u; i < b->item_count; ++i) {
    const unsigned char *r = inv_rec(b->items, i, INV_ITEM_BYTES);
    unsigned owned = 0u;
    if (r[21] == INV_STATE_NONE) continue;
    for (j = 0u; j < b->inventory_count; ++j) {
      uint32_t owner = inv_get_u32(inv_rec(b->invs, j, INV_INVENTORY_BYTES) + 8);
      if (owner != FBS_INV_NONE && inv_handle_index(owner) == i &&
          inv_get_u32(r + 4) == inv_handle_gen(owner))
        ++owned;
    }
    if (owned != (inv_get_u16(inv_rec(b->types, inv_get_u32(r), INV_TYPE_BYTES) + 28) ? 1u : 0u))
      return FBS_INV_E_SCHEMA;
  }

  /* Duplicate keys are rejected before anything is allocated. */
  for (i = 0u; i < b->type_count; ++i) {
    const unsigned char *a = inv_rec(b->types, i, INV_TYPE_BYTES);
    for (j = 0u; j < i; ++j) {
      const unsigned char *c = inv_rec(b->types, j, INV_TYPE_BYTES);
      if (inv_get_u32(a + 4) != inv_get_u32(c + 4)) continue;
      if (memcmp(b->keys + inv_get_u32(a), b->keys + inv_get_u32(c), inv_get_u32(a + 4)) == 0)
        return FBS_INV_E_SCHEMA;
    }
  }
  for (i = 0u; i < b->slot_count; ++i) {
    const unsigned char *a = inv_rec(b->slots, i, INV_SLOT_BYTES);
    for (j = 0u; j < i; ++j) {
      const unsigned char *c = inv_rec(b->slots, j, INV_SLOT_BYTES);
      if (inv_get_u32(a + 4) != inv_get_u32(c + 4)) continue;
      if (memcmp(b->keys + inv_get_u32(a), b->keys + inv_get_u32(c), inv_get_u32(a + 4)) == 0)
        return FBS_INV_E_SCHEMA;
    }
  }

  *out_max_dim = max_dim;
  *out_cells = total_cells;
  return FBS_INV_OK;
}

fbs_inv_status fbs_inv_deserialize(const void *buf, size_t len, const fbs_inv_config *cfg,
                                   const fbs_inv_allocator *alloc, fbs_inv_store **out) {
  const unsigned char *p = (const unsigned char *)buf;
  inv_blob b;
  fbs_inv_config c;
  fbs_inv_store *s = NULL;
  fbs_inv_status st;
  size_t need, total_cells = 0u;
  unsigned max_dim = 1u;
  uint32_t i, koff;

  if (!buf || !out) return FBS_INV_E_INVALID;
  if (cfg && !inv_config_valid(cfg)) return FBS_INV_E_INVALID;

  if (len < (size_t)INV_HEADER_BYTES) return FBS_INV_E_SCHEMA;
  if (p[0] != 'F' || p[1] != 'B' || p[2] != 'I' || p[3] != 'V') return FBS_INV_E_SCHEMA;
  if (inv_get_u16(p + 4) != INV_SCHEMA_VERSION) return FBS_INV_E_SCHEMA;
  if (inv_get_u16(p + 6) != 0u) return FBS_INV_E_SCHEMA;
  if (inv_get_u32(p + 40) != 0u || inv_get_u32(p + 44) != 0u) return FBS_INV_E_SCHEMA;

  b.type_count = inv_get_u32(p + 8);
  b.inventory_count = inv_get_u32(p + 12);
  b.grid_count = inv_get_u32(p + 16);
  b.item_count = inv_get_u32(p + 20);
  b.slot_count = inv_get_u32(p + 24);
  b.key_bytes = inv_get_u32(p + 28);
  b.cwh_len = inv_get_u32(p + 32);
  b.next_gen = inv_get_u32(p + 36);

  if (b.type_count > INV_MAX_TYPES || b.inventory_count > INV_MAX_INVENTORIES ||
      b.grid_count > INV_MAX_GRIDS || b.item_count > INV_MAX_ITEMS ||
      b.slot_count > INV_MAX_SLOTS || b.key_bytes > INV_MAX_KEY_BYTES ||
      b.cwh_len > (uint32_t)INV_MAX_TYPES * 2u * INV_MAX_CONTAINER_GRIDS)
    return FBS_INV_E_SCHEMA;

  need = (size_t)INV_HEADER_BYTES + (size_t)b.type_count * INV_TYPE_BYTES +
         (size_t)b.cwh_len * 2u + (size_t)b.inventory_count * INV_INVENTORY_BYTES +
         (size_t)b.grid_count * INV_GRID_BYTES + (size_t)b.item_count * INV_ITEM_BYTES +
         (size_t)b.slot_count * INV_SLOT_BYTES + (size_t)b.key_bytes;
  if (len != need) return FBS_INV_E_SCHEMA;

  b.types = p + INV_HEADER_BYTES;
  b.cwh = b.types + (size_t)b.type_count * INV_TYPE_BYTES;
  b.invs = b.cwh + (size_t)b.cwh_len * 2u;
  b.grids = b.invs + (size_t)b.inventory_count * INV_INVENTORY_BYTES;
  b.items = b.grids + (size_t)b.grid_count * INV_GRID_BYTES;
  b.slots = b.items + (size_t)b.item_count * INV_ITEM_BYTES;
  b.keys = (const unsigned char *)(b.slots + (size_t)b.slot_count * INV_SLOT_BYTES);

  st = inv_blob_validate(&b, &max_dim, &total_cells);
  if (st != FBS_INV_OK) return st;

  if (cfg) {
    c = *cfg;
    if (c.max_types < b.type_count || c.max_inventories < b.inventory_count ||
        c.max_grids < b.grid_count || c.max_cells < total_cells || c.max_items < b.item_count ||
        c.max_slots < b.slot_count || c.max_key_bytes < b.key_bytes)
      return FBS_INV_E_FULL;
    if ((unsigned)c.max_grid_dim < max_dim) return FBS_INV_E_RANGE;
  } else {
    c = fbs_inv_config_default();
    if (c.max_types < b.type_count) c.max_types = b.type_count;
    if (c.max_inventories < b.inventory_count) c.max_inventories = b.inventory_count;
    if (c.max_grids < b.grid_count) c.max_grids = b.grid_count;
    if ((size_t)c.max_cells < total_cells) c.max_cells = (unsigned)total_cells;
    if (c.max_items < b.item_count) c.max_items = b.item_count;
    if (c.max_slots < b.slot_count) c.max_slots = b.slot_count;
    if (c.max_key_bytes < b.key_bytes) c.max_key_bytes = b.key_bytes;
    if ((unsigned)c.max_grid_dim < max_dim) c.max_grid_dim = (uint16_t)max_dim;
  }

  st = inv_store_alloc(&c, alloc, &s);
  if (st != FBS_INV_OK) return st;

  /* Types, and their container_wh, in id order. */
  koff = 0u;
  for (i = 0u; i < b.type_count; ++i) {
    const unsigned char *r = inv_rec(b.types, i, INV_TYPE_BYTES);
    inv_type_rec *t = &s->types[i];
    t->tags = inv_get_u64(r + 16);
    t->key_off = s->c.key_top;
    t->key_len = inv_get_u32(r + 4);
    t->max_stack = inv_get_u32(r + 12);
    t->cwh_off = inv_get_u32(r + 24);
    t->width = (uint16_t)inv_get_u16(r + 8);
    t->height = (uint16_t)inv_get_u16(r + 10);
    t->container_grids = (uint16_t)inv_get_u16(r + 28);
    t->pad = 0u;
    memcpy(s->keys + s->c.key_top, b.keys + koff, (size_t)t->key_len);
    s->c.key_top += t->key_len;
    koff += t->key_len;
    s->c.type_count += 1u;
    inv_type_hash_insert(s, i);
  }
  for (i = 0u; i < b.cwh_len; ++i) s->cwh[i] = (uint16_t)inv_get_u16(b.cwh + (size_t)i * 2u);
  s->c.cwh_top = b.cwh_len;

  /* Inventories and their grids; cells start empty. */
  for (i = 0u; i < b.inventory_count; ++i) {
    const unsigned char *r = inv_rec(b.invs, i, INV_INVENTORY_BYTES);
    s->inventories[i].first_grid = inv_get_u32(r);
    s->inventories[i].grid_count = (uint16_t)inv_get_u16(r + 4);
    s->inventories[i].owner = inv_get_u32(r + 8);
    s->inventories[i].pad = 0u;
  }
  s->c.inventory_count = b.inventory_count;
  for (i = 0u; i < b.grid_count; ++i) {
    const unsigned char *r = inv_rec(b.grids, i, INV_GRID_BYTES);
    unsigned w = inv_get_u16(r), h = inv_get_u16(r + 2), k;
    s->grids[i].width = (uint16_t)w;
    s->grids[i].height = (uint16_t)h;
    s->grids[i].cell_off = s->c.cell_top;
    for (k = 0u; k < w * h; ++k) s->cells[s->c.cell_top + k] = FBS_INV_NONE;
    s->c.cell_top += w * h;
  }
  s->c.grid_count = b.grid_count;

  /* Items, then the cells rebuilt from their anchors (cells are never
     serialized). */
  for (i = 0u; i < b.item_count; ++i) {
    const unsigned char *r = inv_rec(b.items, i, INV_ITEM_BYTES);
    inv_item_rec *t = &s->items[i];
    t->type = inv_get_u32(r);
    t->generation = inv_get_u32(r + 4);
    t->inventory = inv_get_u32(r + 8);
    t->grid = inv_get_u32(r + 12);
    t->stack = inv_get_u32(r + 24);
    t->container = FBS_INV_NONE;
    t->slot = FBS_INV_NONE;
    t->x = (uint16_t)inv_get_u16(r + 16);
    t->y = (uint16_t)inv_get_u16(r + 18);
    t->rot = r[20];
    t->state = r[21];
    t->pad = 0u;
  }
  s->c.item_count = b.item_count;
  for (i = 0u; i < b.item_count; ++i) {
    const inv_item_rec *t = &s->items[i];
    unsigned fw, fh;
    if (t->state != INV_STATE_GRID) continue;
    inv_footprint_of(&s->types[t->type], t->rot, &fw, &fh);
    inv_stamp(s, t->inventory, t->grid, t->x, t->y, fw, fh, i);
  }

  /* Slots, and the two back-links the blob does not store. */
  for (i = 0u; i < b.slot_count; ++i) {
    const unsigned char *r = inv_rec(b.slots, i, INV_SLOT_BYTES);
    inv_slot_rec *t = &s->slots[i];
    t->accept_tags = inv_get_u64(r + 8);
    t->key_len = inv_get_u32(r + 4);
    s->c.key_end -= t->key_len;
    t->key_off = s->c.key_end;
    t->item = inv_get_u32(r + 16);
    t->pad = 0u;
    memcpy(s->keys + t->key_off, b.keys + koff, (size_t)t->key_len);
    koff += t->key_len;
    s->c.slot_count += 1u;
    inv_slot_hash_insert(s, i);
    if (t->item != FBS_INV_NONE) s->items[inv_handle_index(t->item)].slot = i;
  }
  for (i = 0u; i < b.inventory_count; ++i) {
    uint32_t owner = s->inventories[i].owner;
    if (owner != FBS_INV_NONE && inv_handle_live(s, owner))
      s->items[inv_handle_index(owner)].container = i;
  }

  s->c.next_gen = b.next_gen;
  s->gen_floor = b.next_gen;
  s->sealed = 1u; /* a deserialized store is sealed, with no transaction open */
  s->free_hint = 0u;

  *out = s;
  return FBS_INV_OK;
}
