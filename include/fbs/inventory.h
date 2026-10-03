
/*
 * fbs/inventory.h — FinalBuildSystems spatial (grid) inventory. C99, engine
 * independent, no libm, no floating point.
 *
 * Model (decision: docs/decisions/inventory.md §4): a STORE owns an item-TYPE
 * catalog (footprint, stack cap, tag bits, optional container grids), a set of
 * INVENTORIES each of which is an ordered list of independent rectangular
 * GRIDS, a set of ITEM instances placed at an anchor cell with one rotation
 * bit, and a set of equipment SLOTS holding one item each. One allocation,
 * sized by fbs_inv_config; nothing grows after create. Item and equipment
 * mutations require a TRANSACTION. Type/inventory registration can also run
 * outside one; abort removes registrations made inside it. Sealing, clearing
 * and the unserialized generation floor are not rolled back. Errors
 * leave outputs untouched except FBS_INV_E_TRUNCATED (required size reported).
 * Decision record: docs/decisions/inventory.md section 9. Out of scope for
 * 0.1.0 (additive later): weight/count constraints, non-rectangular
 * footprints, 180/270 rotations, replication.
 */
#ifndef FBS_INV_H
#define FBS_INV_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FBS_INV_VERSION 100 /* major * 10000 + minor * 100 + patch */

/* ---- handles -------------------------------------------------------- */
/* Type, inventory and slot IDs are dense 32-bit indices; NONE is invalid.
   Item handles pack a slot index in the low 16 bits and a generation in the
   high 16 bits. Accessors reject destroyed slots and generation mismatches.
   The store-wide generation counter cycles through 1..65534: sufficiently
   old handles can alias new items after wrap (ledger C031). Handles are not
   identities across stores or save reloads. An unserialized store-local floor
   prevents immediate reuse after abort while the serialized counter rewinds,
   but the floor also wraps. Deserialize starts it at the blob's counter. */
typedef uint32_t fbs_inv_type;
typedef uint32_t fbs_inv_inventory;
typedef uint32_t fbs_inv_grid;    /* grid index WITHIN its inventory */
typedef uint32_t fbs_inv_item;
typedef uint32_t fbs_inv_slot;

#define FBS_INV_NONE ((uint32_t)0xFFFFFFFFu)

typedef enum fbs_inv_rot {
  FBS_INV_ROT_0  = 0,  /* footprint (w, h) */
  FBS_INV_ROT_90 = 1   /* footprint (h, w), anchored at the same top-left cell */
  /* 2 and 3 are reserved for 180/270 and currently return FBS_INV_E_RANGE. */
} fbs_inv_rot;

typedef enum fbs_inv_status {
  FBS_INV_OK           =  0,
  FBS_INV_E_INVALID    = -1,  /* NULL pointer, unknown id, empty key, invalid config */
  FBS_INV_E_NOT_FOUND  = -2,  /* no type/slot with that key; no item at that cell */
  FBS_INV_E_EXISTS     = -3,  /* key already registered; *out untouched */
  FBS_INV_E_FULL       = -4,  /* a config capacity is exhausted (types, items, grids, cells, keys, journal) */
  FBS_INV_E_RANGE      = -5,  /* dimension/stack/count out of range; reserved rotation; count > stack */
  FBS_INV_E_NO_SPACE   = -6,  /* placement is out of bounds or overlaps an occupied cell */
  FBS_INV_E_OCCUPIED   = -7,  /* equipment slot already holds an item */
  FBS_INV_E_REJECTED   = -8,  /* slot tag mask refuses this item type */
  FBS_INV_E_CYCLE      = -9,  /* destination inventory is the item itself or a descendant */
  FBS_INV_E_STALE      = -10, /* handle refers to a destroyed item (generation mismatch) */
  FBS_INV_E_SCHEMA     = -11, /* blob magic/version/length/consistency mismatch, or a rebuild that overlaps */
  FBS_INV_E_TRUNCATED  = -12, /* output too small; required count/length written */
  FBS_INV_E_SEALED     = -13, /* type registration attempted after fbs_inv_seal */
  FBS_INV_E_TXN        = -14, /* nested begin, required txn absent, or a poisoned txn */
  FBS_INV_E_MEMORY     = -15  /* allocator returned NULL */
} fbs_inv_status;

const char *fbs_inv_status_name(int status);
unsigned    fbs_inv_version(void);

typedef struct fbs_inv_allocator {
  void *(*alloc)(void *user, size_t bytes);
  void  (*free)(void *user, void *ptr);
  void *user;
} fbs_inv_allocator;

/* ---- store ---------------------------------------------------------- */

typedef struct fbs_inv_config {
  unsigned max_types;        /* 1..4096 */
  unsigned max_inventories;  /* 1..4096 */
  unsigned max_grids;        /* total grids across all inventories, 1..16384 */
  unsigned max_cells;        /* total cells across all grids, 1..(1<<22) */
  unsigned max_items;        /* live + tombstoned instance slots, 1..65535 */
  unsigned max_slots;        /* equipment slots, 0..1024 */
  unsigned max_key_bytes;    /* type + slot key storage, 1..(1<<22) */
  unsigned max_txn_ops;      /* undo-journal depth, 8..65536 */
  uint16_t max_grid_dim;     /* per-axis cap on any grid, 1..1024 (default 64) */
} fbs_inv_config;

/* 64 types, 32 inventories, 128 grids, 8192 cells, 1024 items, 32 slots,
   4096 key bytes, 256 journal ops, 64 max grid dim. */
fbs_inv_config fbs_inv_config_default(void);

typedef struct fbs_inv_store fbs_inv_store;

fbs_inv_status fbs_inv_store_create(const fbs_inv_config *cfg, const fbs_inv_allocator *alloc,
                                    fbs_inv_store **out);
void           fbs_inv_store_destroy(fbs_inv_store *s);
/* Removes every inventory, item and slot and any open transaction; keeps the
 * type catalog and its seal. Generation counters survive clear but still wrap. */
void           fbs_inv_store_clear(fbs_inv_store *s);
size_t         fbs_inv_store_memory(const fbs_inv_store *s);

/* ---- item types (catalog) ------------------------------------------- */
/* Keys are byte strings (UTF-8 by convention), compared bytewise, 1..255
   bytes, copied. Registration is only legal before fbs_inv_seal. */

typedef struct fbs_inv_type_desc {
  uint16_t  width;              /* 1..max_grid_dim */
  uint16_t  height;             /* 1..max_grid_dim */
  uint32_t  max_stack;          /* 1..(1<<24); 1 means not stackable */
  uint64_t  tags;               /* bitset; equipment slots match with & */
  const uint16_t *container_wh; /* 2*container_grids entries: w0,h0,w1,h1,...  NULL if not a container */
  uint16_t  container_grids;    /* 0 = ordinary item; >0 = this item owns an inventory of that many grids (<= 64);
                                   a container type must have max_stack == 1 (E_RANGE otherwise) */
} fbs_inv_type_desc;
/* container_wh is copied at registration; fbs_inv_type_desc_get returns a
 * pointer into the store's copy while that registration survives. Abort can
 * remove a type registered in the transaction; later registration may reuse
 * its storage. Destruction invalidates all borrowed pointers. */

fbs_inv_status fbs_inv_type_add(fbs_inv_store *s, const char *key, size_t key_len,
                                const fbs_inv_type_desc *desc, fbs_inv_type *out);
fbs_inv_status fbs_inv_type_find(const fbs_inv_store *s, const char *key, size_t key_len,
                                 fbs_inv_type *out);
fbs_inv_status fbs_inv_type_key (const fbs_inv_store *s, fbs_inv_type t,
                                 const char **out_key, size_t *out_len);
fbs_inv_status fbs_inv_type_desc_get(const fbs_inv_store *s, fbs_inv_type t, fbs_inv_type_desc *out);
unsigned       fbs_inv_type_count(const fbs_inv_store *s);
/* Freezes the catalog. Type ids are stable and are what the blob stores.
   Sealing is not transactional: it is never undone by fbs_inv_txn_abort. */
fbs_inv_status fbs_inv_seal(fbs_inv_store *s);
int            fbs_inv_is_sealed(const fbs_inv_store *s);

/* ---- inventories and grids ------------------------------------------ */
/* grid_wh is 2*grid_count entries: w0,h0,w1,h1,... Grids are independent:
   an item lives entirely inside exactly one of them. */

fbs_inv_status fbs_inv_inventory_add(fbs_inv_store *s, const uint16_t *grid_wh, uint16_t grid_count,
                                     fbs_inv_inventory *out);
unsigned       fbs_inv_inventory_count(const fbs_inv_store *s);
fbs_inv_status fbs_inv_grid_count(const fbs_inv_store *s, fbs_inv_inventory inv, uint16_t *out);
fbs_inv_status fbs_inv_grid_size (const fbs_inv_store *s, fbs_inv_inventory inv, fbs_inv_grid g,
                                  uint16_t *out_w, uint16_t *out_h);
/* Container inventories are not freed when the container is destroyed: the
   inventory is detached (its owner no longer resolves) and reused, lowest id
   first, only by a later container whose grid shape matches exactly and whose
   cells are all free, excluding the new item's destination inventory.
   Inventory/grid/cell ids therefore stay stable and the
   blob canonical. */
/* The inventory a container item owns, or FBS_INV_E_NOT_FOUND if it owns none. */
fbs_inv_status fbs_inv_item_container(const fbs_inv_store *s, fbs_inv_item it, fbs_inv_inventory *out);
/* The item that owns this inventory, or FBS_INV_E_NOT_FOUND for a root inventory. */
fbs_inv_status fbs_inv_inventory_owner(const fbs_inv_store *s, fbs_inv_inventory inv, fbs_inv_item *out);
/* 1 when `it` is live (placed or equipped), 0 when the slot exists but the
   handle is destroyed/stale, negative (E_INVALID) for a NULL store or an index
   that was never issued. */
int            fbs_inv_item_live(const fbs_inv_store *s, fbs_inv_item it);
/* Item slots issued so far (live + destroyed); handle indices (low 16 bits) are < count. */
unsigned       fbs_inv_item_count(const fbs_inv_store *s);
/* The slot holding `it`, or FBS_INV_E_NOT_FOUND when it is in a grid. */
fbs_inv_status fbs_inv_item_slot(const fbs_inv_store *s, fbs_inv_item it, fbs_inv_slot *out);

/* ---- queries (const, no transaction) -------------------------------- */

/* The item occupying a cell, FBS_INV_E_NOT_FOUND for an empty in-bounds cell,
   FBS_INV_E_RANGE for coordinates outside the grid. O(1). */
fbs_inv_status fbs_inv_cell_item(const fbs_inv_store *s, fbs_inv_inventory inv, fbs_inv_grid g,
                                 uint16_t x, uint16_t y, fbs_inv_item *out);
/* Where an item is: inventory, grid, anchor cell, rotation. */
fbs_inv_status fbs_inv_item_place(const fbs_inv_store *s, fbs_inv_item it,
                                  fbs_inv_inventory *out_inv, fbs_inv_grid *out_grid,
                                  uint16_t *out_x, uint16_t *out_y, fbs_inv_rot *out_rot);
fbs_inv_status fbs_inv_item_type_of(const fbs_inv_store *s, fbs_inv_item it, fbs_inv_type *out);
fbs_inv_status fbs_inv_item_stack  (const fbs_inv_store *s, fbs_inv_item it, uint32_t *out);
/* Effective footprint after rotation. */
fbs_inv_status fbs_inv_footprint(const fbs_inv_store *s, fbs_inv_type t, fbs_inv_rot rot,
                                 uint16_t *out_w, uint16_t *out_h);

/* Rectangle test: in bounds AND every covered cell free (or held by `ignore`,
   which may be FBS_INV_NONE). This is the whole placement rule. */
fbs_inv_status fbs_inv_can_place(const fbs_inv_store *s, fbs_inv_inventory inv, fbs_inv_grid g,
                                 fbs_inv_type t, fbs_inv_rot rot, uint16_t x, uint16_t y,
                                 fbs_inv_item ignore);

/* First fit. Scan order is FIXED and part of the contract: grids in index
   order, then row-major (y outer, x inner) from (0,0); anchors range over
   [0, w - fw] x [0, h - fh]. try_rotate=1 tests ROT_0 at every anchor of a
   grid first, then ROT_90 over the same grid, before moving to the next grid.
   No item state is mutated by this call (contrast Inventory.cpp:332-339). */
fbs_inv_status fbs_inv_find_place(const fbs_inv_store *s, fbs_inv_inventory inv, fbs_inv_type t,
                                  int try_rotate, fbs_inv_item ignore,
                                  fbs_inv_grid *out_grid, uint16_t *out_x, uint16_t *out_y,
                                  fbs_inv_rot *out_rot);

/* Enumeration, always in ascending item slot index order (deterministic). */
fbs_inv_status fbs_inv_list_items(const fbs_inv_store *s, fbs_inv_inventory inv,
                                  fbs_inv_item *out, size_t cap, size_t *out_count);
/* Sum of stacks of `t` in `inv`, optionally recursing into container items. */
fbs_inv_status fbs_inv_count_of(const fbs_inv_store *s, fbs_inv_inventory inv, fbs_inv_type t,
                                int recurse, uint64_t *out);
/* Total stacks across the whole store, every inventory and every equipment
   slot. The conservation witness (§6, T-4/T-5) asserts on this. */
uint64_t       fbs_inv_total_units(const fbs_inv_store *s);

/* ---- transactions --------------------------------------------------- */
/* Exactly one transaction at a time. Every mutator below returns E_TXN if none
   is open. A mutator that fails leaves the store unchanged for that single
   operation; abort undoes the whole sequence. If the journal fills, the
   mutator returns E_FULL and the txn is POISONED: commit then returns E_TXN
   and only abort is legal. */

fbs_inv_status fbs_inv_txn_begin (fbs_inv_store *s);
fbs_inv_status fbs_inv_txn_commit(fbs_inv_store *s);
fbs_inv_status fbs_inv_txn_abort (fbs_inv_store *s);   /* exact inverse replay */
int            fbs_inv_txn_active(const fbs_inv_store *s);

/* ---- mutation ------------------------------------------------------- */

/* Creates an item of type t with `stack` units and places it. stack must be in
   1..type.max_stack. A container type also gets its own inventory here. */
fbs_inv_status fbs_inv_spawn_at(fbs_inv_store *s, fbs_inv_inventory inv, fbs_inv_grid g,
                                fbs_inv_type t, uint32_t stack, fbs_inv_rot rot,
                                uint16_t x, uint16_t y, fbs_inv_item *out);
/* spawn + fbs_inv_find_place. E_NO_SPACE if nothing fits. */
fbs_inv_status fbs_inv_spawn(fbs_inv_store *s, fbs_inv_inventory inv, fbs_inv_type t,
                             uint32_t stack, int try_rotate, fbs_inv_item *out);
/* Destroys the item and, if it is a container, everything inside it,
   recursively. Undone exactly by abort. */
fbs_inv_status fbs_inv_destroy(fbs_inv_store *s, fbs_inv_item it);

/* ONE atomic step. Refuses with E_CYCLE if `inv` is the item's own container
   or a descendant of it (ancestor walk, any depth — fixes I-10). On any
   failure NOTHING has changed: the item is still where it was. */
fbs_inv_status fbs_inv_move_to(fbs_inv_store *s, fbs_inv_item it,
                               fbs_inv_inventory inv, fbs_inv_grid g,
                               fbs_inv_rot rot, uint16_t x, uint16_t y);
fbs_inv_status fbs_inv_move_auto(fbs_inv_store *s, fbs_inv_item it,
                                 fbs_inv_inventory inv, int try_rotate);
fbs_inv_status fbs_inv_rotate(fbs_inv_store *s, fbs_inv_item it, fbs_inv_rot rot); /* in place; E_NO_SPACE if it would not fit */

/* ---- stacking ------------------------------------------------------- */
/* Merge rejects count > src.stack with E_RANGE. Otherwise it moves the lesser
   of count and dst headroom from src to dst and reports how many moved. Types must be equal (E_INVALID otherwise). If src
   reaches zero it is DESTROYED and its handle goes stale (fixes I-6).
   count == 0 means "as many as possible". Never exceeds dst's cap (fixes I-5).
   Total units across the store is invariant. */
fbs_inv_status fbs_inv_stack_merge(fbs_inv_store *s, fbs_inv_item dst, fbs_inv_item src,
                                   uint32_t count, uint32_t *out_moved);
/* Splits `count` units off `src` into a NEW item placed at the given anchor.
   1 <= count < src.stack (E_RANGE otherwise: a full split is a move, not a
   split — fixes I-9). Placement is validated before anything is decremented. */
fbs_inv_status fbs_inv_stack_split_to(fbs_inv_store *s, fbs_inv_item src,
                                      fbs_inv_inventory inv, fbs_inv_grid g, fbs_inv_rot rot,
                                      uint16_t x, uint16_t y, uint32_t count, fbs_inv_item *out);
fbs_inv_status fbs_inv_stack_headroom(const fbs_inv_store *s, fbs_inv_item it, uint32_t *out);

/* ---- equipment slots ------------------------------------------------ */
/* accept_tags == 0 accepts any type; otherwise accepts iff
   (type.tags & accept_tags) != 0 — the source's HasAny semantics.
   fbs_inv_slot_add is a mutator: it requires an open transaction. */

fbs_inv_status fbs_inv_slot_add(fbs_inv_store *s, const char *key, size_t key_len,
                                uint64_t accept_tags, fbs_inv_slot *out);
fbs_inv_status fbs_inv_slot_find(const fbs_inv_store *s, const char *key, size_t key_len,
                                 fbs_inv_slot *out);
fbs_inv_status fbs_inv_slot_item(const fbs_inv_store *s, fbs_inv_slot sl, fbs_inv_item *out);
fbs_inv_status fbs_inv_slot_accepts(const fbs_inv_store *s, fbs_inv_slot sl, fbs_inv_type t);
/* E_OCCUPIED if the slot is full — never a silent overwrite (fixes I-14). */
fbs_inv_status fbs_inv_equip(fbs_inv_store *s, fbs_inv_slot sl, fbs_inv_item it);
/* Moves the equipped item into `inv` (auto-placed) and empties the slot.
   Atomic: if it does not fit, the slot is untouched and E_NO_SPACE is returned. */
fbs_inv_status fbs_inv_unequip_to(fbs_inv_store *s, fbs_inv_slot sl, fbs_inv_inventory inv,
                                  int try_rotate);

/* ---- serialization -------------------------------------------------- */
/* Little-endian FBIV v1: byte identity requires identical IDs, generations,
   records and serialized counter, not arbitrary construction order. The undo
   journal, seal and unserialized generation floor are omitted; equal blobs
   can therefore precede different future handle allocations after abort. */

/* Serialization is legal at any time, including inside a transaction (the
 * store is consistent between mutators); it snapshots the current state. */
size_t         fbs_inv_serialized_size(const fbs_inv_store *s); /* 0 for NULL */
fbs_inv_status fbs_inv_serialize  (const fbs_inv_store *s, void *buf, size_t cap, size_t *out_len);
/* cfg NULL: capacities are the larger of the defaults and what the blob needs
 * (max_txn_ops from the defaults; max_grid_dim = the larger of the default and
 * the largest grid dimension in the blob). With cfg, everything must fit
 * (E_FULL) and max_grid_dim must cover every grid (E_RANGE). The result is
 * sealed, with no transaction open. */
fbs_inv_status fbs_inv_deserialize(const void *buf, size_t len, const fbs_inv_config *cfg,
                                   const fbs_inv_allocator *alloc, fbs_inv_store **out);

#ifdef __cplusplus
}
#endif
#endif /* FBS_INV_H */
