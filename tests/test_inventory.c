/*
 * tests/test_inventory.c — witnesses for include/fbs/inventory.h.
 *
 * Self-contained: no test framework. Exit code = number of failures (clamped
 * to 100 so it survives the 8-bit exit status; the true count is printed).
 *
 * Covers docs/decisions/inventory.md section 6: T-1 .. T-12 with the exact
 * witnesses stated there (T-2 is the I-1 counter-example the source gets
 * wrong; T-7 is byte-identical rollback), plus allocator failure, every
 * capacity exhaustion, every E_TRUNCATED path, NULL/bad-enum validation and
 * 0xA5 output-untouched checks on every entry point, the status-name/version
 * functions and a committed golden serialization fixture.
 *
 * It also carries the witnesses for the contract points amended after the
 * module review (docs/lanes/goap-inventory-review.md): container types must
 * have max_stack == 1 (INV-1), a handle minted inside an aborted transaction is
 * never reissued (INV-2), sealing is not rolled back (INV-4), fbs_inv_slot_add
 * is a mutator (INV-5), max_items tops out at 65535 (INV-9), and the 100k fuzz
 * registers container types so nesting, cycles, recursive destroy and shell
 * recycling are fuzzed rather than only covered by fixed cases (INV-10). Every
 * RNG draw is its own statement, so the check count does not depend on
 * argument evaluation order (INV-11).
 *
 * T-12's WASM half ("run on native and WASM and assert identical blob hashes")
 * is out of scope for this C test binary: this repository builds WASM only for
 * the trace module (integrations/wasm/build-trace.sh). The native half runs
 * here in full, and the golden fixture below is the artifact a WASM build would
 * be compared against byte for byte.
 *
 *   ./fbs_test_inventory                     compare against tests/fixtures/inventory/store.bin
 *   ./fbs_test_inventory --write-fixtures    rewrite that file
 *   ./fbs_test_inventory --fixture-dir DIR   look for fixtures under DIR
 */

#include "fbs/inventory.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------- */
/* Harness                                                                   */
/* ------------------------------------------------------------------------- */

static int g_checks = 0;
static int g_fails = 0;

static void check_impl(int cond, const char *expr, const char *file, int line) {
  ++g_checks;
  if (!cond) {
    ++g_fails;
    printf("FAIL %s:%d: %s\n", file, line, expr);
  }
}

#define CHECK(expr) check_impl((expr) ? 1 : 0, #expr, __FILE__, __LINE__)

static const char *g_fixture_dir = "fixtures/inventory";
static int g_write_fixtures = 0;

static int untouched(const void *p, size_t n, unsigned char fill) {
  const unsigned char *b = (const unsigned char *)p;
  size_t i;
  for (i = 0; i < n; ++i)
    if (b[i] != fill) return 0;
  return 1;
}

/* Deterministic 32-bit xorshift; no rand() anywhere (T-5b and T-12 require a
 * fixed, documented seed). */
typedef struct {
  uint32_t state;
} rng;

static void rng_seed(rng *r, uint32_t seed) { r->state = seed ? seed : 1u; }

static uint32_t rng_next(rng *r) {
  uint32_t x = r->state;
  x = (uint32_t)(x ^ (x << 13));
  x = (uint32_t)(x ^ (x >> 17));
  x = (uint32_t)(x ^ (x << 5));
  r->state = x;
  return x;
}

static unsigned rng_below(rng *r, unsigned n) { return n ? (unsigned)(rng_next(r) % n) : 0u; }

/* Counting allocator. */
typedef struct {
  int allocs;
  int frees;
  size_t bytes;
  int budget; /* < 0: unlimited, else the number of allocations still allowed */
} counting_alloc;

static void *ca_alloc(void *user, size_t bytes) {
  counting_alloc *c = (counting_alloc *)user;
  if (c->budget == 0) return NULL;
  if (c->budget > 0) --c->budget;
  ++c->allocs;
  c->bytes += bytes;
  return malloc(bytes);
}

static void ca_free(void *user, void *ptr) {
  counting_alloc *c = (counting_alloc *)user;
  if (!ptr) return;
  ++c->frees;
  free(ptr);
}

/* ------------------------------------------------------------------------- */
/* Helpers                                                                   */
/* ------------------------------------------------------------------------- */

static fbs_inv_store *make_store(const fbs_inv_config *cfg) {
  fbs_inv_store *s = NULL;
  CHECK(fbs_inv_store_create(cfg, NULL, &s) == FBS_INV_OK);
  return s;
}

static fbs_inv_type add_type(fbs_inv_store *s, const char *key, uint16_t w, uint16_t h,
                             uint32_t max_stack, uint64_t tags, const uint16_t *cwh, uint16_t ng) {
  fbs_inv_type_desc d;
  fbs_inv_type t = FBS_INV_NONE;
  d.width = w;
  d.height = h;
  d.max_stack = max_stack;
  d.tags = tags;
  d.container_wh = cwh;
  d.container_grids = ng;
  CHECK(fbs_inv_type_add(s, key, strlen(key), &d, &t) == FBS_INV_OK);
  return t;
}

static fbs_inv_inventory add_inv(fbs_inv_store *s, const uint16_t *wh, uint16_t n) {
  fbs_inv_inventory inv = FBS_INV_NONE;
  CHECK(fbs_inv_inventory_add(s, wh, n, &inv) == FBS_INV_OK);
  return inv;
}

static fbs_inv_inventory add_inv1(fbs_inv_store *s, uint16_t w, uint16_t h) {
  uint16_t wh[2];
  wh[0] = w;
  wh[1] = h;
  return add_inv(s, wh, 1u);
}

static fbs_inv_slot add_slot(fbs_inv_store *s, const char *key, uint64_t accept) {
  fbs_inv_slot sl = FBS_INV_NONE;
  CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
  CHECK(fbs_inv_slot_add(s, key, strlen(key), accept, &sl) == FBS_INV_OK);
  CHECK(fbs_inv_txn_commit(s) == FBS_INV_OK);
  return sl;
}

/* One-operation transaction wrappers, so the witnesses stay readable. */
static fbs_inv_item spawn_at(fbs_inv_store *s, fbs_inv_inventory inv, fbs_inv_grid g,
                             fbs_inv_type t, uint32_t stack, fbs_inv_rot rot, uint16_t x,
                             uint16_t y) {
  fbs_inv_item it = FBS_INV_NONE;
  CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
  CHECK(fbs_inv_spawn_at(s, inv, g, t, stack, rot, x, y, &it) == FBS_INV_OK);
  CHECK(fbs_inv_txn_commit(s) == FBS_INV_OK);
  return it;
}

static fbs_inv_item spawn_auto(fbs_inv_store *s, fbs_inv_inventory inv, fbs_inv_type t,
                               uint32_t stack, int try_rotate) {
  fbs_inv_item it = FBS_INV_NONE;
  CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
  CHECK(fbs_inv_spawn(s, inv, t, stack, try_rotate, &it) == FBS_INV_OK);
  CHECK(fbs_inv_txn_commit(s) == FBS_INV_OK);
  return it;
}

/* Runs one mutator inside its own transaction and reports its status; the
 * transaction is committed on success and aborted on failure. */
#define IN_TXN(store, expr, out_status)                        \
  do {                                                         \
    CHECK(fbs_inv_txn_begin(store) == FBS_INV_OK);              \
    (out_status) = (expr);                                     \
    if ((out_status) == FBS_INV_OK)                            \
      CHECK(fbs_inv_txn_commit(store) == FBS_INV_OK);           \
    else                                                       \
      CHECK(fbs_inv_txn_abort(store) == FBS_INV_OK);            \
  } while (0)

static unsigned char *serialize_alloc(const fbs_inv_store *s, size_t *out_len) {
  size_t need = fbs_inv_serialized_size(s);
  size_t written = 0;
  unsigned char *buf = (unsigned char *)malloc(need ? need : 1u);
  CHECK(buf != NULL);
  if (!buf) {
    *out_len = 0;
    return NULL;
  }
  CHECK(fbs_inv_serialize(s, buf, need, &written) == FBS_INV_OK);
  CHECK(written == need);
  *out_len = need;
  return buf;
}

static int blobs_equal(const unsigned char *a, size_t alen, const unsigned char *b, size_t blen) {
  return alen == blen && memcmp(a, b, alen) == 0;
}

/* Total grid count across every inventory, and the total container_wh length;
 * both are needed to address a record inside a blob. */
static size_t total_grids(const fbs_inv_store *s) {
  size_t n = 0;
  unsigned i;
  for (i = 0; i < fbs_inv_inventory_count(s); ++i) {
    uint16_t gc = 0;
    CHECK(fbs_inv_grid_count(s, i, &gc) == FBS_INV_OK);
    n += gc;
  }
  return n;
}

static size_t total_cwh(const fbs_inv_store *s) {
  size_t n = 0;
  unsigned i;
  for (i = 0; i < fbs_inv_type_count(s); ++i) {
    fbs_inv_type_desc d;
    CHECK(fbs_inv_type_desc_get(s, i, &d) == FBS_INV_OK);
    n += (size_t)d.container_grids * 2u;
  }
  return n;
}

static size_t item_record_offset(const fbs_inv_store *s, unsigned i) {
  return 48u + 32u * (size_t)fbs_inv_type_count(s) + 2u * total_cwh(s) +
         16u * (size_t)fbs_inv_inventory_count(s) + 8u * total_grids(s) + 28u * (size_t)i;
}

/* Every accessor must report a destroyed handle as stale. */
static void expect_stale(const fbs_inv_store *s, fbs_inv_item it) {
  fbs_inv_inventory inv = FBS_INV_NONE;
  fbs_inv_grid g = FBS_INV_NONE;
  fbs_inv_slot sl = FBS_INV_NONE;
  fbs_inv_type t = FBS_INV_NONE;
  fbs_inv_rot rot = FBS_INV_ROT_0;
  uint16_t x = 0, y = 0;
  uint32_t n = 0;
  CHECK(fbs_inv_item_live(s, it) == 0);
  CHECK(fbs_inv_item_place(s, it, &inv, &g, &x, &y, &rot) == FBS_INV_E_STALE);
  CHECK(fbs_inv_item_type_of(s, it, &t) == FBS_INV_E_STALE);
  CHECK(fbs_inv_item_stack(s, it, &n) == FBS_INV_E_STALE);
  CHECK(fbs_inv_item_container(s, it, &inv) == FBS_INV_E_STALE);
  CHECK(fbs_inv_item_slot(s, it, &sl) == FBS_INV_E_STALE);
  CHECK(fbs_inv_stack_headroom(s, it, &n) == FBS_INV_E_STALE);
}

static fbs_inv_item cell_at(const fbs_inv_store *s, fbs_inv_inventory inv, fbs_inv_grid g,
                            uint16_t x, uint16_t y) {
  fbs_inv_item it = FBS_INV_NONE;
  fbs_inv_status st = fbs_inv_cell_item(s, inv, g, x, y, &it);
  if (st != FBS_INV_OK) return FBS_INV_NONE;
  return it;
}

/* Asserts that `it` occupies exactly the w*h cells anchored at (x, y) of grid
 * `g` and nothing else in that grid. */
static void expect_footprint(const fbs_inv_store *s, fbs_inv_inventory inv, fbs_inv_grid g,
                             fbs_inv_item it, unsigned x, unsigned y, unsigned w, unsigned h) {
  uint16_t gw = 0, gh = 0;
  unsigned cx, cy;
  CHECK(fbs_inv_grid_size(s, inv, g, &gw, &gh) == FBS_INV_OK);
  for (cy = 0; cy < gh; ++cy) {
    for (cx = 0; cx < gw; ++cx) {
      fbs_inv_item got = FBS_INV_NONE;
      fbs_inv_status st = fbs_inv_cell_item(s, inv, g, (uint16_t)cx, (uint16_t)cy, &got);
      int inside = (cx >= x && cx < x + w && cy >= y && cy < y + h);
      if (inside) {
        CHECK(st == FBS_INV_OK && got == it);
      } else {
        CHECK(st == FBS_INV_E_NOT_FOUND);
      }
    }
  }
}

/* ------------------------------------------------------------------------- */
/* T-1 — footprint, rotation and the cells an item actually owns              */
/* ------------------------------------------------------------------------- */

static void test_t1_footprint_and_rotation(void) {
  fbs_inv_store *s = make_store(NULL);
  fbs_inv_type t = add_type(s, "board", 2, 3, 1, 0, NULL, 0);
  fbs_inv_inventory inv = add_inv1(s, 4, 4);
  fbs_inv_item it;
  uint16_t w = 0, h = 0;
  fbs_inv_status st;

  CHECK(fbs_inv_footprint(s, t, FBS_INV_ROT_0, &w, &h) == FBS_INV_OK);
  CHECK(w == 2 && h == 3);
  CHECK(fbs_inv_footprint(s, t, FBS_INV_ROT_90, &w, &h) == FBS_INV_OK);
  CHECK(w == 3 && h == 2);

  it = spawn_at(s, inv, 0, t, 1, FBS_INV_ROT_0, 1, 1);
  expect_footprint(s, inv, 0, it, 1, 1, 2, 3);

  /* Rotating in place transposes the footprint about the same anchor. */
  IN_TXN(s, fbs_inv_rotate(s, it, FBS_INV_ROT_90), st);
  CHECK(st == FBS_INV_OK);
  expect_footprint(s, inv, 0, it, 1, 1, 3, 2);

  /* T-1c — the I-15a witness: one hit test, used by every path. A cell inside
     the unrotated rectangle but outside the rotated one is empty, and vice
     versa. */
  CHECK(cell_at(s, inv, 0, 1, 3) == FBS_INV_NONE); /* was inside at ROT_0   */
  CHECK(cell_at(s, inv, 0, 3, 1) == it);           /* is inside at ROT_90   */

  {
    fbs_inv_inventory pinv = FBS_INV_NONE;
    fbs_inv_grid pg = FBS_INV_NONE;
    uint16_t px = 0, py = 0;
    fbs_inv_rot prot = FBS_INV_ROT_0;
    CHECK(fbs_inv_item_place(s, it, &pinv, &pg, &px, &py, &prot) == FBS_INV_OK);
    CHECK(pinv == inv && pg == 0 && px == 1 && py == 1 && prot == FBS_INV_ROT_90);
  }

  /* T-1b — the reserved 180/270 values are rejected, everywhere. */
  CHECK(fbs_inv_footprint(s, t, (fbs_inv_rot)2, &w, &h) == FBS_INV_E_RANGE);
  CHECK(fbs_inv_footprint(s, t, (fbs_inv_rot)3, &w, &h) == FBS_INV_E_RANGE);
  CHECK(fbs_inv_can_place(s, inv, 0, t, (fbs_inv_rot)2, 0, 0, FBS_INV_NONE) == FBS_INV_E_RANGE);
  CHECK(fbs_inv_can_place(s, inv, 0, t, (fbs_inv_rot)3, 0, 0, FBS_INV_NONE) == FBS_INV_E_RANGE);
  {
    fbs_inv_item made = FBS_INV_NONE;
    CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
    CHECK(fbs_inv_spawn_at(s, inv, 0, t, 1, (fbs_inv_rot)2, 0, 0, &made) == FBS_INV_E_RANGE);
    CHECK(made == FBS_INV_NONE);
    CHECK(fbs_inv_rotate(s, it, (fbs_inv_rot)3) == FBS_INV_E_RANGE);
    CHECK(fbs_inv_move_to(s, it, inv, 0, (fbs_inv_rot)2, 0, 0) == FBS_INV_E_RANGE);
    CHECK(fbs_inv_txn_abort(s) == FBS_INV_OK);
    /* the rotation the item already had is untouched by the refusals */
    expect_footprint(s, inv, 0, it, 1, 1, 3, 2);
  }

  fbs_inv_store_destroy(s);
}

/* ------------------------------------------------------------------------- */
/* T-2 — the I-1 witness: the counter-example a faithful transliteration fails */
/* ------------------------------------------------------------------------- */

static void test_t2_counter_example(void) {
  /* docs/sources/inventory-inventory.md §10, I-1: a 4x4 grid with (0,1) and
     (2,0) occupied, asking for a 2x2. The source's tile-counting scan reports
     the anchor (1,0) — a rectangle that contains the occupied cell (2,0) it
     never examined — and then stamps over the resident. */
  fbs_inv_store *s = make_store(NULL);
  fbs_inv_type small = add_type(s, "pebble", 1, 1, 1, 0, NULL, 0);
  fbs_inv_type big = add_type(s, "crate", 2, 2, 1, 0, NULL, 0);
  fbs_inv_inventory inv = add_inv1(s, 4, 4);
  fbs_inv_item a = spawn_at(s, inv, 0, small, 1, FBS_INV_ROT_0, 0, 1);
  fbs_inv_item b = spawn_at(s, inv, 0, small, 1, FBS_INV_ROT_0, 2, 0);
  fbs_inv_grid g = FBS_INV_NONE;
  uint16_t x = 0xFFFFu, y = 0xFFFFu;
  fbs_inv_rot rot = FBS_INV_ROT_90;
  fbs_inv_item made = FBS_INV_NONE;
  fbs_inv_status st;

  /* The rectangle test refuses (1,0) — it overlaps (2,0). */
  CHECK(fbs_inv_can_place(s, inv, 0, big, FBS_INV_ROT_0, 1, 0, FBS_INV_NONE) ==
        FBS_INV_E_NO_SPACE);
  /* ... and refuses every other anchor that overlaps a resident. */
  CHECK(fbs_inv_can_place(s, inv, 0, big, FBS_INV_ROT_0, 0, 0, FBS_INV_NONE) ==
        FBS_INV_E_NO_SPACE);
  CHECK(fbs_inv_can_place(s, inv, 0, big, FBS_INV_ROT_0, 2, 0, FBS_INV_NONE) ==
        FBS_INV_E_NO_SPACE);
  CHECK(fbs_inv_can_place(s, inv, 0, big, FBS_INV_ROT_0, 0, 1, FBS_INV_NONE) ==
        FBS_INV_E_NO_SPACE);
  /* The five genuine fits are all accepted. */
  CHECK(fbs_inv_can_place(s, inv, 0, big, FBS_INV_ROT_0, 1, 1, FBS_INV_NONE) == FBS_INV_OK);
  CHECK(fbs_inv_can_place(s, inv, 0, big, FBS_INV_ROT_0, 2, 1, FBS_INV_NONE) == FBS_INV_OK);
  CHECK(fbs_inv_can_place(s, inv, 0, big, FBS_INV_ROT_0, 0, 2, FBS_INV_NONE) == FBS_INV_OK);
  CHECK(fbs_inv_can_place(s, inv, 0, big, FBS_INV_ROT_0, 1, 2, FBS_INV_NONE) == FBS_INV_OK);
  CHECK(fbs_inv_can_place(s, inv, 0, big, FBS_INV_ROT_0, 2, 2, FBS_INV_NONE) == FBS_INV_OK);

  /* First fit under the contract's scan order (grids in index order, then
     row-major y outer / x inner) is (1,1). It is never (1,0). */
  CHECK(fbs_inv_find_place(s, inv, big, 0, FBS_INV_NONE, &g, &x, &y, &rot) == FBS_INV_OK);
  CHECK(g == 0 && x == 1 && y == 1 && rot == FBS_INV_ROT_0);
  CHECK(!(x == 1 && y == 0));

  /* Placing at the source's answer fails and disturbs nothing. */
  IN_TXN(s, fbs_inv_spawn_at(s, inv, 0, big, 1, FBS_INV_ROT_0, 1, 0, &made), st);
  CHECK(st == FBS_INV_E_NO_SPACE);
  CHECK(made == FBS_INV_NONE);
  CHECK(cell_at(s, inv, 0, 2, 0) == b);
  CHECK(cell_at(s, inv, 0, 0, 1) == a);
  CHECK(fbs_inv_item_live(s, a) == 1);
  CHECK(fbs_inv_item_live(s, b) == 1);
  CHECK(fbs_inv_item_count(s) == 2u);

  /* With both residents gone the same call succeeds at (0,0). */
  CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
  CHECK(fbs_inv_destroy(s, a) == FBS_INV_OK);
  CHECK(fbs_inv_destroy(s, b) == FBS_INV_OK);
  CHECK(fbs_inv_spawn_at(s, inv, 0, big, 1, FBS_INV_ROT_0, 1, 0, &made) == FBS_INV_OK);
  CHECK(fbs_inv_txn_commit(s) == FBS_INV_OK);
  expect_footprint(s, inv, 0, made, 1, 0, 2, 2);

  fbs_inv_store_destroy(s);
}

/* ------------------------------------------------------------------------- */
/* T-3 — bounds, scan order, rotation fallback, multi-grid                    */
/* ------------------------------------------------------------------------- */

static void test_t3_bounds(void) {
  fbs_inv_store *s = make_store(NULL);
  fbs_inv_type t = add_type(s, "board", 2, 3, 1, 0, NULL, 0);
  fbs_inv_type fill = add_type(s, "sheet", 4, 4, 1, 0, NULL, 0);
  fbs_inv_inventory inv = add_inv1(s, 4, 4);
  fbs_inv_inventory inv2 = add_inv1(s, 4, 4);
  fbs_inv_item it;
  uint16_t bad[2];
  fbs_inv_inventory made = FBS_INV_NONE;

  /* Anchor + footprint past the edge, in x, in y, and in both. */
  CHECK(fbs_inv_can_place(s, inv, 0, t, FBS_INV_ROT_0, 3, 0, FBS_INV_NONE) == FBS_INV_E_NO_SPACE);
  CHECK(fbs_inv_can_place(s, inv, 0, t, FBS_INV_ROT_0, 0, 2, FBS_INV_NONE) == FBS_INV_E_NO_SPACE);
  CHECK(fbs_inv_can_place(s, inv, 0, t, FBS_INV_ROT_0, 3, 2, FBS_INV_NONE) == FBS_INV_E_NO_SPACE);
  CHECK(fbs_inv_can_place(s, inv, 0, t, FBS_INV_ROT_0, 2, 1, FBS_INV_NONE) == FBS_INV_OK);

  /* Beyond max_grid_dim is a range error, not a placement failure. */
  CHECK(fbs_inv_can_place(s, inv, 0, t, FBS_INV_ROT_0, 64, 0, FBS_INV_NONE) == FBS_INV_E_RANGE);
  CHECK(fbs_inv_can_place(s, inv, 0, t, FBS_INV_ROT_0, 0, 64, FBS_INV_NONE) == FBS_INV_E_RANGE);
  CHECK(fbs_inv_can_place(s, inv, 0, t, FBS_INV_ROT_0, 1000, 1000, FBS_INV_NONE) ==
        FBS_INV_E_RANGE);

  /* Degenerate grids are refused at registration (fixes I-3 / I-4). */
  bad[0] = 0;
  bad[1] = 4;
  CHECK(fbs_inv_inventory_add(s, bad, 1, &made) == FBS_INV_E_RANGE);
  bad[0] = 4;
  bad[1] = 0;
  CHECK(fbs_inv_inventory_add(s, bad, 1, &made) == FBS_INV_E_RANGE);
  bad[0] = 65;
  bad[1] = 1;
  CHECK(fbs_inv_inventory_add(s, bad, 1, &made) == FBS_INV_E_RANGE);
  CHECK(fbs_inv_inventory_add(s, bad, 0, &made) == FBS_INV_E_RANGE);
  CHECK(made == FBS_INV_NONE);

  /* An item that exactly fills the grid fits at (0,0) and nowhere else. */
  CHECK(fbs_inv_can_place(s, inv2, 0, fill, FBS_INV_ROT_0, 0, 0, FBS_INV_NONE) == FBS_INV_OK);
  CHECK(fbs_inv_can_place(s, inv2, 0, fill, FBS_INV_ROT_0, 1, 0, FBS_INV_NONE) ==
        FBS_INV_E_NO_SPACE);
  CHECK(fbs_inv_can_place(s, inv2, 0, fill, FBS_INV_ROT_0, 0, 1, FBS_INV_NONE) ==
        FBS_INV_E_NO_SPACE);
  it = spawn_at(s, inv2, 0, fill, 1, FBS_INV_ROT_0, 0, 0);
  expect_footprint(s, inv2, 0, it, 0, 0, 4, 4);

  fbs_inv_store_destroy(s);
}

static void test_t3b_scan_order(void) {
  fbs_inv_store *s = make_store(NULL);
  fbs_inv_type t = add_type(s, "unit", 1, 1, 1, 0, NULL, 0);
  fbs_inv_inventory inv = add_inv1(s, 3, 3);
  fbs_inv_grid g = FBS_INV_NONE;
  uint16_t x = 0xFFFFu, y = 0xFFFFu;
  fbs_inv_rot rot = FBS_INV_ROT_90;

  CHECK(fbs_inv_find_place(s, inv, t, 0, FBS_INV_NONE, &g, &x, &y, &rot) == FBS_INV_OK);
  CHECK(g == 0 && x == 0 && y == 0 && rot == FBS_INV_ROT_0);
  (void)spawn_at(s, inv, 0, t, 1, FBS_INV_ROT_0, 0, 0);
  CHECK(fbs_inv_find_place(s, inv, t, 0, FBS_INV_NONE, &g, &x, &y, &rot) == FBS_INV_OK);
  CHECK(x == 1 && y == 0);
  (void)spawn_at(s, inv, 0, t, 1, FBS_INV_ROT_0, 1, 0);
  (void)spawn_at(s, inv, 0, t, 1, FBS_INV_ROT_0, 2, 0);
  CHECK(fbs_inv_find_place(s, inv, t, 0, FBS_INV_NONE, &g, &x, &y, &rot) == FBS_INV_OK);
  CHECK(x == 0 && y == 1);
  fbs_inv_store_destroy(s);
}

static void test_t3c_rotation_fallback(void) {
  fbs_inv_store *s = make_store(NULL);
  fbs_inv_type t = add_type(s, "rod", 1, 3, 1, 0, NULL, 0);
  fbs_inv_inventory wide = add_inv1(s, 3, 1);
  fbs_inv_inventory home = add_inv1(s, 3, 3);
  fbs_inv_item it = spawn_at(s, home, 0, t, 1, FBS_INV_ROT_0, 0, 0);
  fbs_inv_grid g = FBS_INV_NONE;
  uint16_t x = 0xFFFFu, y = 0xFFFFu;
  fbs_inv_rot rot = FBS_INV_ROT_0;
  fbs_inv_status st;

  CHECK(fbs_inv_find_place(s, wide, t, 1, FBS_INV_NONE, &g, &x, &y, &rot) == FBS_INV_OK);
  CHECK(g == 0 && x == 0 && y == 0 && rot == FBS_INV_ROT_90);
  x = 0xFFFFu;
  y = 0xFFFFu;
  rot = FBS_INV_ROT_0;
  CHECK(fbs_inv_find_place(s, wide, t, 0, FBS_INV_NONE, &g, &x, &y, &rot) == FBS_INV_E_NO_SPACE);
  CHECK(x == 0xFFFFu && y == 0xFFFFu && rot == FBS_INV_ROT_0); /* outputs untouched */

  /* The I-11 hazard: a refused auto-move must not have rotated the item. */
  IN_TXN(s, fbs_inv_move_auto(s, it, wide, 0), st);
  CHECK(st == FBS_INV_E_NO_SPACE);
  {
    fbs_inv_inventory pi = FBS_INV_NONE;
    fbs_inv_grid pg = FBS_INV_NONE;
    uint16_t px = 0, py = 0;
    fbs_inv_rot pr = FBS_INV_ROT_90;
    CHECK(fbs_inv_item_place(s, it, &pi, &pg, &px, &py, &pr) == FBS_INV_OK);
    CHECK(pi == home && pg == 0 && px == 0 && py == 0 && pr == FBS_INV_ROT_0);
  }
  IN_TXN(s, fbs_inv_move_auto(s, it, wide, 1), st);
  CHECK(st == FBS_INV_OK);
  {
    fbs_inv_inventory pi = FBS_INV_NONE;
    fbs_inv_grid pg = FBS_INV_NONE;
    uint16_t px = 0xFFFFu, py = 0xFFFFu;
    fbs_inv_rot pr = FBS_INV_ROT_0;
    CHECK(fbs_inv_item_place(s, it, &pi, &pg, &px, &py, &pr) == FBS_INV_OK);
    CHECK(pi == wide && pg == 0 && px == 0 && py == 0 && pr == FBS_INV_ROT_90);
  }
  fbs_inv_store_destroy(s);
}

static void test_t3d_multi_grid(void) {
  fbs_inv_store *s = make_store(NULL);
  fbs_inv_type t = add_type(s, "slab", 3, 3, 1, 0, NULL, 0);
  uint16_t wh[4];
  fbs_inv_inventory inv;
  fbs_inv_grid g = FBS_INV_NONE;
  uint16_t x = 0xFFFFu, y = 0xFFFFu, gw = 0, gh = 0;
  fbs_inv_rot rot = FBS_INV_ROT_90;
  fbs_inv_item it;

  wh[0] = 2;
  wh[1] = 2;
  wh[2] = 4;
  wh[3] = 4;
  inv = add_inv(s, wh, 2);
  {
    uint16_t gc = 0;
    CHECK(fbs_inv_grid_count(s, inv, &gc) == FBS_INV_OK);
    CHECK(gc == 2);
  }
  CHECK(fbs_inv_grid_size(s, inv, 0, &gw, &gh) == FBS_INV_OK);
  CHECK(gw == 2 && gh == 2);
  CHECK(fbs_inv_grid_size(s, inv, 1, &gw, &gh) == FBS_INV_OK);
  CHECK(gw == 4 && gh == 4);

  CHECK(fbs_inv_find_place(s, inv, t, 1, FBS_INV_NONE, &g, &x, &y, &rot) == FBS_INV_OK);
  CHECK(g == 1 && x == 0 && y == 0 && rot == FBS_INV_ROT_0);
  it = spawn_auto(s, inv, t, 1, 1);
  expect_footprint(s, inv, 1, it, 0, 0, 3, 3);
  expect_footprint(s, inv, 0, FBS_INV_NONE, 0, 0, 0, 0); /* grid 0 stays empty */
  /* Grids are independent: nothing straddles. A second 3x3 does not fit. */
  {
    fbs_inv_item made = FBS_INV_NONE;
    fbs_inv_status st;
    IN_TXN(s, fbs_inv_spawn(s, inv, t, 1, 1, &made), st);
    CHECK(st == FBS_INV_E_NO_SPACE);
    CHECK(made == FBS_INV_NONE);
  }
  fbs_inv_store_destroy(s);
}

/* ------------------------------------------------------------------------- */
/* T-4 — stack merge: the cap is respected and units are conserved            */
/* ------------------------------------------------------------------------- */

static void test_t4_merge(void) {
  fbs_inv_store *s = make_store(NULL);
  fbs_inv_type t = add_type(s, "coin", 1, 1, 10, 0, NULL, 0);
  fbs_inv_inventory inv = add_inv1(s, 4, 4);
  fbs_inv_item dst = spawn_at(s, inv, 0, t, 7, FBS_INV_ROT_0, 0, 0);
  fbs_inv_item src = spawn_at(s, inv, 0, t, 5, FBS_INV_ROT_0, 1, 0);
  uint32_t moved = 0xFFFFFFFFu, n = 0;
  uint64_t before = fbs_inv_total_units(s);
  fbs_inv_status st;

  CHECK(before == 12u);
  CHECK(fbs_inv_stack_headroom(s, dst, &n) == FBS_INV_OK);
  CHECK(n == 3u);

  IN_TXN(s, fbs_inv_stack_merge(s, dst, src, 0, &moved), st);
  CHECK(st == FBS_INV_OK);
  CHECK(moved == 3u); /* fixes I-5: never past the cap */
  CHECK(fbs_inv_item_stack(s, dst, &n) == FBS_INV_OK && n == 10u);
  CHECK(fbs_inv_item_stack(s, src, &n) == FBS_INV_OK && n == 2u);
  CHECK(fbs_inv_total_units(s) == before);

  moved = 0xFFFFFFFFu;
  IN_TXN(s, fbs_inv_stack_merge(s, dst, src, 0, &moved), st);
  CHECK(st == FBS_INV_OK);
  CHECK(moved == 0u);
  CHECK(fbs_inv_total_units(s) == before);

  /* T-4d — count larger than the giver's stack is a range error that changes
     nothing (and leaves *out_moved untouched). */
  moved = 0xA5A5A5A5u;
  IN_TXN(s, fbs_inv_stack_merge(s, dst, src, 3, &moved), st);
  CHECK(st == FBS_INV_E_RANGE);
  CHECK(moved == 0xA5A5A5A5u);
  CHECK(fbs_inv_item_stack(s, src, &n) == FBS_INV_OK && n == 2u);
  CHECK(fbs_inv_total_units(s) == before);

  fbs_inv_store_destroy(s);
}

static void test_t4b_zero_is_destroyed(void) {
  /* The I-6 witness. */
  fbs_inv_store *s = make_store(NULL);
  fbs_inv_type t = add_type(s, "coin", 1, 1, 10, 0, NULL, 0);
  fbs_inv_inventory inv = add_inv1(s, 4, 4);
  fbs_inv_item dst = spawn_at(s, inv, 0, t, 7, FBS_INV_ROT_0, 0, 0);
  fbs_inv_item src = spawn_at(s, inv, 0, t, 3, FBS_INV_ROT_0, 1, 0);
  uint64_t before = fbs_inv_total_units(s);
  uint32_t moved = 0, n = 0;
  fbs_inv_status st;

  CHECK(before == 10u);
  IN_TXN(s, fbs_inv_stack_merge(s, dst, src, 0, &moved), st);
  CHECK(st == FBS_INV_OK);
  CHECK(moved == 3u);
  CHECK(fbs_inv_item_stack(s, dst, &n) == FBS_INV_OK && n == 10u);
  expect_stale(s, src);
  CHECK(cell_at(s, inv, 0, 1, 0) == FBS_INV_NONE); /* its cell is free again */
  CHECK(fbs_inv_total_units(s) == before);
  CHECK(fbs_inv_item_count(s) == 2u); /* the slot is a tombstone, not gone */

  fbs_inv_store_destroy(s);
}

static void test_t4c_identity_is_the_type(void) {
  /* The I-8 witness: two different types with identical footprint and identical
     tags must refuse to merge. Stacking is type identity, nothing else. */
  fbs_inv_store *s = make_store(NULL);
  fbs_inv_type a = add_type(s, "copper", 1, 1, 10, 0x5u, NULL, 0);
  fbs_inv_type b = add_type(s, "bronze", 1, 1, 10, 0x5u, NULL, 0);
  fbs_inv_inventory inv = add_inv1(s, 4, 4);
  fbs_inv_item ia = spawn_at(s, inv, 0, a, 4, FBS_INV_ROT_0, 0, 0);
  fbs_inv_item ib = spawn_at(s, inv, 0, b, 4, FBS_INV_ROT_0, 1, 0);
  uint32_t moved = 0xA5A5A5A5u, n = 0;
  fbs_inv_status st;

  CHECK(a != b);
  IN_TXN(s, fbs_inv_stack_merge(s, ia, ib, 0, &moved), st);
  CHECK(st == FBS_INV_E_INVALID);
  CHECK(moved == 0xA5A5A5A5u);
  CHECK(fbs_inv_item_stack(s, ia, &n) == FBS_INV_OK && n == 4u);
  CHECK(fbs_inv_item_stack(s, ib, &n) == FBS_INV_OK && n == 4u);
  /* An item cannot merge into itself either. */
  IN_TXN(s, fbs_inv_stack_merge(s, ia, ia, 1, &moved), st);
  CHECK(st == FBS_INV_E_INVALID);
  CHECK(fbs_inv_total_units(s) == 8u);

  fbs_inv_store_destroy(s);
}

/* ------------------------------------------------------------------------- */
/* T-5 — split conserves, and validates before it decrements                  */
/* ------------------------------------------------------------------------- */

static void test_t5_split(void) {
  fbs_inv_store *s = make_store(NULL);
  fbs_inv_type t = add_type(s, "coin", 1, 1, 20, 0, NULL, 0);
  fbs_inv_type block = add_type(s, "block", 1, 1, 1, 0, NULL, 0);
  fbs_inv_inventory inv = add_inv1(s, 4, 4);
  fbs_inv_item src = spawn_at(s, inv, 0, t, 9, FBS_INV_ROT_0, 0, 0);
  fbs_inv_item wall = spawn_at(s, inv, 0, block, 1, FBS_INV_ROT_0, 3, 3);
  fbs_inv_item made = FBS_INV_NONE;
  uint64_t before = fbs_inv_total_units(s);
  uint32_t n = 0;
  fbs_inv_status st;

  /* A full split is a move, not a split (fixes I-9). */
  IN_TXN(s, fbs_inv_stack_split_to(s, src, inv, 0, FBS_INV_ROT_0, 1, 0, 9, &made), st);
  CHECK(st == FBS_INV_E_RANGE);
  CHECK(made == FBS_INV_NONE);
  IN_TXN(s, fbs_inv_stack_split_to(s, src, inv, 0, FBS_INV_ROT_0, 1, 0, 0, &made), st);
  CHECK(st == FBS_INV_E_RANGE);
  IN_TXN(s, fbs_inv_stack_split_to(s, src, inv, 0, FBS_INV_ROT_0, 1, 0, 10, &made), st);
  CHECK(st == FBS_INV_E_RANGE);
  CHECK(made == FBS_INV_NONE);
  CHECK(fbs_inv_item_stack(s, src, &n) == FBS_INV_OK && n == 9u);

  /* Placement is validated first: an occupied destination leaves src at 9. */
  IN_TXN(s, fbs_inv_stack_split_to(s, src, inv, 0, FBS_INV_ROT_0, 3, 3, 4, &made), st);
  CHECK(st == FBS_INV_E_NO_SPACE);
  CHECK(made == FBS_INV_NONE);
  CHECK(fbs_inv_item_stack(s, src, &n) == FBS_INV_OK && n == 9u);
  CHECK(cell_at(s, inv, 0, 3, 3) == wall);
  CHECK(fbs_inv_total_units(s) == before);

  IN_TXN(s, fbs_inv_stack_split_to(s, src, inv, 0, FBS_INV_ROT_0, 1, 0, 4, &made), st);
  CHECK(st == FBS_INV_OK);
  CHECK(made != FBS_INV_NONE && made != src);
  CHECK(fbs_inv_item_stack(s, made, &n) == FBS_INV_OK && n == 4u);
  CHECK(fbs_inv_item_stack(s, src, &n) == FBS_INV_OK && n == 5u);
  CHECK(fbs_inv_total_units(s) == before);
  CHECK(cell_at(s, inv, 0, 1, 0) == made);

  fbs_inv_store_destroy(s);
}

/* T-5b — 2,000 random merge/split/move operations from a fixed seed; total
 * units invariant after every one, and no stack ever exceeds its cap. */
static void test_t5b_property(void) {
  fbs_inv_config cfg = fbs_inv_config_default();
  fbs_inv_store *s;
  fbs_inv_type types[8];
  fbs_inv_inventory invs[3];
  fbs_inv_item live[64];
  unsigned live_n = 0, op;
  uint64_t units;
  rng r;
  static const uint32_t caps[8] = {2u, 3u, 5u, 8u, 10u, 16u, 25u, 64u};
  static const uint16_t dims[8][2] = {{1, 1}, {1, 2}, {2, 1}, {1, 1}, {2, 2}, {1, 3}, {1, 1}, {3, 1}};
  unsigned i;

  cfg.max_items = 256u;
  cfg.max_txn_ops = 4096u;
  s = make_store(&cfg);
  for (i = 0; i < 8u; ++i) {
    char key[8];
    key[0] = 's';
    key[1] = (char)('0' + (int)i);
    key[2] = '\0';
    types[i] = add_type(s, key, dims[i][0], dims[i][1], caps[i], 0, NULL, 0);
  }
  for (i = 0; i < 3u; ++i) invs[i] = add_inv1(s, 6, 6);
  CHECK(fbs_inv_seal(s) == FBS_INV_OK);

  rng_seed(&r, 0x5EED0BADu);
  units = 0u; /* the running expectation; only spawn is allowed to change it */
  CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
  for (op = 0; op < 2000u; ++op) {
    unsigned kind = rng_below(&r, 10u);
    fbs_inv_status st = FBS_INV_OK;

    if (live_n < 8u || kind < 3u) { /* keep a population alive */
      unsigned ti = rng_below(&r, 8u);
      fbs_inv_item made = FBS_INV_NONE;
      uint32_t stack = 1u + rng_below(&r, caps[ti]);
      unsigned which = rng_below(&r, 3u);
      int rotate = (int)rng_below(&r, 2u);
      st = fbs_inv_spawn(s, invs[which], types[ti], stack, rotate, &made);
      if (st == FBS_INV_OK) {
        units += stack;
        if (live_n < 64u) live[live_n++] = made;
      }
    } else if (kind < 6u && live_n >= 2u) { /* merge — conserves */
      unsigned a = rng_below(&r, live_n);
      unsigned b = rng_below(&r, live_n);
      uint32_t moved = 0;
      st = fbs_inv_stack_merge(s, live[a], live[b], rng_below(&r, 4u), &moved);
    } else if (kind < 8u && live_n >= 1u) { /* split — conserves */
      unsigned a = rng_below(&r, live_n);
      fbs_inv_item made = FBS_INV_NONE;
      fbs_inv_inventory dinv = invs[rng_below(&r, 3u)];
      fbs_inv_grid g = FBS_INV_NONE;
      uint16_t x = 0, y = 0;
      fbs_inv_rot rot = FBS_INV_ROT_0;
      uint32_t stack = 0;
      fbs_inv_type ty = FBS_INV_NONE;
      if (fbs_inv_item_stack(s, live[a], &stack) == FBS_INV_OK && stack > 1u &&
          fbs_inv_item_type_of(s, live[a], &ty) == FBS_INV_OK &&
          fbs_inv_find_place(s, dinv, ty, 0, FBS_INV_NONE, &g, &x, &y, &rot) == FBS_INV_OK) {
        st = fbs_inv_stack_split_to(s, live[a], dinv, g, rot, x, y, 1u + rng_below(&r, stack - 1u),
                                    &made);
        if (st == FBS_INV_OK && live_n < 64u) live[live_n++] = made;
      }
    } else if (live_n >= 1u) { /* move — conserves */
      unsigned a = rng_below(&r, live_n);
      unsigned which = rng_below(&r, 3u);
      int rotate = (int)rng_below(&r, 2u);
      st = fbs_inv_move_auto(s, live[a], invs[which], rotate);
    }
    CHECK(st == FBS_INV_OK || st == FBS_INV_E_NO_SPACE || st == FBS_INV_E_FULL ||
          st == FBS_INV_E_STALE || st == FBS_INV_E_INVALID || st == FBS_INV_E_RANGE);

    /* The two invariants, after every single operation. */
    if (fbs_inv_total_units(s) != units) CHECK(0);
    for (i = 0; i < live_n; ++i) {
      uint32_t stack = 0;
      fbs_inv_type ty = FBS_INV_NONE;
      if (fbs_inv_item_stack(s, live[i], &stack) != FBS_INV_OK) continue; /* merged away */
      if (fbs_inv_item_type_of(s, live[i], &ty) != FBS_INV_OK) continue;
      if (stack < 1u || ty >= 8u || stack > caps[ty]) CHECK(0);
    }

    if ((op % 97u) == 96u) { /* keep the journal well inside max_txn_ops */
      CHECK(fbs_inv_txn_commit(s) == FBS_INV_OK);
      CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
    }
  }
  CHECK(fbs_inv_txn_commit(s) == FBS_INV_OK);
  CHECK(fbs_inv_total_units(s) == units);
  CHECK(units > 0u);
  fbs_inv_store_destroy(s);
}

/* ------------------------------------------------------------------------- */
/* T-6 — nesting: cycles at any depth, and recursive destroy                  */
/* ------------------------------------------------------------------------- */

typedef struct {
  fbs_inv_store *s;
  fbs_inv_type pack, pouch, gem;
  fbs_inv_inventory root;
  fbs_inv_item a, b, c, coin;
  fbs_inv_inventory inv_a, inv_b, inv_c;
} nest_fixture;

/* root 6x6 holds A (a 2x2 pack, inventory 3x3); A holds B (a 1x1 pouch,
 * inventory 2x2); B holds C (another pouch, inventory 2x2); C holds a coin. */
static nest_fixture build_nest(void) {
  static const uint16_t pack_wh[2] = {3, 3};
  static const uint16_t pouch_wh[2] = {2, 2};
  nest_fixture f;
  f.s = make_store(NULL);
  f.pack = add_type(f.s, "pack", 2, 2, 1, 0x1u, pack_wh, 1);
  f.pouch = add_type(f.s, "pouch", 1, 1, 1, 0x2u, pouch_wh, 1);
  f.gem = add_type(f.s, "gem", 1, 1, 9, 0x4u, NULL, 0);
  f.root = add_inv1(f.s, 6, 6);
  f.a = spawn_at(f.s, f.root, 0, f.pack, 1, FBS_INV_ROT_0, 0, 0);
  CHECK(fbs_inv_item_container(f.s, f.a, &f.inv_a) == FBS_INV_OK);
  f.b = spawn_at(f.s, f.inv_a, 0, f.pouch, 1, FBS_INV_ROT_0, 0, 0);
  CHECK(fbs_inv_item_container(f.s, f.b, &f.inv_b) == FBS_INV_OK);
  f.c = spawn_at(f.s, f.inv_b, 0, f.pouch, 1, FBS_INV_ROT_0, 0, 0);
  CHECK(fbs_inv_item_container(f.s, f.c, &f.inv_c) == FBS_INV_OK);
  f.coin = spawn_at(f.s, f.inv_c, 0, f.gem, 5, FBS_INV_ROT_0, 0, 0);
  return f;
}

static void test_t6_cycles(void) {
  nest_fixture f = build_nest();
  fbs_inv_store *s = f.s;
  fbs_inv_status st;
  fbs_inv_item owner = FBS_INV_NONE;
  uint16_t gw = 0, gh = 0;

  /* The links the model promises. */
  CHECK(f.inv_a != f.root && f.inv_b != f.inv_a && f.inv_c != f.inv_b);
  CHECK(fbs_inv_inventory_owner(s, f.inv_a, &owner) == FBS_INV_OK && owner == f.a);
  CHECK(fbs_inv_inventory_owner(s, f.inv_c, &owner) == FBS_INV_OK && owner == f.c);
  CHECK(fbs_inv_inventory_owner(s, f.root, &owner) == FBS_INV_E_NOT_FOUND);
  CHECK(fbs_inv_item_container(s, f.coin, &owner) == FBS_INV_E_NOT_FOUND);
  CHECK(fbs_inv_grid_size(s, f.inv_a, 0, &gw, &gh) == FBS_INV_OK && gw == 3 && gh == 3);
  CHECK(fbs_inv_grid_size(s, f.inv_b, 0, &gw, &gh) == FBS_INV_OK && gw == 2 && gh == 2);
  CHECK(fbs_inv_total_units(s) == 8u); /* 3 containers at 1 + a 5-gem */

  /* Direct self-nesting. */
  IN_TXN(s, fbs_inv_move_to(s, f.a, f.inv_a, 0, FBS_INV_ROT_0, 1, 1), st);
  CHECK(st == FBS_INV_E_CYCLE);
  IN_TXN(s, fbs_inv_move_auto(s, f.a, f.inv_a, 0), st);
  CHECK(st == FBS_INV_E_CYCLE);

  /* Depth 2: A into the inventory of the pouch it already contains. */
  IN_TXN(s, fbs_inv_move_to(s, f.a, f.inv_b, 0, FBS_INV_ROT_0, 0, 1), st);
  CHECK(st == FBS_INV_E_CYCLE);

  /* Depth 3 — the case the source's GetOuter() == InItem guard cannot see
     (I-10). A into C's inventory, where C is two levels inside A. */
  IN_TXN(s, fbs_inv_move_to(s, f.a, f.inv_c, 0, FBS_INV_ROT_0, 0, 1), st);
  CHECK(st == FBS_INV_E_CYCLE);
  IN_TXN(s, fbs_inv_move_auto(s, f.a, f.inv_c, 1), st);
  CHECK(st == FBS_INV_E_CYCLE);
  /* ... and B into C's inventory, one level down from B. */
  IN_TXN(s, fbs_inv_move_to(s, f.b, f.inv_c, 0, FBS_INV_ROT_0, 0, 1), st);
  CHECK(st == FBS_INV_E_CYCLE);

  /* Nothing moved. */
  {
    fbs_inv_inventory pi = FBS_INV_NONE;
    fbs_inv_grid pg = FBS_INV_NONE;
    uint16_t px = 0, py = 0;
    fbs_inv_rot pr = FBS_INV_ROT_90;
    CHECK(fbs_inv_item_place(s, f.a, &pi, &pg, &px, &py, &pr) == FBS_INV_OK);
    CHECK(pi == f.root && pg == 0 && px == 0 && py == 0 && pr == FBS_INV_ROT_0);
    CHECK(fbs_inv_item_place(s, f.b, &pi, &pg, &px, &py, &pr) == FBS_INV_OK);
    CHECK(pi == f.inv_a);
  }

  /* Legal nesting: a container that is not an ancestor. */
  {
    fbs_inv_item d = spawn_at(s, f.root, 0, f.pouch, 1, FBS_INV_ROT_0, 4, 4);
    fbs_inv_inventory inv_d = FBS_INV_NONE;
    CHECK(fbs_inv_item_container(s, d, &inv_d) == FBS_INV_OK);
    IN_TXN(s, fbs_inv_move_to(s, d, f.inv_a, 0, FBS_INV_ROT_0, 2, 2), st);
    CHECK(st == FBS_INV_OK);
    CHECK(cell_at(s, f.inv_a, 0, 2, 2) == d);
    /* and now A into D's inventory is a cycle too */
    IN_TXN(s, fbs_inv_move_to(s, f.a, inv_d, 0, FBS_INV_ROT_0, 0, 0), st);
    CHECK(st == FBS_INV_E_CYCLE);
    /* while the gem, which owns nothing, may go anywhere */
    IN_TXN(s, fbs_inv_move_to(s, f.coin, inv_d, 0, FBS_INV_ROT_0, 1, 1), st);
    CHECK(st == FBS_INV_OK);
  }

  fbs_inv_store_destroy(s);
}

static void test_t6b_recursive_destroy(void) {
  nest_fixture f = build_nest();
  fbs_inv_store *s = f.s;
  fbs_inv_item outside = spawn_at(s, f.root, 0, f.gem, 7, FBS_INV_ROT_0, 5, 5);
  size_t before_len = 0;
  unsigned char *before = NULL;
  uint64_t units = fbs_inv_total_units(s);

  CHECK(units == 15u); /* 3 containers + a 5-gem + a 7-gem */
  before = serialize_alloc(s, &before_len);

  CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
  CHECK(fbs_inv_destroy(s, f.a) == FBS_INV_OK);
  CHECK(fbs_inv_txn_commit(s) == FBS_INV_OK);

  /* Everything inside went with it, at every depth. */
  expect_stale(s, f.a);
  expect_stale(s, f.b);
  expect_stale(s, f.c);
  expect_stale(s, f.coin);
  CHECK(fbs_inv_item_live(s, outside) == 1);
  CHECK(fbs_inv_total_units(s) == 7u); /* dropped by exactly the contained units */
  CHECK(cell_at(s, f.root, 0, 0, 0) == FBS_INV_NONE);
  CHECK(cell_at(s, f.inv_c, 0, 0, 0) == FBS_INV_NONE);
  /* The inventories survive as detached shells; their ids never move. */
  {
    fbs_inv_item owner = FBS_INV_NONE;
    CHECK(fbs_inv_inventory_owner(s, f.inv_a, &owner) == FBS_INV_OK && owner == f.a);
    CHECK(fbs_inv_item_live(s, owner) == 0);
    CHECK(fbs_inv_inventory_count(s) == 4u);
  }

  /* And abort puts all of it back, byte for byte (T-7). */
  CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
  CHECK(fbs_inv_destroy(s, outside) == FBS_INV_OK);
  CHECK(fbs_inv_txn_abort(s) == FBS_INV_OK);
  CHECK(fbs_inv_item_live(s, outside) == 1);

  fbs_inv_store_destroy(s);
  free(before);

  /* The full undo, from a fresh fixture: destroy the whole tree and abort. */
  {
    nest_fixture h = build_nest();
    unsigned char *b0, *b1;
    size_t l0 = 0, l1 = 0;
    b0 = serialize_alloc(h.s, &l0);
    CHECK(fbs_inv_txn_begin(h.s) == FBS_INV_OK);
    CHECK(fbs_inv_destroy(h.s, h.a) == FBS_INV_OK);
    CHECK(fbs_inv_total_units(h.s) == 0u);
    CHECK(fbs_inv_txn_abort(h.s) == FBS_INV_OK);
    b1 = serialize_alloc(h.s, &l1);
    CHECK(blobs_equal(b0, l0, b1, l1));
    CHECK(fbs_inv_total_units(h.s) == 8u);
    CHECK(fbs_inv_item_live(h.s, h.coin) == 1);
    CHECK(cell_at(h.s, h.inv_c, 0, 0, 0) == h.coin);
    free(b0);
    free(b1);
    fbs_inv_store_destroy(h.s);
  }
}

/* ------------------------------------------------------------------------- */
/* T-7 — the headline witness: rollback is byte-identical                     */
/* ------------------------------------------------------------------------- */

typedef struct {
  fbs_inv_store *s;
  fbs_inv_type coin, sword, pack;
  fbs_inv_inventory x, y;
  fbs_inv_slot hand, ring;
  fbs_inv_item a, b, c, worn;
} txn_fixture;

/* Two inventories holding several items, plus an occupied equipment slot. */
static txn_fixture build_txn_fixture(const fbs_inv_config *cfg) {
  static const uint16_t pack_wh[2] = {2, 2};
  txn_fixture f;
  f.s = make_store(cfg);
  f.coin = add_type(f.s, "coin", 1, 1, 20, 0x1u, NULL, 0);
  f.sword = add_type(f.s, "sword", 1, 3, 1, 0x2u, NULL, 0);
  f.pack = add_type(f.s, "pack", 2, 2, 1, 0x4u, pack_wh, 1);
  CHECK(fbs_inv_seal(f.s) == FBS_INV_OK);
  f.x = add_inv1(f.s, 4, 4);
  f.y = add_inv1(f.s, 2, 2);
  f.hand = add_slot(f.s, "hand", 0x2u);
  f.ring = add_slot(f.s, "ring", 0u);
  f.a = spawn_at(f.s, f.x, 0, f.coin, 6, FBS_INV_ROT_0, 0, 0);
  f.b = spawn_at(f.s, f.x, 0, f.coin, 9, FBS_INV_ROT_0, 1, 0);
  f.c = spawn_at(f.s, f.x, 0, f.pack, 1, FBS_INV_ROT_0, 0, 2);
  f.worn = spawn_at(f.s, f.x, 0, f.sword, 1, FBS_INV_ROT_0, 3, 0);
  {
    fbs_inv_status st;
    IN_TXN(f.s, fbs_inv_equip(f.s, f.hand, f.worn), st);
    CHECK(st == FBS_INV_OK);
  }
  return f;
}

static void test_t7_rollback_is_byte_identical(void) {
  txn_fixture f = build_txn_fixture(NULL);
  fbs_inv_store *s = f.s;
  unsigned char *before, *after;
  size_t bl = 0, al = 0;
  fbs_inv_status st;

  before = serialize_alloc(s, &bl);

  /* A multi-step move where the third step does not fit: inventory y is 2x2
     and already holds two coins by then, so the 2x2 pack cannot follow. */
  CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
  CHECK(fbs_inv_move_to(s, f.a, f.y, 0, FBS_INV_ROT_0, 0, 0) == FBS_INV_OK);
  CHECK(fbs_inv_move_to(s, f.b, f.y, 0, FBS_INV_ROT_0, 1, 0) == FBS_INV_OK);
  st = fbs_inv_move_to(s, f.c, f.y, 0, FBS_INV_ROT_0, 0, 0);
  CHECK(st == FBS_INV_E_NO_SPACE);
  CHECK(fbs_inv_txn_abort(s) == FBS_INV_OK);

  after = serialize_alloc(s, &al);
  CHECK(bl == al);
  CHECK(blobs_equal(before, bl, after, al));
  CHECK(cell_at(s, f.x, 0, 0, 0) == f.a);
  CHECK(cell_at(s, f.x, 0, 1, 0) == f.b);
  free(after);

  /* T-7b — the same, with each of the other failure modes. */
  CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
  CHECK(fbs_inv_move_to(s, f.a, f.y, 0, FBS_INV_ROT_0, 0, 0) == FBS_INV_OK);
  {
    fbs_inv_inventory inside = FBS_INV_NONE;
    CHECK(fbs_inv_item_container(s, f.c, &inside) == FBS_INV_OK);
    CHECK(fbs_inv_move_to(s, f.c, inside, 0, FBS_INV_ROT_0, 0, 0) == FBS_INV_E_CYCLE);
  }
  CHECK(fbs_inv_txn_abort(s) == FBS_INV_OK);
  after = serialize_alloc(s, &al);
  CHECK(blobs_equal(before, bl, after, al));
  free(after);

  CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
  CHECK(fbs_inv_move_to(s, f.b, f.y, 0, FBS_INV_ROT_0, 0, 0) == FBS_INV_OK);
  CHECK(fbs_inv_equip(s, f.ring, f.a) == FBS_INV_OK);
  CHECK(fbs_inv_equip(s, f.ring, f.b) == FBS_INV_E_OCCUPIED);
  CHECK(fbs_inv_txn_abort(s) == FBS_INV_OK);
  after = serialize_alloc(s, &al);
  CHECK(blobs_equal(before, bl, after, al));
  free(after);

  /* destroy-then-fail: the recursive destroy of a container, then a refusal */
  CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
  CHECK(fbs_inv_destroy(s, f.c) == FBS_INV_OK);
  CHECK(fbs_inv_destroy(s, f.a) == FBS_INV_OK);
  CHECK(fbs_inv_move_to(s, f.a, f.y, 0, FBS_INV_ROT_0, 0, 0) == FBS_INV_E_STALE);
  CHECK(fbs_inv_txn_abort(s) == FBS_INV_OK);
  after = serialize_alloc(s, &al);
  CHECK(blobs_equal(before, bl, after, al));
  CHECK(fbs_inv_item_live(s, f.a) == 1);
  CHECK(fbs_inv_item_live(s, f.c) == 1);
  free(after);

  /* spawn-then-abort must not leak an item slot, a generation or a container */
  CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
  {
    fbs_inv_item made = FBS_INV_NONE;
    CHECK(fbs_inv_spawn_at(s, f.y, 0, f.pack, 1, FBS_INV_ROT_0, 0, 0, &made) == FBS_INV_OK);
    CHECK(made != FBS_INV_NONE);
    CHECK(fbs_inv_txn_abort(s) == FBS_INV_OK);
    CHECK(fbs_inv_item_live(s, made) == 0 || fbs_inv_item_live(s, made) < 0);
  }
  after = serialize_alloc(s, &al);
  CHECK(blobs_equal(before, bl, after, al));
  free(after);

  free(before);
  fbs_inv_store_destroy(s);
}

static void test_t7c_commit_is_not_a_no_op(void) {
  txn_fixture f = build_txn_fixture(NULL);
  txn_fixture g = build_txn_fixture(NULL);
  unsigned char *before, *one, *many;
  size_t bl = 0, ol = 0, ml = 0;

  before = serialize_alloc(f.s, &bl);

  /* One transaction with three steps that all succeed ... */
  CHECK(fbs_inv_txn_begin(f.s) == FBS_INV_OK);
  CHECK(fbs_inv_move_to(f.s, f.a, f.y, 0, FBS_INV_ROT_0, 0, 0) == FBS_INV_OK);
  CHECK(fbs_inv_move_to(f.s, f.b, f.y, 0, FBS_INV_ROT_0, 1, 0) == FBS_INV_OK);
  CHECK(fbs_inv_move_to(f.s, f.c, f.x, 0, FBS_INV_ROT_0, 2, 2) == FBS_INV_OK);
  CHECK(fbs_inv_txn_commit(f.s) == FBS_INV_OK);
  one = serialize_alloc(f.s, &ol);

  /* ... equals the directly-constructed store that did the same three moves in
     three separate transactions. */
  CHECK(fbs_inv_txn_begin(g.s) == FBS_INV_OK);
  CHECK(fbs_inv_move_to(g.s, g.a, g.y, 0, FBS_INV_ROT_0, 0, 0) == FBS_INV_OK);
  CHECK(fbs_inv_txn_commit(g.s) == FBS_INV_OK);
  CHECK(fbs_inv_txn_begin(g.s) == FBS_INV_OK);
  CHECK(fbs_inv_move_to(g.s, g.b, g.y, 0, FBS_INV_ROT_0, 1, 0) == FBS_INV_OK);
  CHECK(fbs_inv_txn_commit(g.s) == FBS_INV_OK);
  CHECK(fbs_inv_txn_begin(g.s) == FBS_INV_OK);
  CHECK(fbs_inv_move_to(g.s, g.c, g.x, 0, FBS_INV_ROT_0, 2, 2) == FBS_INV_OK);
  CHECK(fbs_inv_txn_commit(g.s) == FBS_INV_OK);
  many = serialize_alloc(g.s, &ml);

  CHECK(blobs_equal(one, ol, many, ml));
  CHECK(!blobs_equal(before, bl, one, ol));

  free(before);
  free(one);
  free(many);
  fbs_inv_store_destroy(f.s);
  fbs_inv_store_destroy(g.s);
}

static void test_t7d_journal_exhaustion(void) {
  fbs_inv_config cfg = fbs_inv_config_default();
  txn_fixture f;
  fbs_inv_store *s;
  unsigned char *before, *after;
  size_t bl = 0, al = 0;
  unsigned step;
  int overflowed = 0;
  fbs_inv_item made = FBS_INV_NONE;

  cfg.max_txn_ops = 8u;
  f = build_txn_fixture(&cfg);
  s = f.s;
  before = serialize_alloc(s, &bl);

  CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
  for (step = 0; step < 20u; ++step) {
    /* Each move costs three journal records, so the third one overflows a
       depth-8 journal. */
    fbs_inv_status st =
        fbs_inv_move_to(s, f.a, f.x, 0, FBS_INV_ROT_0, (uint16_t)(2u + step % 2u), 3);
    if (st == FBS_INV_E_FULL) {
      overflowed = 1;
      CHECK(step == 2u);
      break;
    }
    CHECK(st == FBS_INV_OK);
  }
  CHECK(overflowed);

  /* Poisoned: commit is refused, further mutators are refused, only abort is
     legal, and abort restores the blob byte for byte. */
  CHECK(fbs_inv_txn_commit(s) == FBS_INV_E_TXN);
  CHECK(fbs_inv_move_to(s, f.b, f.y, 0, FBS_INV_ROT_0, 0, 0) == FBS_INV_E_TXN);
  CHECK(fbs_inv_spawn_at(s, f.x, 0, f.coin, 1, FBS_INV_ROT_0, 3, 3, &made) ==
        FBS_INV_E_TXN);
  CHECK(made == FBS_INV_NONE);
  CHECK(fbs_inv_destroy(s, f.b) == FBS_INV_E_TXN);
  CHECK(fbs_inv_txn_active(s) == 1);
  CHECK(fbs_inv_txn_abort(s) == FBS_INV_OK);
  CHECK(fbs_inv_txn_active(s) == 0);

  after = serialize_alloc(s, &al);
  CHECK(blobs_equal(before, bl, after, al));

  /* The store is usable again afterwards. */
  CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
  CHECK(fbs_inv_move_to(s, f.a, f.x, 0, FBS_INV_ROT_0, 3, 3) == FBS_INV_OK);
  CHECK(fbs_inv_txn_commit(s) == FBS_INV_OK);

  free(before);
  free(after);
  fbs_inv_store_destroy(s);
}

static void test_t7e_transaction_discipline(void) {
  txn_fixture f = build_txn_fixture(NULL);
  fbs_inv_store *s = f.s;
  fbs_inv_item made = FBS_INV_NONE;
  uint32_t moved = 0xA5A5A5A5u;

  /* No transaction open: every mutator refuses, and no output is written. */
  CHECK(fbs_inv_txn_active(s) == 0);
  CHECK(fbs_inv_spawn_at(s, f.x, 0, f.coin, 1, FBS_INV_ROT_0, 3, 3, &made) == FBS_INV_E_TXN);
  CHECK(made == FBS_INV_NONE);
  CHECK(fbs_inv_spawn(s, f.x, f.coin, 1, 0, &made) == FBS_INV_E_TXN);
  CHECK(made == FBS_INV_NONE);
  CHECK(fbs_inv_destroy(s, f.a) == FBS_INV_E_TXN);
  CHECK(fbs_inv_move_to(s, f.a, f.y, 0, FBS_INV_ROT_0, 0, 0) == FBS_INV_E_TXN);
  CHECK(fbs_inv_move_auto(s, f.a, f.y, 0) == FBS_INV_E_TXN);
  CHECK(fbs_inv_rotate(s, f.a, FBS_INV_ROT_90) == FBS_INV_E_TXN);
  CHECK(fbs_inv_stack_merge(s, f.a, f.b, 0, &moved) == FBS_INV_E_TXN);
  CHECK(moved == 0xA5A5A5A5u);
  CHECK(fbs_inv_stack_split_to(s, f.b, f.x, 0, FBS_INV_ROT_0, 3, 3, 2, &made) == FBS_INV_E_TXN);
  CHECK(made == FBS_INV_NONE);
  CHECK(fbs_inv_equip(s, f.ring, f.a) == FBS_INV_E_TXN);
  CHECK(fbs_inv_unequip_to(s, f.hand, f.x, 0) == FBS_INV_E_TXN);
  {
    fbs_inv_slot fresh = FBS_INV_NONE;
    CHECK(fbs_inv_slot_add(s, "boot", 4u, 0u, &fresh) == FBS_INV_E_TXN);
    CHECK(fresh == FBS_INV_NONE);
  }
  /* the registration calls above the transaction paragraph still do not need one */
  {
    fbs_inv_type_desc d;
    fbs_inv_type nt = FBS_INV_NONE;
    fbs_inv_inventory ni = FBS_INV_NONE;
    uint16_t wh[2];
    d.width = 1;
    d.height = 1;
    d.max_stack = 1;
    d.tags = 0;
    d.container_wh = NULL;
    d.container_grids = 0;
    CHECK(fbs_inv_type_add(s, "late", 4u, &d, &nt) == FBS_INV_E_SEALED); /* sealed, not E_TXN */
    wh[0] = 2;
    wh[1] = 2;
    CHECK(fbs_inv_inventory_add(s, wh, 1, &ni) == FBS_INV_OK);
  }
  CHECK(fbs_inv_txn_commit(s) == FBS_INV_E_TXN);
  CHECK(fbs_inv_txn_abort(s) == FBS_INV_E_TXN);

  /* Nested begin is refused and leaves the outer transaction alone. */
  CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
  CHECK(fbs_inv_txn_begin(s) == FBS_INV_E_TXN);
  CHECK(fbs_inv_txn_active(s) == 1);
  CHECK(fbs_inv_move_to(s, f.a, f.x, 0, FBS_INV_ROT_0, 3, 3) == FBS_INV_OK);
  CHECK(fbs_inv_txn_commit(s) == FBS_INV_OK);
  CHECK(fbs_inv_txn_active(s) == 0);

  /* Queries never need a transaction. */
  CHECK(fbs_inv_can_place(s, f.x, 0, f.coin, FBS_INV_ROT_0, 2, 3, FBS_INV_NONE) == FBS_INV_OK);
  CHECK(fbs_inv_total_units(s) == 17u);

  /* store_clear drops an open transaction. */
  CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
  CHECK(fbs_inv_destroy(s, f.a) == FBS_INV_OK);
  fbs_inv_store_clear(s);
  CHECK(fbs_inv_txn_active(s) == 0);
  CHECK(fbs_inv_inventory_count(s) == 0u);
  CHECK(fbs_inv_item_count(s) == 0u);
  CHECK(fbs_inv_type_count(s) == 3u);   /* the catalog survives ... */
  CHECK(fbs_inv_is_sealed(s) == 1);     /* ... and so does its seal */
  CHECK(fbs_inv_total_units(s) == 0u);
  /* Generations keep counting, so the handles issued before the clear stay
     unusable even once the indices are reissued. */
  {
    fbs_inv_inventory inv = add_inv1(s, 4, 4);
    fbs_inv_item fresh = spawn_at(s, inv, 0, f.coin, 1, FBS_INV_ROT_0, 0, 0);
    CHECK(fresh != f.a);
    CHECK(fbs_inv_item_live(s, f.a) <= 0);
    CHECK(fbs_inv_item_live(s, fresh) == 1);
  }

  fbs_inv_store_destroy(s);
}

/* ------------------------------------------------------------------------- */
/* T-8 — serialization: determinism, round trip, corruption, truncation       */
/* ------------------------------------------------------------------------- */

#define RICH_HANDLES 7

/* Two construction routes for one logical store. Route 0 places every item at
 * its final anchor; route 1 spawns the same items, in the same order (so item
 * ids and generations match), at different anchors and then moves them into
 * place in a different order. The blob must not be able to tell them apart. */
static fbs_inv_store *build_rich(int route, fbs_inv_item *h, fbs_inv_inventory *invs,
                                 fbs_inv_slot *hand) {
  static const uint16_t pack_wh[2] = {2, 2};
  fbs_inv_store *s = make_store(NULL);
  fbs_inv_type coin = add_type(s, "coin", 1, 1, 20, 0x1u, NULL, 0);
  fbs_inv_type sword = add_type(s, "sword", 1, 3, 1, 0x2u, NULL, 0);
  fbs_inv_type pack = add_type(s, "pack", 2, 2, 1, 0x4u, pack_wh, 1);
  fbs_inv_type gem = add_type(s, "gem", 1, 1, 9, 0x8u, NULL, 0);
  fbs_inv_inventory x, y, inside = FBS_INV_NONE;
  fbs_inv_slot ring;
  fbs_inv_status st;

  CHECK(fbs_inv_seal(s) == FBS_INV_OK);
  x = add_inv1(s, 4, 4);
  y = add_inv1(s, 2, 2);
  *hand = add_slot(s, "hand", 0x2u);
  ring = add_slot(s, "ring", 0u);
  (void)ring;

  if (route == 0) {
    h[0] = spawn_at(s, x, 0, coin, 6, FBS_INV_ROT_0, 0, 0);
    h[1] = spawn_at(s, x, 0, coin, 9, FBS_INV_ROT_0, 1, 0);
    h[2] = spawn_at(s, x, 0, sword, 1, FBS_INV_ROT_0, 3, 0);
    h[3] = spawn_at(s, x, 0, pack, 1, FBS_INV_ROT_0, 0, 2);
    CHECK(fbs_inv_item_container(s, h[3], &inside) == FBS_INV_OK);
    h[4] = spawn_at(s, inside, 0, gem, 4, FBS_INV_ROT_0, 1, 1);
    h[5] = spawn_at(s, y, 0, pack, 1, FBS_INV_ROT_0, 0, 0);
    CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
    CHECK(fbs_inv_destroy(s, h[5]) == FBS_INV_OK);
    CHECK(fbs_inv_txn_commit(s) == FBS_INV_OK);
    h[6] = spawn_at(s, y, 0, coin, 3, FBS_INV_ROT_0, 0, 0);
    IN_TXN(s, fbs_inv_equip(s, *hand, h[2]), st);
    CHECK(st == FBS_INV_OK);
  } else {
    h[0] = spawn_at(s, x, 0, coin, 6, FBS_INV_ROT_0, 2, 0);
    h[1] = spawn_at(s, x, 0, coin, 9, FBS_INV_ROT_0, 2, 1);
    h[2] = spawn_at(s, x, 0, sword, 1, FBS_INV_ROT_0, 3, 0);
    h[3] = spawn_at(s, x, 0, pack, 1, FBS_INV_ROT_0, 0, 0);
    CHECK(fbs_inv_item_container(s, h[3], &inside) == FBS_INV_OK);
    h[4] = spawn_at(s, inside, 0, gem, 4, FBS_INV_ROT_0, 0, 0);
    h[5] = spawn_at(s, y, 0, pack, 1, FBS_INV_ROT_0, 0, 0);
    CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
    CHECK(fbs_inv_destroy(s, h[5]) == FBS_INV_OK);
    CHECK(fbs_inv_txn_commit(s) == FBS_INV_OK);
    h[6] = spawn_at(s, y, 0, coin, 3, FBS_INV_ROT_0, 1, 1);
    IN_TXN(s, fbs_inv_equip(s, *hand, h[2]), st);
    CHECK(st == FBS_INV_OK);
    /* now walk them into place, in an order of its own */
    CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
    CHECK(fbs_inv_move_to(s, h[3], x, 0, FBS_INV_ROT_0, 0, 2) == FBS_INV_OK);
    CHECK(fbs_inv_move_to(s, h[4], inside, 0, FBS_INV_ROT_0, 1, 1) == FBS_INV_OK);
    CHECK(fbs_inv_move_to(s, h[1], x, 0, FBS_INV_ROT_0, 1, 0) == FBS_INV_OK);
    CHECK(fbs_inv_move_to(s, h[0], x, 0, FBS_INV_ROT_0, 0, 0) == FBS_INV_OK);
    CHECK(fbs_inv_move_to(s, h[6], y, 0, FBS_INV_ROT_0, 0, 0) == FBS_INV_OK);
    CHECK(fbs_inv_txn_commit(s) == FBS_INV_OK);
  }
  invs[0] = x;
  invs[1] = y;
  invs[2] = inside;
  return s;
}

/* Every fact the blob is supposed to carry, checked through public handles. */
static void expect_rich_state(const fbs_inv_store *s, const fbs_inv_item *h,
                              const fbs_inv_inventory *invs, fbs_inv_slot hand) {
  fbs_inv_inventory pi = FBS_INV_NONE, inside = FBS_INV_NONE;
  fbs_inv_grid pg = FBS_INV_NONE;
  fbs_inv_slot sl = FBS_INV_NONE;
  fbs_inv_type ty = FBS_INV_NONE;
  fbs_inv_item held = FBS_INV_NONE;
  uint16_t px = 0, py = 0;
  fbs_inv_rot pr = FBS_INV_ROT_90;
  uint32_t n = 0;

  CHECK(fbs_inv_item_place(s, h[0], &pi, &pg, &px, &py, &pr) == FBS_INV_OK);
  CHECK(pi == invs[0] && pg == 0 && px == 0 && py == 0 && pr == FBS_INV_ROT_0);
  CHECK(fbs_inv_item_stack(s, h[0], &n) == FBS_INV_OK && n == 6u);
  CHECK(fbs_inv_item_place(s, h[1], &pi, &pg, &px, &py, &pr) == FBS_INV_OK);
  CHECK(pi == invs[0] && px == 1 && py == 0);
  CHECK(fbs_inv_item_stack(s, h[1], &n) == FBS_INV_OK && n == 9u);

  /* the sword is equipped, so it has no anchor and the slot names it */
  CHECK(fbs_inv_item_place(s, h[2], &pi, &pg, &px, &py, &pr) == FBS_INV_E_NOT_FOUND);
  CHECK(fbs_inv_item_slot(s, h[2], &sl) == FBS_INV_OK && sl == hand);
  CHECK(fbs_inv_slot_item(s, hand, &held) == FBS_INV_OK && held == h[2]);

  CHECK(fbs_inv_item_place(s, h[3], &pi, &pg, &px, &py, &pr) == FBS_INV_OK);
  CHECK(pi == invs[0] && px == 0 && py == 2);
  CHECK(fbs_inv_item_container(s, h[3], &inside) == FBS_INV_OK && inside == invs[2]);
  CHECK(fbs_inv_inventory_owner(s, invs[2], &held) == FBS_INV_OK && held == h[3]);

  CHECK(fbs_inv_item_place(s, h[4], &pi, &pg, &px, &py, &pr) == FBS_INV_OK);
  CHECK(pi == invs[2] && px == 1 && py == 1);
  CHECK(fbs_inv_item_stack(s, h[4], &n) == FBS_INV_OK && n == 4u);
  CHECK(fbs_inv_item_type_of(s, h[4], &ty) == FBS_INV_OK && ty == 3u);

  /* T-8d — the tombstone is still a tombstone; the index was reissued to a
     different item under a new generation. */
  CHECK(fbs_inv_item_live(s, h[5]) == 0);
  CHECK(fbs_inv_item_place(s, h[5], &pi, &pg, &px, &py, &pr) == FBS_INV_E_STALE);
  CHECK(h[5] != h[6]);
  CHECK((h[5] & 0xFFFFu) == (h[6] & 0xFFFFu)); /* same slot index ... */
  CHECK((h[5] >> 16) != (h[6] >> 16));         /* ... different generation */

  CHECK(fbs_inv_item_place(s, h[6], &pi, &pg, &px, &py, &pr) == FBS_INV_OK);
  CHECK(pi == invs[1] && px == 0 && py == 0);
  CHECK(fbs_inv_item_stack(s, h[6], &n) == FBS_INV_OK && n == 3u);

  CHECK(fbs_inv_total_units(s) == 6u + 9u + 1u + 1u + 4u + 3u);
  CHECK(fbs_inv_item_count(s) == 6u);
  CHECK(fbs_inv_inventory_count(s) == 4u);
  /* the detached shell left behind by the destroyed container is still there */
  CHECK(fbs_inv_inventory_owner(s, 3u, &held) == FBS_INV_OK);
  CHECK(fbs_inv_item_live(s, held) == 0);
  {
    size_t count = 99u;
    fbs_inv_item listed[8];
    CHECK(fbs_inv_list_items(s, 3u, listed, 8u, &count) == FBS_INV_OK && count == 0u);
    CHECK(fbs_inv_list_items(s, invs[0], listed, 8u, &count) == FBS_INV_OK && count == 3u);
    CHECK(listed[0] == h[0] && listed[1] == h[1] && listed[2] == h[3]);
    CHECK(fbs_inv_count_of(s, invs[0], 0u, 0, (uint64_t *)0) == FBS_INV_E_INVALID);
  }
  {
    uint64_t total = 0;
    CHECK(fbs_inv_count_of(s, invs[0], 3u, 0, &total) == FBS_INV_OK && total == 0u);
    CHECK(fbs_inv_count_of(s, invs[0], 3u, 1, &total) == FBS_INV_OK && total == 4u);
    CHECK(fbs_inv_count_of(s, invs[0], 0u, 0, &total) == FBS_INV_OK && total == 15u);
  }
}

static void test_t8_determinism_and_round_trip(void) {
  fbs_inv_item h0[RICH_HANDLES], h1[RICH_HANDLES];
  fbs_inv_inventory i0[3], i1[3];
  fbs_inv_slot hand0 = FBS_INV_NONE, hand1 = FBS_INV_NONE;
  fbs_inv_store *a = build_rich(0, h0, i0, &hand0);
  fbs_inv_store *b = build_rich(1, h1, i1, &hand1);
  fbs_inv_store *c = NULL;
  unsigned char *ba, *bb, *bc;
  size_t la = 0, lb = 0, lc = 0;
  unsigned i;

  for (i = 0; i < RICH_HANDLES; ++i) CHECK(h0[i] == h1[i]);
  CHECK(i0[2] == i1[2] && hand0 == hand1);

  ba = serialize_alloc(a, &la);
  bb = serialize_alloc(b, &lb);
  CHECK(blobs_equal(ba, la, bb, lb)); /* two construction routes, one blob */
  CHECK(la == fbs_inv_serialized_size(a));
  CHECK(la == fbs_inv_serialized_size(b));

  expect_rich_state(a, h0, i0, hand0);
  expect_rich_state(b, h1, i1, hand1);

  /* deser(ser(s)) is a fixed point, and every handle still resolves. */
  CHECK(fbs_inv_deserialize(ba, la, NULL, NULL, &c) == FBS_INV_OK);
  bc = serialize_alloc(c, &lc);
  CHECK(blobs_equal(ba, la, bc, lc));
  expect_rich_state(c, h0, i0, hand0);
  CHECK(fbs_inv_is_sealed(c) == 1);
  CHECK(fbs_inv_txn_active(c) == 0);
  {
    /* the reloaded store is fully usable, detached shell and all */
    fbs_inv_status st;
    fbs_inv_item made = FBS_INV_NONE;
    fbs_inv_type coin = FBS_INV_NONE;
    CHECK(fbs_inv_type_find(c, "coin", 4u, &coin) == FBS_INV_OK && coin == 0u);
    IN_TXN(c, fbs_inv_spawn_at(c, i0[0], 0, coin, 2, FBS_INV_ROT_0, 2, 0, &made), st);
    CHECK(st == FBS_INV_OK);
    CHECK(fbs_inv_item_count(c) == 7u);
  }
  free(bc);
  fbs_inv_store_destroy(c);

  /* An explicit config that fits is honoured; one that does not is refused. */
  c = NULL;
  {
    fbs_inv_config cfg = fbs_inv_config_default();
    cfg.max_items = 6u;
    CHECK(fbs_inv_deserialize(ba, la, &cfg, NULL, &c) == FBS_INV_OK);
    CHECK(fbs_inv_item_count(c) == 6u);
    fbs_inv_store_destroy(c);
    c = NULL;
    cfg.max_items = 5u;
    CHECK(fbs_inv_deserialize(ba, la, &cfg, NULL, &c) == FBS_INV_E_FULL);
    CHECK(c == NULL);
    cfg.max_items = 6u;
    cfg.max_grid_dim = 3u;
    CHECK(fbs_inv_deserialize(ba, la, &cfg, NULL, &c) == FBS_INV_E_RANGE);
    CHECK(c == NULL);
    cfg.max_grid_dim = 0u;
    CHECK(fbs_inv_deserialize(ba, la, &cfg, NULL, &c) == FBS_INV_E_INVALID);
    CHECK(c == NULL);
  }

  /* An empty store round-trips too. */
  {
    fbs_inv_store *e = make_store(NULL);
    fbs_inv_store *f = NULL;
    unsigned char *be, *bf;
    size_t le = 0, lf = 0;
    be = serialize_alloc(e, &le);
    CHECK(le == 48u);
    CHECK(fbs_inv_deserialize(be, le, NULL, NULL, &f) == FBS_INV_OK);
    bf = serialize_alloc(f, &lf);
    CHECK(blobs_equal(be, le, bf, lf));
    free(be);
    free(bf);
    fbs_inv_store_destroy(e);
    fbs_inv_store_destroy(f);
  }

  free(ba);
  free(bb);
  fbs_inv_store_destroy(a);
  fbs_inv_store_destroy(b);
}

/* A corrupted blob must be refused without allocating anything and without
 * touching the caller's out-pointer. */
static void expect_schema_reject(const unsigned char *blob, size_t len, const char *what) {
  fbs_inv_store *s = (fbs_inv_store *)0x1;
  counting_alloc ca;
  fbs_inv_allocator alloc;
  fbs_inv_status st;
  ca.allocs = 0;
  ca.frees = 0;
  ca.bytes = 0;
  ca.budget = -1;
  alloc.alloc = ca_alloc;
  alloc.free = ca_free;
  alloc.user = &ca;
  st = fbs_inv_deserialize(blob, len, NULL, &alloc, &s);
  ++g_checks;
  if (st != FBS_INV_E_SCHEMA || s != (fbs_inv_store *)0x1 || ca.allocs != 0) {
    ++g_fails;
    printf("FAIL schema rejection (%s): status %s, out %s, allocs %d\n", what,
           fbs_inv_status_name(st), s == (fbs_inv_store *)0x1 ? "untouched" : "WRITTEN",
           ca.allocs);
    if (st == FBS_INV_OK) fbs_inv_store_destroy(s);
  }
}

static void test_t8b_corruption(void) {
  fbs_inv_item h[RICH_HANDLES];
  fbs_inv_inventory invs[3];
  fbs_inv_slot hand = FBS_INV_NONE;
  fbs_inv_store *s = build_rich(0, h, invs, &hand);
  size_t len = 0, item0, item1;
  unsigned char *good = serialize_alloc(s, &len);
  unsigned char *bad = (unsigned char *)malloc(len);

  CHECK(bad != NULL);
  if (!bad) {
    free(good);
    fbs_inv_store_destroy(s);
    return;
  }
  item0 = item_record_offset(s, 0);
  item1 = item_record_offset(s, 1);

  memcpy(bad, good, len);
  bad[0] = 'X';
  expect_schema_reject(bad, len, "magic");

  memcpy(bad, good, len);
  bad[4] = 2;
  expect_schema_reject(bad, len, "version");

  memcpy(bad, good, len);
  bad[6] = 1;
  expect_schema_reject(bad, len, "flags");

  memcpy(bad, good, len);
  bad[40] = 1;
  expect_schema_reject(bad, len, "reserved header word");

  memcpy(bad, good, len);
  expect_schema_reject(bad, len - 1u, "truncated tail");
  expect_schema_reject(bad, 47u, "truncated header");
  expect_schema_reject(bad, len + 1u, "trailing garbage");

  memcpy(bad, good, len);
  bad[item0 + 16u] = 15; /* x well past the 4x4 grid */
  expect_schema_reject(bad, len, "anchor out of grid");

  memcpy(bad, good, len);
  bad[item1 + 16u] = bad[item0 + 16u]; /* same x ... */
  bad[item1 + 18u] = bad[item0 + 18u]; /* ... and same y as item 0 */
  expect_schema_reject(bad, len, "overlapping footprints");

  memcpy(bad, good, len);
  bad[item0 + 20u] = 2; /* a reserved rotation */
  expect_schema_reject(bad, len, "bad rotation");

  memcpy(bad, good, len);
  bad[item0 + 21u] = 7; /* not a state */
  expect_schema_reject(bad, len, "bad state");

  memcpy(bad, good, len);
  bad[item0 + 24u] = 0; /* stack 0 on a live item */
  expect_schema_reject(bad, len, "zero stack");

  memcpy(bad, good, len);
  bad[item0 + 24u] = 21; /* past the type's max_stack of 20 */
  expect_schema_reject(bad, len, "stack over cap");

  memcpy(bad, good, len);
  bad[item0 + 4u] = 0;
  bad[item0 + 5u] = 0; /* generation 0 is not issuable */
  expect_schema_reject(bad, len, "zero generation");

  memcpy(bad, good, len);
  bad[20] = 9; /* item_count that does not match the record block */
  expect_schema_reject(bad, len, "item count mismatch");

  memcpy(bad, good, len);
  bad[8] = 9; /* type_count that does not match */
  expect_schema_reject(bad, len, "type count mismatch");

  memcpy(bad, good, len);
  bad[36] = 0;
  bad[37] = 0;
  bad[38] = 0;
  bad[39] = 0; /* next_generation 0 */
  expect_schema_reject(bad, len, "bad next_generation");

  free(bad);
  free(good);
  fbs_inv_store_destroy(s);
}

static void test_t8c_truncated_output(void) {
  fbs_inv_item h[RICH_HANDLES];
  fbs_inv_inventory invs[3];
  fbs_inv_slot hand = FBS_INV_NONE;
  fbs_inv_store *s = build_rich(0, h, invs, &hand);
  size_t need = fbs_inv_serialized_size(s), got = 0;
  unsigned char *buf = (unsigned char *)malloc(need);

  CHECK(buf != NULL);
  if (buf) {
    memset(buf, 0xA5, need);
    CHECK(fbs_inv_serialize(s, buf, need - 1u, &got) == FBS_INV_E_TRUNCATED);
    CHECK(got == need);
    CHECK(untouched(buf, need, 0xA5)); /* nothing usable was written */
    got = 0;
    CHECK(fbs_inv_serialize(s, NULL, 0u, &got) == FBS_INV_E_TRUNCATED);
    CHECK(got == need);
    got = 0;
    CHECK(fbs_inv_serialize(s, buf, need, &got) == FBS_INV_OK);
    CHECK(got == need);
    free(buf);
  }
  CHECK(fbs_inv_serialized_size(NULL) == 0u);
  fbs_inv_store_destroy(s);
}

/* ------------------------------------------------------------------------- */
/* T-9 — equipment slots                                                      */
/* ------------------------------------------------------------------------- */

static void test_t9_equipment(void) {
  static const uint16_t pack_wh[2] = {2, 2};
  fbs_inv_store *s = make_store(NULL);
  fbs_inv_type sword = add_type(s, "sword", 1, 3, 1, 0x2u, NULL, 0);
  fbs_inv_type ring = add_type(s, "ring", 1, 1, 1, 0x8u, NULL, 0);
  fbs_inv_type pack = add_type(s, "pack", 2, 2, 1, 0x4u, pack_wh, 1);
  fbs_inv_type gem = add_type(s, "gem", 1, 1, 9, 0x1u, NULL, 0);
  fbs_inv_inventory bag = add_inv1(s, 4, 4);
  fbs_inv_inventory tiny = add_inv1(s, 1, 1);
  fbs_inv_slot any = add_slot(s, "trinket", 0u);
  fbs_inv_slot weapon = add_slot(s, "weapon", 0x2u | 0x4u);
  fbs_inv_item a, b, p, g;
  fbs_inv_inventory inside = FBS_INV_NONE;
  fbs_inv_item held = FBS_INV_NONE;
  fbs_inv_slot where = FBS_INV_NONE;
  fbs_inv_status st;

  /* accept_tags == 0 accepts anything; a mask is HasAny. */
  CHECK(fbs_inv_slot_accepts(s, any, sword) == FBS_INV_OK);
  CHECK(fbs_inv_slot_accepts(s, any, ring) == FBS_INV_OK);
  CHECK(fbs_inv_slot_accepts(s, weapon, sword) == FBS_INV_OK);
  CHECK(fbs_inv_slot_accepts(s, weapon, pack) == FBS_INV_OK);
  CHECK(fbs_inv_slot_accepts(s, weapon, ring) == FBS_INV_E_REJECTED);
  CHECK(fbs_inv_slot_accepts(s, weapon, gem) == FBS_INV_E_REJECTED);

  a = spawn_at(s, bag, 0, sword, 1, FBS_INV_ROT_0, 0, 0);
  b = spawn_at(s, bag, 0, sword, 1, FBS_INV_ROT_0, 1, 0);
  {
    fbs_inv_item r = spawn_at(s, bag, 0, ring, 1, FBS_INV_ROT_0, 3, 0);
    IN_TXN(s, fbs_inv_equip(s, weapon, r), st);
    CHECK(st == FBS_INV_E_REJECTED);
    CHECK(fbs_inv_slot_item(s, weapon, &held) == FBS_INV_E_NOT_FOUND);
    CHECK(cell_at(s, bag, 0, 3, 0) == r);
  }

  IN_TXN(s, fbs_inv_equip(s, weapon, a), st);
  CHECK(st == FBS_INV_OK);
  CHECK(fbs_inv_slot_item(s, weapon, &held) == FBS_INV_OK && held == a);
  CHECK(cell_at(s, bag, 0, 0, 0) == FBS_INV_NONE); /* its cells were released */
  CHECK(fbs_inv_item_slot(s, a, &where) == FBS_INV_OK && where == weapon);

  /* The I-14 witness: an occupied slot is never silently overwritten. */
  IN_TXN(s, fbs_inv_equip(s, weapon, b), st);
  CHECK(st == FBS_INV_E_OCCUPIED);
  CHECK(fbs_inv_slot_item(s, weapon, &held) == FBS_INV_OK && held == a);
  CHECK(cell_at(s, bag, 0, 1, 0) == b); /* and b never left the grid */

  /* Unequipping into a full inventory is refused, atomically. */
  IN_TXN(s, fbs_inv_unequip_to(s, weapon, tiny, 1), st);
  CHECK(st == FBS_INV_E_NO_SPACE);
  CHECK(fbs_inv_slot_item(s, weapon, &held) == FBS_INV_OK && held == a);

  IN_TXN(s, fbs_inv_unequip_to(s, weapon, bag, 1), st);
  CHECK(st == FBS_INV_OK);
  CHECK(fbs_inv_slot_item(s, weapon, &held) == FBS_INV_E_NOT_FOUND);
  CHECK(fbs_inv_item_slot(s, a, &where) == FBS_INV_E_NOT_FOUND);
  CHECK(fbs_inv_item_live(s, a) == 1);
  IN_TXN(s, fbs_inv_unequip_to(s, weapon, bag, 1), st);
  CHECK(st == FBS_INV_E_NOT_FOUND); /* an empty slot has nothing to give */

  /* An equipped container keeps its contents reachable and counted. */
  p = spawn_at(s, bag, 0, pack, 1, FBS_INV_ROT_0, 2, 2);
  CHECK(fbs_inv_item_container(s, p, &inside) == FBS_INV_OK);
  g = spawn_at(s, inside, 0, gem, 6, FBS_INV_ROT_0, 0, 0);
  CHECK(fbs_inv_total_units(s) == 1u + 1u + 1u + 1u + 6u);
  IN_TXN(s, fbs_inv_equip(s, weapon, p), st);
  CHECK(st == FBS_INV_OK);
  CHECK(fbs_inv_item_live(s, g) == 1);
  CHECK(cell_at(s, inside, 0, 0, 0) == g);
  CHECK(fbs_inv_item_container(s, p, &inside) == FBS_INV_OK);
  CHECK(fbs_inv_total_units(s) == 10u);
  {
    uint64_t n = 0;
    CHECK(fbs_inv_count_of(s, inside, gem, 0, &n) == FBS_INV_OK && n == 6u);
  }
  /* Unequipping the container back into its own inventory is still a cycle. */
  IN_TXN(s, fbs_inv_unequip_to(s, weapon, inside, 0), st);
  CHECK(st == FBS_INV_E_CYCLE);
  CHECK(fbs_inv_slot_item(s, weapon, &held) == FBS_INV_OK && held == p);
  /* Destroying an equipped container empties the slot and takes the contents. */
  CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
  CHECK(fbs_inv_destroy(s, p) == FBS_INV_OK);
  CHECK(fbs_inv_slot_item(s, weapon, &held) == FBS_INV_E_NOT_FOUND);
  expect_stale(s, g);
  CHECK(fbs_inv_txn_abort(s) == FBS_INV_OK);
  CHECK(fbs_inv_slot_item(s, weapon, &held) == FBS_INV_OK && held == p);
  CHECK(fbs_inv_item_live(s, g) == 1);

  fbs_inv_store_destroy(s);
}

/* ------------------------------------------------------------------------- */
/* T-10 — one call per status value, table driven                             */
/* ------------------------------------------------------------------------- */

static fbs_inv_status err_ok(void) {
  fbs_inv_store *s = make_store(NULL);
  fbs_inv_type t = add_type(s, "unit", 1, 1, 1, 0, NULL, 0);
  fbs_inv_inventory inv = add_inv1(s, 2, 2);
  fbs_inv_item it = FBS_INV_NONE;
  fbs_inv_status st;
  IN_TXN(s, fbs_inv_spawn_at(s, inv, 0, t, 1, FBS_INV_ROT_0, 0, 0, &it), st);
  fbs_inv_store_destroy(s);
  return st;
}

static fbs_inv_status err_invalid(void) {
  return fbs_inv_store_create(NULL, NULL, NULL);
}

static fbs_inv_status err_not_found(void) {
  fbs_inv_store *s = make_store(NULL);
  fbs_inv_type t = FBS_INV_NONE;
  fbs_inv_status st;
  (void)add_type(s, "known", 1, 1, 1, 0, NULL, 0);
  st = fbs_inv_type_find(s, "missing", 7u, &t);
  CHECK(t == FBS_INV_NONE);
  fbs_inv_store_destroy(s);
  return st;
}

static fbs_inv_status err_exists(void) {
  fbs_inv_store *s = make_store(NULL);
  fbs_inv_type_desc d;
  fbs_inv_type t = 0xA5A5A5A5u;
  fbs_inv_status st;
  (void)add_type(s, "dup", 1, 1, 1, 0, NULL, 0);
  d.width = 2;
  d.height = 2;
  d.max_stack = 1;
  d.tags = 0;
  d.container_wh = NULL;
  d.container_grids = 0;
  st = fbs_inv_type_add(s, "dup", 3u, &d, &t);
  CHECK(t == 0xA5A5A5A5u); /* *out untouched */
  CHECK(fbs_inv_type_count(s) == 1u);
  fbs_inv_store_destroy(s);
  return st;
}

static fbs_inv_status err_full_types(void) {
  fbs_inv_config cfg = fbs_inv_config_default();
  fbs_inv_store *s;
  fbs_inv_type_desc d;
  fbs_inv_type t = FBS_INV_NONE;
  fbs_inv_status st;
  cfg.max_types = 1u;
  s = make_store(&cfg);
  (void)add_type(s, "a", 1, 1, 1, 0, NULL, 0);
  d.width = 1;
  d.height = 1;
  d.max_stack = 1;
  d.tags = 0;
  d.container_wh = NULL;
  d.container_grids = 0;
  st = fbs_inv_type_add(s, "b", 1u, &d, &t);
  fbs_inv_store_destroy(s);
  return st;
}

static fbs_inv_status err_full_inventories(void) {
  fbs_inv_config cfg = fbs_inv_config_default();
  fbs_inv_store *s;
  fbs_inv_inventory inv = FBS_INV_NONE;
  uint16_t wh[2];
  fbs_inv_status st;
  cfg.max_inventories = 1u;
  s = make_store(&cfg);
  (void)add_inv1(s, 2, 2);
  wh[0] = 2;
  wh[1] = 2;
  st = fbs_inv_inventory_add(s, wh, 1, &inv);
  CHECK(inv == FBS_INV_NONE);
  fbs_inv_store_destroy(s);
  return st;
}

static fbs_inv_status err_full_grids(void) {
  fbs_inv_config cfg = fbs_inv_config_default();
  fbs_inv_store *s;
  fbs_inv_inventory inv = FBS_INV_NONE;
  uint16_t wh[4];
  fbs_inv_status st;
  cfg.max_grids = 2u;
  s = make_store(&cfg);
  (void)add_inv1(s, 2, 2);
  wh[0] = 1;
  wh[1] = 1;
  wh[2] = 1;
  wh[3] = 1;
  st = fbs_inv_inventory_add(s, wh, 2, &inv);
  fbs_inv_store_destroy(s);
  return st;
}

static fbs_inv_status err_full_cells(void) {
  fbs_inv_config cfg = fbs_inv_config_default();
  fbs_inv_store *s;
  fbs_inv_inventory inv = FBS_INV_NONE;
  uint16_t wh[2];
  fbs_inv_status st;
  cfg.max_cells = 4u;
  s = make_store(&cfg);
  wh[0] = 3;
  wh[1] = 3;
  st = fbs_inv_inventory_add(s, wh, 1, &inv);
  fbs_inv_store_destroy(s);
  return st;
}

static fbs_inv_status err_full_items(void) {
  fbs_inv_config cfg = fbs_inv_config_default();
  fbs_inv_store *s;
  fbs_inv_type t;
  fbs_inv_inventory inv;
  fbs_inv_item it = FBS_INV_NONE;
  fbs_inv_status st;
  cfg.max_items = 1u;
  s = make_store(&cfg);
  t = add_type(s, "unit", 1, 1, 1, 0, NULL, 0);
  inv = add_inv1(s, 4, 4);
  (void)spawn_at(s, inv, 0, t, 1, FBS_INV_ROT_0, 0, 0);
  IN_TXN(s, fbs_inv_spawn_at(s, inv, 0, t, 1, FBS_INV_ROT_0, 1, 0, &it), st);
  CHECK(it == FBS_INV_NONE);
  fbs_inv_store_destroy(s);
  return st;
}

static fbs_inv_status err_full_slots(void) {
  fbs_inv_config cfg = fbs_inv_config_default();
  fbs_inv_store *s;
  fbs_inv_slot sl = FBS_INV_NONE;
  fbs_inv_status st;
  cfg.max_slots = 0u;
  s = make_store(&cfg);
  IN_TXN(s, fbs_inv_slot_add(s, "hand", 4u, 0u, &sl), st);
  CHECK(sl == FBS_INV_NONE);
  fbs_inv_store_destroy(s);
  return st;
}

static fbs_inv_status err_full_keys(void) {
  fbs_inv_config cfg = fbs_inv_config_default();
  fbs_inv_store *s;
  fbs_inv_type_desc d;
  fbs_inv_type t = FBS_INV_NONE;
  fbs_inv_status st;
  cfg.max_key_bytes = 4u;
  s = make_store(&cfg);
  (void)add_type(s, "abcd", 1, 1, 1, 0, NULL, 0);
  d.width = 1;
  d.height = 1;
  d.max_stack = 1;
  d.tags = 0;
  d.container_wh = NULL;
  d.container_grids = 0;
  st = fbs_inv_type_add(s, "e", 1u, &d, &t);
  fbs_inv_store_destroy(s);
  return st;
}

static fbs_inv_status err_full_journal(void) {
  fbs_inv_config cfg = fbs_inv_config_default();
  fbs_inv_store *s;
  fbs_inv_type t;
  fbs_inv_inventory inv;
  fbs_inv_item it;
  fbs_inv_status st = FBS_INV_OK;
  unsigned k;
  cfg.max_txn_ops = 8u;
  s = make_store(&cfg);
  t = add_type(s, "unit", 1, 1, 1, 0, NULL, 0);
  inv = add_inv1(s, 4, 4);
  it = spawn_at(s, inv, 0, t, 1, FBS_INV_ROT_0, 0, 0);
  CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
  for (k = 0; k < 10u && st == FBS_INV_OK; ++k)
    st = fbs_inv_move_to(s, it, inv, 0, FBS_INV_ROT_0, (uint16_t)(k % 4u), 1);
  CHECK(fbs_inv_txn_abort(s) == FBS_INV_OK);
  fbs_inv_store_destroy(s);
  return st;
}

static fbs_inv_status err_range(void) {
  fbs_inv_store *s = make_store(NULL);
  fbs_inv_type_desc d;
  fbs_inv_type t = FBS_INV_NONE;
  fbs_inv_status st;
  d.width = 0;
  d.height = 1;
  d.max_stack = 1;
  d.tags = 0;
  d.container_wh = NULL;
  d.container_grids = 0;
  st = fbs_inv_type_add(s, "bad", 3u, &d, &t);
  CHECK(t == FBS_INV_NONE);
  fbs_inv_store_destroy(s);
  return st;
}

static fbs_inv_status err_no_space(void) {
  fbs_inv_store *s = make_store(NULL);
  fbs_inv_type t = add_type(s, "unit", 1, 1, 1, 0, NULL, 0);
  fbs_inv_inventory inv = add_inv1(s, 1, 1);
  fbs_inv_item it = FBS_INV_NONE;
  fbs_inv_status st;
  (void)spawn_at(s, inv, 0, t, 1, FBS_INV_ROT_0, 0, 0);
  IN_TXN(s, fbs_inv_spawn_at(s, inv, 0, t, 1, FBS_INV_ROT_0, 0, 0, &it), st);
  fbs_inv_store_destroy(s);
  return st;
}

static fbs_inv_status err_occupied(void) {
  fbs_inv_store *s = make_store(NULL);
  fbs_inv_type t = add_type(s, "unit", 1, 1, 1, 0, NULL, 0);
  fbs_inv_inventory inv = add_inv1(s, 2, 2);
  fbs_inv_slot sl = add_slot(s, "hand", 0u);
  fbs_inv_item a = spawn_at(s, inv, 0, t, 1, FBS_INV_ROT_0, 0, 0);
  fbs_inv_item b = spawn_at(s, inv, 0, t, 1, FBS_INV_ROT_0, 1, 0);
  fbs_inv_status st;
  IN_TXN(s, fbs_inv_equip(s, sl, a), st);
  CHECK(st == FBS_INV_OK);
  IN_TXN(s, fbs_inv_equip(s, sl, b), st);
  fbs_inv_store_destroy(s);
  return st;
}

static fbs_inv_status err_rejected(void) {
  fbs_inv_store *s = make_store(NULL);
  fbs_inv_type t = add_type(s, "unit", 1, 1, 1, 0x1u, NULL, 0);
  fbs_inv_inventory inv = add_inv1(s, 2, 2);
  fbs_inv_slot sl = add_slot(s, "hand", 0x2u);
  fbs_inv_item a = spawn_at(s, inv, 0, t, 1, FBS_INV_ROT_0, 0, 0);
  fbs_inv_status st;
  IN_TXN(s, fbs_inv_equip(s, sl, a), st);
  fbs_inv_store_destroy(s);
  return st;
}

static fbs_inv_status err_cycle(void) {
  nest_fixture f = build_nest();
  fbs_inv_status st;
  IN_TXN(f.s, fbs_inv_move_to(f.s, f.a, f.inv_c, 0, FBS_INV_ROT_0, 1, 1), st);
  fbs_inv_store_destroy(f.s);
  return st;
}

static fbs_inv_status err_stale(void) {
  fbs_inv_store *s = make_store(NULL);
  fbs_inv_type t = add_type(s, "unit", 1, 1, 1, 0, NULL, 0);
  fbs_inv_inventory inv = add_inv1(s, 2, 2);
  fbs_inv_item a = spawn_at(s, inv, 0, t, 1, FBS_INV_ROT_0, 0, 0);
  fbs_inv_type got = FBS_INV_NONE;
  fbs_inv_status st;
  CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
  CHECK(fbs_inv_destroy(s, a) == FBS_INV_OK);
  CHECK(fbs_inv_txn_commit(s) == FBS_INV_OK);
  st = fbs_inv_item_type_of(s, a, &got);
  CHECK(got == FBS_INV_NONE);
  fbs_inv_store_destroy(s);
  return st;
}

static fbs_inv_status err_schema(void) {
  fbs_inv_store *s = (fbs_inv_store *)0x1;
  static const unsigned char junk[48] = {0};
  fbs_inv_status st = fbs_inv_deserialize(junk, sizeof junk, NULL, NULL, &s);
  CHECK(s == (fbs_inv_store *)0x1);
  return st;
}

static fbs_inv_status err_truncated(void) {
  fbs_inv_store *s = make_store(NULL);
  size_t got = 0;
  unsigned char one = 0xA5u;
  fbs_inv_status st = fbs_inv_serialize(s, &one, 1u, &got);
  CHECK(got == 48u);
  CHECK(one == 0xA5u);
  fbs_inv_store_destroy(s);
  return st;
}

static fbs_inv_status err_sealed(void) {
  fbs_inv_store *s = make_store(NULL);
  fbs_inv_type_desc d;
  fbs_inv_type t = FBS_INV_NONE;
  fbs_inv_status st;
  (void)add_type(s, "before", 1, 1, 1, 0, NULL, 0);
  CHECK(fbs_inv_is_sealed(s) == 0);
  CHECK(fbs_inv_seal(s) == FBS_INV_OK);
  CHECK(fbs_inv_is_sealed(s) == 1);
  d.width = 1;
  d.height = 1;
  d.max_stack = 1;
  d.tags = 0;
  d.container_wh = NULL;
  d.container_grids = 0;
  st = fbs_inv_type_add(s, "after", 5u, &d, &t);
  CHECK(t == FBS_INV_NONE);
  CHECK(fbs_inv_type_count(s) == 1u);
  fbs_inv_store_destroy(s);
  return st;
}

static fbs_inv_status err_txn(void) {
  fbs_inv_store *s = make_store(NULL);
  fbs_inv_type t = add_type(s, "unit", 1, 1, 1, 0, NULL, 0);
  fbs_inv_inventory inv = add_inv1(s, 2, 2);
  fbs_inv_item it = FBS_INV_NONE;
  fbs_inv_status st = fbs_inv_spawn_at(s, inv, 0, t, 1, FBS_INV_ROT_0, 0, 0, &it);
  CHECK(it == FBS_INV_NONE);
  fbs_inv_store_destroy(s);
  return st;
}

static fbs_inv_status err_memory(void) {
  counting_alloc ca;
  fbs_inv_allocator alloc;
  fbs_inv_store *s = (fbs_inv_store *)0x1;
  fbs_inv_status st;
  ca.allocs = 0;
  ca.frees = 0;
  ca.bytes = 0;
  ca.budget = 0;
  alloc.alloc = ca_alloc;
  alloc.free = ca_free;
  alloc.user = &ca;
  st = fbs_inv_store_create(NULL, &alloc, &s);
  CHECK(s == (fbs_inv_store *)0x1);
  CHECK(ca.allocs == 0 && ca.frees == 0);
  return st;
}

typedef fbs_inv_status (*err_fn)(void);

typedef struct {
  fbs_inv_status expect;
  const char *name;
  err_fn fn;
} err_case;

static void test_t10_error_table(void) {
  static const err_case cases[] = {
      {FBS_INV_OK, "ok", err_ok},
      {FBS_INV_E_INVALID, "invalid", err_invalid},
      {FBS_INV_E_NOT_FOUND, "not_found", err_not_found},
      {FBS_INV_E_EXISTS, "exists", err_exists},
      {FBS_INV_E_FULL, "full/types", err_full_types},
      {FBS_INV_E_FULL, "full/inventories", err_full_inventories},
      {FBS_INV_E_FULL, "full/grids", err_full_grids},
      {FBS_INV_E_FULL, "full/cells", err_full_cells},
      {FBS_INV_E_FULL, "full/items", err_full_items},
      {FBS_INV_E_FULL, "full/slots", err_full_slots},
      {FBS_INV_E_FULL, "full/keys", err_full_keys},
      {FBS_INV_E_FULL, "full/journal", err_full_journal},
      {FBS_INV_E_RANGE, "range", err_range},
      {FBS_INV_E_NO_SPACE, "no_space", err_no_space},
      {FBS_INV_E_OCCUPIED, "occupied", err_occupied},
      {FBS_INV_E_REJECTED, "rejected", err_rejected},
      {FBS_INV_E_CYCLE, "cycle", err_cycle},
      {FBS_INV_E_STALE, "stale", err_stale},
      {FBS_INV_E_SCHEMA, "schema", err_schema},
      {FBS_INV_E_TRUNCATED, "truncated", err_truncated},
      {FBS_INV_E_SEALED, "sealed", err_sealed},
      {FBS_INV_E_TXN, "txn", err_txn},
      {FBS_INV_E_MEMORY, "memory", err_memory}};
  size_t i;
  for (i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
    fbs_inv_status got = cases[i].fn();
    ++g_checks;
    if (got != cases[i].expect) {
      ++g_fails;
      printf("FAIL error case %s: expected %s, got %s\n", cases[i].name,
             fbs_inv_status_name(cases[i].expect), fbs_inv_status_name(got));
    }
  }
}

static void test_status_names(void) {
  static const int all[] = {FBS_INV_OK,         FBS_INV_E_INVALID,   FBS_INV_E_NOT_FOUND,
                            FBS_INV_E_EXISTS,   FBS_INV_E_FULL,      FBS_INV_E_RANGE,
                            FBS_INV_E_NO_SPACE, FBS_INV_E_OCCUPIED,  FBS_INV_E_REJECTED,
                            FBS_INV_E_CYCLE,    FBS_INV_E_STALE,     FBS_INV_E_SCHEMA,
                            FBS_INV_E_TRUNCATED, FBS_INV_E_SEALED,   FBS_INV_E_TXN,
                            FBS_INV_E_MEMORY};
  size_t i, j;
  size_t n = sizeof all / sizeof all[0];
  CHECK(n == 16u);
  for (i = 0; i < n; ++i) {
    const char *a = fbs_inv_status_name(all[i]);
    CHECK(a != NULL);
    CHECK(a[0] != '\0');
    CHECK(strcmp(a, "unknown") != 0);
    for (j = 0; j < i; ++j) CHECK(strcmp(a, fbs_inv_status_name(all[j])) != 0);
  }
  CHECK(strcmp(fbs_inv_status_name(FBS_INV_OK), "ok") == 0);
  CHECK(strcmp(fbs_inv_status_name(FBS_INV_E_CYCLE), "cycle") == 0);
  CHECK(strcmp(fbs_inv_status_name(FBS_INV_E_NO_SPACE), "no_space") == 0);
  /* out of range in both directions */
  CHECK(strcmp(fbs_inv_status_name(-16), "unknown") == 0);
  CHECK(strcmp(fbs_inv_status_name(-999), "unknown") == 0);
  CHECK(strcmp(fbs_inv_status_name(1), "unknown") == 0);
  CHECK(strcmp(fbs_inv_status_name(999), "unknown") == 0);

  CHECK(fbs_inv_version() == FBS_INV_VERSION);
  CHECK(fbs_inv_version() == 100u);
  {
    fbs_inv_config cfg = fbs_inv_config_default();
    CHECK(cfg.max_types == 64u);
    CHECK(cfg.max_inventories == 32u);
    CHECK(cfg.max_grids == 128u);
    CHECK(cfg.max_cells == 8192u);
    CHECK(cfg.max_items == 1024u);
    CHECK(cfg.max_slots == 32u);
    CHECK(cfg.max_key_bytes == 4096u);
    CHECK(cfg.max_txn_ops == 256u);
    CHECK(cfg.max_grid_dim == 64u);
  }
}

/* ------------------------------------------------------------------------- */
/* T-11 — allocator failure, allocation count and reported memory             */
/* ------------------------------------------------------------------------- */

static void test_t11_allocator(void) {
  counting_alloc ca;
  fbs_inv_allocator alloc;
  fbs_inv_store *s = NULL;
  fbs_inv_item h[RICH_HANDLES];
  fbs_inv_inventory invs[3];
  fbs_inv_slot hand = FBS_INV_NONE;
  unsigned char *blob;
  size_t len = 0;

  alloc.alloc = ca_alloc;
  alloc.free = ca_free;
  alloc.user = &ca;

  /* T-11b — exactly one allocation, and store_memory reports its size. */
  ca.allocs = 0;
  ca.frees = 0;
  ca.bytes = 0;
  ca.budget = -1;
  CHECK(fbs_inv_store_create(NULL, &alloc, &s) == FBS_INV_OK);
  CHECK(ca.allocs == 1);
  CHECK(fbs_inv_store_memory(s) == ca.bytes);
  CHECK(fbs_inv_store_memory(NULL) == 0u);
  {
    /* nothing after create allocates, however much is put in the store */
    static const uint16_t pack_wh[2] = {2, 2};
    fbs_inv_type t = add_type(s, "pack", 2, 2, 1, 0, pack_wh, 1);
    fbs_inv_inventory inv = add_inv1(s, 4, 4);
    fbs_inv_item it = spawn_at(s, inv, 0, t, 1, FBS_INV_ROT_0, 0, 0);
    fbs_inv_status st;
    (void)it;
    IN_TXN(s, fbs_inv_destroy(s, it), st);
    CHECK(st == FBS_INV_OK);
    CHECK(ca.allocs == 1);
  }
  fbs_inv_store_destroy(s);
  CHECK(ca.frees == 1);
  s = NULL;

  /* create with a refusing allocator */
  ca.allocs = 0;
  ca.frees = 0;
  ca.bytes = 0;
  ca.budget = 0;
  s = (fbs_inv_store *)0x1;
  CHECK(fbs_inv_store_create(NULL, &alloc, &s) == FBS_INV_E_MEMORY);
  CHECK(s == (fbs_inv_store *)0x1);
  CHECK(ca.allocs == 0 && ca.frees == 0);

  /* deserialize with a refusing allocator, on a blob that is otherwise valid */
  {
    fbs_inv_store *src = build_rich(0, h, invs, &hand);
    blob = serialize_alloc(src, &len);
    fbs_inv_store_destroy(src);
  }
  ca.allocs = 0;
  ca.frees = 0;
  ca.bytes = 0;
  ca.budget = 0;
  s = (fbs_inv_store *)0x1;
  CHECK(fbs_inv_deserialize(blob, len, NULL, &alloc, &s) == FBS_INV_E_MEMORY);
  CHECK(s == (fbs_inv_store *)0x1);
  CHECK(ca.allocs == 0 && ca.frees == 0);

  ca.budget = -1;
  s = NULL;
  CHECK(fbs_inv_deserialize(blob, len, NULL, &alloc, &s) == FBS_INV_OK);
  CHECK(ca.allocs == 1);
  CHECK(fbs_inv_store_memory(s) == ca.bytes);
  fbs_inv_store_destroy(s);
  CHECK(ca.frees == 1);

  /* a half-built allocator is rejected outright */
  {
    fbs_inv_allocator broken;
    fbs_inv_store *out = (fbs_inv_store *)0x1;
    broken.alloc = NULL;
    broken.free = ca_free;
    broken.user = &ca;
    CHECK(fbs_inv_store_create(NULL, &broken, &out) == FBS_INV_E_INVALID);
    broken.alloc = ca_alloc;
    broken.free = NULL;
    CHECK(fbs_inv_store_create(NULL, &broken, &out) == FBS_INV_E_INVALID);
    CHECK(out == (fbs_inv_store *)0x1);
  }

  free(blob);
  fbs_inv_store_destroy(NULL); /* NULL is a no-op, not a crash */
  fbs_inv_store_clear(NULL);
}

/* ------------------------------------------------------------------------- */
/* Argument hygiene: NULL, bad enums and bad ids on every entry point, with   */
/* the caller's outputs pre-filled with 0xA5 and checked afterwards.          */
/* ------------------------------------------------------------------------- */

#define A5_U32 0xA5A5A5A5u
#define A5_U16 ((uint16_t)0xA5A5u)

static void test_invalid_arguments(void) {
  static const uint16_t pack_wh[2] = {2, 2};
  fbs_inv_store *s = make_store(NULL);
  fbs_inv_type t = add_type(s, "pack", 2, 2, 1, 0x1u, pack_wh, 1);
  fbs_inv_inventory inv = add_inv1(s, 4, 4);
  fbs_inv_slot sl = add_slot(s, "hand", 0u);
  fbs_inv_item it = spawn_at(s, inv, 0, t, 1, FBS_INV_ROT_0, 0, 0);
  fbs_inv_type_desc desc;
  fbs_inv_type ot = A5_U32;
  fbs_inv_inventory oi = A5_U32;
  fbs_inv_grid og = A5_U32;
  fbs_inv_item oit = A5_U32;
  fbs_inv_slot os = A5_U32;
  fbs_inv_rot orot = (fbs_inv_rot)FBS_INV_ROT_90;
  uint16_t ow = A5_U16, oh = A5_U16;
  uint32_t on = A5_U32;
  uint64_t o64 = 0xA5A5A5A5A5A5A5A5u;
  size_t osz = (size_t)0xA5A5A5A5u;
  const char *okey = (const char *)0x1;
  fbs_inv_item bad_handle = 0xFFFF0000u | 0x00FFu; /* index never issued */

  desc.width = 1;
  desc.height = 1;
  desc.max_stack = 1;
  desc.tags = 0;
  desc.container_wh = NULL;
  desc.container_grids = 0;

  /* store */
  CHECK(fbs_inv_store_create(NULL, NULL, NULL) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_store_memory(NULL) == 0u);

  /* types */
  CHECK(fbs_inv_type_add(NULL, "k", 1u, &desc, &ot) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_type_add(s, NULL, 1u, &desc, &ot) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_type_add(s, "k", 1u, NULL, &ot) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_type_add(s, "k", 1u, &desc, NULL) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_type_add(s, "k", 0u, &desc, &ot) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_type_add(s, "k", 256u, &desc, &ot) == FBS_INV_E_INVALID);
  CHECK(ot == A5_U32);
  desc.container_grids = 1;
  desc.container_wh = NULL;
  CHECK(fbs_inv_type_add(s, "k", 1u, &desc, &ot) == FBS_INV_E_INVALID);
  desc.container_grids = 65;
  desc.container_wh = pack_wh;
  CHECK(fbs_inv_type_add(s, "k", 1u, &desc, &ot) == FBS_INV_E_RANGE);
  desc.container_grids = 0;
  desc.container_wh = NULL;
  desc.max_stack = 0;
  CHECK(fbs_inv_type_add(s, "k", 1u, &desc, &ot) == FBS_INV_E_RANGE);
  desc.max_stack = (1u << 24) + 1u;
  CHECK(fbs_inv_type_add(s, "k", 1u, &desc, &ot) == FBS_INV_E_RANGE);
  desc.max_stack = 1;
  desc.height = 65; /* past the default max_grid_dim */
  CHECK(fbs_inv_type_add(s, "k", 1u, &desc, &ot) == FBS_INV_E_RANGE);
  desc.height = 1;
  CHECK(ot == A5_U32);

  CHECK(fbs_inv_type_find(NULL, "pack", 4u, &ot) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_type_find(s, NULL, 4u, &ot) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_type_find(s, "pack", 4u, NULL) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_type_find(s, "pack", 0u, &ot) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_type_find(s, "nope", 4u, &ot) == FBS_INV_E_NOT_FOUND);
  CHECK(ot == A5_U32);
  CHECK(fbs_inv_type_find(s, "pack", 4u, &ot) == FBS_INV_OK && ot == t);

  CHECK(fbs_inv_type_key(NULL, t, &okey, &osz) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_type_key(s, t, NULL, &osz) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_type_key(s, t, &okey, NULL) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_type_key(s, 99u, &okey, &osz) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_type_key(s, FBS_INV_NONE, &okey, &osz) == FBS_INV_E_INVALID);
  CHECK(okey == (const char *)0x1 && osz == (size_t)0xA5A5A5A5u);
  CHECK(fbs_inv_type_key(s, t, &okey, &osz) == FBS_INV_OK);
  CHECK(osz == 4u && memcmp(okey, "pack", 4u) == 0);

  CHECK(fbs_inv_type_desc_get(NULL, t, &desc) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_type_desc_get(s, t, NULL) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_type_desc_get(s, 99u, &desc) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_type_desc_get(s, t, &desc) == FBS_INV_OK);
  CHECK(desc.width == 2 && desc.height == 2 && desc.max_stack == 1u && desc.tags == 0x1u);
  CHECK(desc.container_grids == 1 && desc.container_wh != NULL);
  CHECK(desc.container_wh[0] == 2 && desc.container_wh[1] == 2);
  CHECK(fbs_inv_type_count(NULL) == 0u);
  CHECK(fbs_inv_seal(NULL) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_is_sealed(NULL) == 0);

  /* inventories and grids */
  CHECK(fbs_inv_inventory_add(NULL, pack_wh, 1, &oi) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_inventory_add(s, NULL, 1, &oi) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_inventory_add(s, pack_wh, 1, NULL) == FBS_INV_E_INVALID);
  CHECK(oi == A5_U32);
  CHECK(fbs_inv_inventory_count(NULL) == 0u);
  CHECK(fbs_inv_grid_count(NULL, inv, &ow) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_grid_count(s, inv, NULL) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_grid_count(s, 99u, &ow) == FBS_INV_E_INVALID);
  CHECK(ow == A5_U16);
  CHECK(fbs_inv_grid_size(NULL, inv, 0, &ow, &oh) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_grid_size(s, inv, 0, NULL, &oh) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_grid_size(s, inv, 0, &ow, NULL) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_grid_size(s, 99u, 0, &ow, &oh) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_grid_size(s, inv, 9u, &ow, &oh) == FBS_INV_E_INVALID);
  CHECK(ow == A5_U16 && oh == A5_U16);

  /* item accessors */
  CHECK(fbs_inv_item_container(NULL, it, &oi) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_item_container(s, it, NULL) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_item_container(s, bad_handle, &oi) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_item_container(s, FBS_INV_NONE, &oi) == FBS_INV_E_INVALID);
  CHECK(oi == A5_U32);
  CHECK(fbs_inv_inventory_owner(NULL, inv, &oit) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_inventory_owner(s, inv, NULL) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_inventory_owner(s, 99u, &oit) == FBS_INV_E_INVALID);
  CHECK(oit == A5_U32);
  CHECK(fbs_inv_item_live(NULL, it) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_item_live(s, bad_handle) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_item_count(NULL) == 0u);
  CHECK(fbs_inv_item_slot(NULL, it, &os) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_item_slot(s, it, NULL) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_item_slot(s, bad_handle, &os) == FBS_INV_E_INVALID);
  CHECK(os == A5_U32);

  /* queries */
  CHECK(fbs_inv_cell_item(NULL, inv, 0, 0, 0, &oit) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_cell_item(s, inv, 0, 0, 0, NULL) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_cell_item(s, 99u, 0, 0, 0, &oit) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_cell_item(s, inv, 9u, 0, 0, &oit) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_cell_item(s, inv, 0, 4, 0, &oit) == FBS_INV_E_RANGE);
  CHECK(fbs_inv_cell_item(s, inv, 0, 0, 4, &oit) == FBS_INV_E_RANGE);
  CHECK(fbs_inv_cell_item(s, inv, 0, 3, 3, &oit) == FBS_INV_E_NOT_FOUND);
  CHECK(oit == A5_U32);

  CHECK(fbs_inv_item_place(NULL, it, &oi, &og, &ow, &oh, &orot) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_item_place(s, it, NULL, &og, &ow, &oh, &orot) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_item_place(s, it, &oi, NULL, &ow, &oh, &orot) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_item_place(s, it, &oi, &og, NULL, &oh, &orot) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_item_place(s, it, &oi, &og, &ow, NULL, &orot) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_item_place(s, it, &oi, &og, &ow, &oh, NULL) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_item_place(s, bad_handle, &oi, &og, &ow, &oh, &orot) == FBS_INV_E_INVALID);
  CHECK(oi == A5_U32 && og == A5_U32 && ow == A5_U16 && oh == A5_U16);
  CHECK(fbs_inv_item_type_of(NULL, it, &ot) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_item_type_of(s, it, NULL) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_item_stack(NULL, it, &on) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_item_stack(s, it, NULL) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_item_stack(s, bad_handle, &on) == FBS_INV_E_INVALID);
  CHECK(on == A5_U32);

  CHECK(fbs_inv_footprint(NULL, t, FBS_INV_ROT_0, &ow, &oh) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_footprint(s, t, FBS_INV_ROT_0, NULL, &oh) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_footprint(s, t, FBS_INV_ROT_0, &ow, NULL) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_footprint(s, 99u, FBS_INV_ROT_0, &ow, &oh) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_footprint(s, t, (fbs_inv_rot)7, &ow, &oh) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_footprint(s, t, (fbs_inv_rot)-1, &ow, &oh) == FBS_INV_E_INVALID);
  CHECK(ow == A5_U16 && oh == A5_U16);

  CHECK(fbs_inv_can_place(NULL, inv, 0, t, FBS_INV_ROT_0, 0, 0, FBS_INV_NONE) ==
        FBS_INV_E_INVALID);
  CHECK(fbs_inv_can_place(s, 99u, 0, t, FBS_INV_ROT_0, 0, 0, FBS_INV_NONE) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_can_place(s, inv, 9u, t, FBS_INV_ROT_0, 0, 0, FBS_INV_NONE) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_can_place(s, inv, 0, 99u, FBS_INV_ROT_0, 0, 0, FBS_INV_NONE) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_can_place(s, inv, 0, t, (fbs_inv_rot)9, 0, 0, FBS_INV_NONE) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_can_place(s, inv, 0, t, FBS_INV_ROT_0, 0, 0, bad_handle) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_can_place(s, inv, 0, t, FBS_INV_ROT_0, 0, 0, it) == FBS_INV_OK);

  CHECK(fbs_inv_find_place(NULL, inv, t, 0, FBS_INV_NONE, &og, &ow, &oh, &orot) ==
        FBS_INV_E_INVALID);
  CHECK(fbs_inv_find_place(s, inv, t, 0, FBS_INV_NONE, NULL, &ow, &oh, &orot) ==
        FBS_INV_E_INVALID);
  CHECK(fbs_inv_find_place(s, inv, t, 0, FBS_INV_NONE, &og, NULL, &oh, &orot) ==
        FBS_INV_E_INVALID);
  CHECK(fbs_inv_find_place(s, inv, t, 0, FBS_INV_NONE, &og, &ow, NULL, &orot) ==
        FBS_INV_E_INVALID);
  CHECK(fbs_inv_find_place(s, inv, t, 0, FBS_INV_NONE, &og, &ow, &oh, NULL) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_find_place(s, 99u, t, 0, FBS_INV_NONE, &og, &ow, &oh, &orot) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_find_place(s, inv, 99u, 0, FBS_INV_NONE, &og, &ow, &oh, &orot) ==
        FBS_INV_E_INVALID);
  CHECK(fbs_inv_find_place(s, inv, t, 0, bad_handle, &og, &ow, &oh, &orot) == FBS_INV_E_INVALID);
  CHECK(og == A5_U32 && ow == A5_U16 && oh == A5_U16);

  {
    fbs_inv_item listed[4];
    size_t count = (size_t)0xA5A5A5A5u;
    CHECK(fbs_inv_list_items(NULL, inv, listed, 4u, &count) == FBS_INV_E_INVALID);
    CHECK(fbs_inv_list_items(s, inv, listed, 4u, NULL) == FBS_INV_E_INVALID);
    CHECK(fbs_inv_list_items(s, inv, NULL, 4u, &count) == FBS_INV_E_INVALID);
    CHECK(fbs_inv_list_items(s, 99u, listed, 4u, &count) == FBS_INV_E_INVALID);
    CHECK(count == (size_t)0xA5A5A5A5u);
    memset(listed, 0xA5, sizeof listed);
    CHECK(fbs_inv_list_items(s, inv, NULL, 0u, &count) == FBS_INV_E_TRUNCATED);
    CHECK(count == 1u);
    CHECK(untouched(listed, sizeof listed, 0xA5));
    CHECK(fbs_inv_list_items(s, inv, listed, 4u, &count) == FBS_INV_OK);
    CHECK(count == 1u && listed[0] == it);
  }

  CHECK(fbs_inv_count_of(NULL, inv, t, 0, &o64) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_count_of(s, inv, t, 0, NULL) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_count_of(s, 99u, t, 0, &o64) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_count_of(s, inv, 99u, 0, &o64) == FBS_INV_E_INVALID);
  CHECK(o64 == 0xA5A5A5A5A5A5A5A5u);
  CHECK(fbs_inv_total_units(NULL) == 0u);

  /* transactions */
  CHECK(fbs_inv_txn_begin(NULL) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_txn_commit(NULL) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_txn_abort(NULL) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_txn_active(NULL) == 0);

  /* mutators, inside a transaction so that E_TXN is not what answers */
  CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
  CHECK(fbs_inv_spawn_at(NULL, inv, 0, t, 1, FBS_INV_ROT_0, 2, 2, &oit) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_spawn_at(s, inv, 0, t, 1, FBS_INV_ROT_0, 2, 2, NULL) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_spawn_at(s, 99u, 0, t, 1, FBS_INV_ROT_0, 2, 2, &oit) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_spawn_at(s, inv, 0, 99u, 1, FBS_INV_ROT_0, 2, 2, &oit) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_spawn_at(s, inv, 0, t, 0, FBS_INV_ROT_0, 2, 2, &oit) == FBS_INV_E_RANGE);
  CHECK(fbs_inv_spawn_at(s, inv, 0, t, 4, FBS_INV_ROT_0, 2, 2, &oit) == FBS_INV_E_RANGE);
  CHECK(fbs_inv_spawn(NULL, inv, t, 1, 0, &oit) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_spawn(s, inv, t, 1, 0, NULL) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_spawn(s, 99u, t, 1, 0, &oit) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_spawn(s, inv, 99u, 1, 0, &oit) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_spawn(s, inv, t, 9, 0, &oit) == FBS_INV_E_RANGE);
  CHECK(oit == A5_U32);
  CHECK(fbs_inv_destroy(NULL, it) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_destroy(s, bad_handle) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_move_to(NULL, it, inv, 0, FBS_INV_ROT_0, 2, 2) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_move_to(s, bad_handle, inv, 0, FBS_INV_ROT_0, 2, 2) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_move_to(s, it, 99u, 0, FBS_INV_ROT_0, 2, 2) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_move_to(s, it, inv, 9u, FBS_INV_ROT_0, 2, 2) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_move_auto(NULL, it, inv, 0) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_move_auto(s, bad_handle, inv, 0) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_move_auto(s, it, 99u, 0) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_rotate(NULL, it, FBS_INV_ROT_0) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_rotate(s, bad_handle, FBS_INV_ROT_0) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_rotate(s, it, (fbs_inv_rot)5) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_stack_merge(NULL, it, it, 0, &on) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_stack_merge(s, it, it, 0, NULL) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_stack_merge(s, bad_handle, it, 0, &on) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_stack_merge(s, it, bad_handle, 0, &on) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_stack_split_to(NULL, it, inv, 0, FBS_INV_ROT_0, 2, 2, 1, &oit) ==
        FBS_INV_E_INVALID);
  CHECK(fbs_inv_stack_split_to(s, it, inv, 0, FBS_INV_ROT_0, 2, 2, 1, NULL) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_stack_split_to(s, bad_handle, inv, 0, FBS_INV_ROT_0, 2, 2, 1, &oit) ==
        FBS_INV_E_INVALID);
  CHECK(fbs_inv_stack_headroom(NULL, it, &on) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_stack_headroom(s, it, NULL) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_stack_headroom(s, bad_handle, &on) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_equip(NULL, sl, it) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_equip(s, 99u, it) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_equip(s, sl, bad_handle) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_unequip_to(NULL, sl, inv, 0) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_unequip_to(s, 99u, inv, 0) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_unequip_to(s, sl, 99u, 0) == FBS_INV_E_INVALID);
  CHECK(oit == A5_U32 && on == A5_U32);
  CHECK(fbs_inv_txn_abort(s) == FBS_INV_OK);

  /* equipment slots */
  CHECK(fbs_inv_slot_add(NULL, "k", 1u, 0u, &os) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_slot_add(s, "k", 1u, 0u, &os) == FBS_INV_E_TXN); /* a mutator */
  CHECK(os == A5_U32);
  CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
  CHECK(fbs_inv_slot_add(s, NULL, 1u, 0u, &os) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_slot_add(s, "k", 1u, 0u, NULL) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_slot_add(s, "k", 0u, 0u, &os) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_slot_add(s, "k", 256u, 0u, &os) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_slot_add(s, "hand", 4u, 0u, &os) == FBS_INV_E_EXISTS);
  CHECK(fbs_inv_txn_abort(s) == FBS_INV_OK);
  CHECK(os == A5_U32);
  CHECK(fbs_inv_slot_find(NULL, "hand", 4u, &os) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_slot_find(s, NULL, 4u, &os) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_slot_find(s, "hand", 4u, NULL) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_slot_find(s, "nope", 4u, &os) == FBS_INV_E_NOT_FOUND);
  CHECK(os == A5_U32);
  CHECK(fbs_inv_slot_find(s, "hand", 4u, &os) == FBS_INV_OK && os == sl);
  CHECK(fbs_inv_slot_item(NULL, sl, &oit) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_slot_item(s, sl, NULL) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_slot_item(s, 99u, &oit) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_slot_item(s, sl, &oit) == FBS_INV_E_NOT_FOUND);
  CHECK(oit == A5_U32);
  CHECK(fbs_inv_slot_accepts(NULL, sl, t) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_slot_accepts(s, 99u, t) == FBS_INV_E_INVALID);
  CHECK(fbs_inv_slot_accepts(s, sl, 99u) == FBS_INV_E_INVALID);

  /* serialization */
  {
    size_t got = (size_t)0xA5A5A5A5u;
    unsigned char buf[8];
    fbs_inv_store *out = (fbs_inv_store *)0x1;
    CHECK(fbs_inv_serialize(NULL, buf, sizeof buf, &got) == FBS_INV_E_INVALID);
    CHECK(fbs_inv_serialize(s, buf, sizeof buf, NULL) == FBS_INV_E_INVALID);
    CHECK(fbs_inv_serialize(s, NULL, 8u, &got) == FBS_INV_E_INVALID);
    CHECK(got == (size_t)0xA5A5A5A5u);
    CHECK(fbs_inv_deserialize(NULL, 48u, NULL, NULL, &out) == FBS_INV_E_INVALID);
    CHECK(fbs_inv_deserialize(buf, 48u, NULL, NULL, NULL) == FBS_INV_E_INVALID);
    CHECK(out == (fbs_inv_store *)0x1);
  }

  fbs_inv_store_destroy(s);
}

static void test_config_validation(void) {
  fbs_inv_config cfg;
  fbs_inv_store *s = (fbs_inv_store *)0x1;
  unsigned i;
  for (i = 0; i < 19u; ++i) {
    cfg = fbs_inv_config_default();
    switch (i) {
      case 0: cfg.max_types = 0u; break;
      case 1: cfg.max_types = 4097u; break;
      case 2: cfg.max_inventories = 0u; break;
      case 3: cfg.max_inventories = 4097u; break;
      case 4: cfg.max_grids = 0u; break;
      case 5: cfg.max_grids = 16385u; break;
      case 6: cfg.max_cells = 0u; break;
      case 7: cfg.max_cells = (1u << 22) + 1u; break;
      case 8: cfg.max_items = 0u; break;
      case 9: cfg.max_items = 65536u; break;
      case 10: cfg.max_slots = 1025u; break;
      case 11: cfg.max_key_bytes = 0u; break;
      case 12: cfg.max_key_bytes = (1u << 22) + 1u; break;
      case 13: cfg.max_txn_ops = 7u; break;
      case 14: cfg.max_txn_ops = 65537u; break;
      case 15: cfg.max_grid_dim = 0u; break;
      case 16: cfg.max_grid_dim = 1025u; break;
      case 17: cfg.max_types = 0u; cfg.max_items = 0u; break;
      default: cfg.max_cells = 0u; cfg.max_grids = 0u; break;
    }
    CHECK(fbs_inv_store_create(&cfg, NULL, &s) == FBS_INV_E_INVALID);
    CHECK(s == (fbs_inv_store *)0x1);
  }
  /* the extremes that are legal */
  cfg = fbs_inv_config_default();
  cfg.max_slots = 0u;
  cfg.max_txn_ops = 8u;
  cfg.max_grid_dim = 1024u;
  s = NULL;
  CHECK(fbs_inv_store_create(&cfg, NULL, &s) == FBS_INV_OK);
  fbs_inv_store_destroy(s);
}

/* ------------------------------------------------------------------------- */
/* T-12 — 100k random operations against an independent reference model       */
/* ------------------------------------------------------------------------- */
/* The model keeps its own item table, inventory table, occupancy arrays,     */
/* generation counter and floor, slot-reuse rule and container-inventory      */
/* recycling rule, written from the specification rather than from            */
/* src/inventory.c, and decides independently whether each call should        */
/* succeed. Containers are in the mix (INV-10), so nesting, E_CYCLE,          */
/* recursive destroy and inventory recycling are fuzzed, not only fixed.      */

#define FZ_OPS 100000u
#define FZ_FIXPOINT_EVERY 1u /* ser/deser/ser is checked after every operation */
#define FZ_TXN_LEN 64u

#define FZ_TYPES 8u
#define FZ_ROOTS 3u
#define FZ_MAX_INVS 12u
#define FZ_MAX_GRIDS 22u
#define FZ_MAX_CELLS 101u
#define FZ_MAXG 2u
#define FZ_DIM 6u
#define FZ_ITEMS 48u
#define FZ_SLOTS 2u
#define FZ_NIL 0xFFFFu

/* Six ordinary types and two containers. A container type must have
   max_stack == 1 (INV-1), which the store now enforces. */
static const uint16_t fz_tw[FZ_TYPES] = {1u, 2u, 1u, 2u, 3u, 1u, 1u, 2u};
static const uint16_t fz_th[FZ_TYPES] = {1u, 1u, 3u, 2u, 2u, 2u, 1u, 1u};
static const uint32_t fz_cap[FZ_TYPES] = {10u, 1u, 4u, 1u, 6u, 3u, 1u, 1u};
static const uint64_t fz_tags[FZ_TYPES] = {1u, 2u, 4u, 8u, 3u, 16u, 32u, 64u};
static const unsigned fz_cng[FZ_TYPES] = {0u, 0u, 0u, 0u, 0u, 0u, 1u, 2u};
static const uint16_t fz_cwh[FZ_TYPES][FZ_MAXG * 2u] = {
    {0u, 0u, 0u, 0u}, {0u, 0u, 0u, 0u}, {0u, 0u, 0u, 0u}, {0u, 0u, 0u, 0u},
    {0u, 0u, 0u, 0u}, {0u, 0u, 0u, 0u},
    {2u, 2u, 0u, 0u},  /* t6: one 2x2 grid                */
    {2u, 1u, 1u, 2u}}; /* t7: a 2x1 grid and a 1x2 grid   */
static const uint64_t fz_mask[FZ_SLOTS] = {0u, 5u};

static const unsigned fz_root_ng[FZ_ROOTS] = {1u, 2u, 1u};
static const unsigned fz_root_gw[FZ_ROOTS][FZ_MAXG] = {{6u, 0u}, {4u, 3u}, {5u, 0u}};
static const unsigned fz_root_gh[FZ_ROOTS][FZ_MAXG] = {{5u, 0u}, {4u, 3u}, {2u, 0u}};

typedef struct {
  unsigned char state; /* 0 tombstone, 1 in a grid, 2 in a slot */
  uint32_t type, gen, stack;
  unsigned inv, grid, x, y, rot, slot, container;
} fz_item;

typedef struct {
  unsigned ng;
  unsigned gw[FZ_MAXG];
  unsigned gh[FZ_MAXG];
  uint32_t owner; /* handle of the owning container, or FBS_INV_NONE */
} fz_invrec;

typedef struct {
  fz_item items[FZ_ITEMS];
  unsigned item_count;
  uint32_t next_gen;  /* rewound by abort, exactly like the store's */
  uint32_t gen_floor; /* never rewound (INV-2) */
  unsigned slot_item[FZ_SLOTS];
  fz_invrec invs[FZ_MAX_INVS];
  unsigned inv_count, grid_count, cell_top;
  unsigned occ[FZ_MAX_INVS][FZ_MAXG][FZ_DIM][FZ_DIM];
} fz_model;

static void fz_fp(uint32_t t, unsigned rot, unsigned *fw, unsigned *fh) {
  *fw = rot ? fz_th[t] : fz_tw[t];
  *fh = rot ? fz_tw[t] : fz_th[t];
}

static void fz_clear_grid(fz_model *m, unsigned inv, unsigned g) {
  unsigned x, y;
  for (y = 0; y < FZ_DIM; ++y)
    for (x = 0; x < FZ_DIM; ++x) m->occ[inv][g][y][x] = FZ_NIL;
}

static void fz_init(fz_model *m) {
  unsigned i, g, k;
  memset(m, 0, sizeof *m);
  m->item_count = 0u;
  m->next_gen = 1u;
  m->gen_floor = 1u;
  for (i = 0; i < FZ_SLOTS; ++i) m->slot_item[i] = FZ_NIL;
  for (i = 0; i < FZ_MAX_INVS; ++i) {
    m->invs[i].owner = FBS_INV_NONE;
    for (g = 0; g < FZ_MAXG; ++g) fz_clear_grid(m, i, g);
  }
  for (i = 0; i < FZ_ROOTS; ++i) {
    m->invs[i].ng = fz_root_ng[i];
    for (k = 0; k < fz_root_ng[i]; ++k) {
      m->invs[i].gw[k] = fz_root_gw[i][k];
      m->invs[i].gh[k] = fz_root_gh[i][k];
      m->cell_top += fz_root_gw[i][k] * fz_root_gh[i][k];
    }
    m->grid_count += fz_root_ng[i];
  }
  m->inv_count = FZ_ROOTS;
}

static uint32_t fz_handle(const fz_model *m, unsigned idx) {
  return (m->items[idx].gen << 16) | (idx & 0xFFFFu);
}

static uint32_t fz_take_gen(fz_model *m) {
  uint32_t g = m->next_gen > m->gen_floor ? m->next_gen : m->gen_floor;
  m->next_gen = (g >= 0xFFFEu) ? 1u : g + 1u;
  m->gen_floor = m->next_gen;
  return g;
}

static int fz_live_handle(const fz_model *m, uint32_t h) {
  unsigned idx;
  if (h == FBS_INV_NONE) return 0;
  idx = h & 0xFFFFu;
  if (idx >= m->item_count) return 0;
  if (m->items[idx].gen != ((h >> 16) & 0xFFFFu)) return 0;
  return m->items[idx].state != 0u;
}

static int fz_detached(const fz_model *m, unsigned inv) {
  return m->invs[inv].owner != FBS_INV_NONE && !fz_live_handle(m, m->invs[inv].owner);
}

static int fz_inv_empty(const fz_model *m, unsigned inv) {
  unsigned g, x, y;
  for (g = 0; g < m->invs[inv].ng; ++g)
    for (y = 0; y < m->invs[inv].gh[g]; ++y)
      for (x = 0; x < m->invs[inv].gw[g]; ++x)
        if (m->occ[inv][g][y][x] != FZ_NIL) return 0;
  return 1;
}

static int fz_free_rect(const fz_model *m, unsigned inv, unsigned g, unsigned x, unsigned y,
                        unsigned fw, unsigned fh, unsigned ignore) {
  unsigned dx, dy;
  if (fw > m->invs[inv].gw[g] || fh > m->invs[inv].gh[g]) return 0;
  if (x > m->invs[inv].gw[g] - fw || y > m->invs[inv].gh[g] - fh) return 0;
  for (dy = 0; dy < fh; ++dy)
    for (dx = 0; dx < fw; ++dx) {
      unsigned v = m->occ[inv][g][y + dy][x + dx];
      if (v != FZ_NIL && v != ignore) return 0;
    }
  return 1;
}

static int fz_find(const fz_model *m, unsigned inv, uint32_t t, int try_rotate, unsigned ignore,
                   unsigned *og, unsigned *ox, unsigned *oy, unsigned *orot) {
  unsigned g, r, x, y, fw, fh;
  for (g = 0; g < m->invs[inv].ng; ++g)
    for (r = 0; r < (try_rotate ? 2u : 1u); ++r) {
      fz_fp(t, r, &fw, &fh);
      if (fw > m->invs[inv].gw[g] || fh > m->invs[inv].gh[g]) continue;
      for (y = 0; y + fh <= m->invs[inv].gh[g]; ++y)
        for (x = 0; x + fw <= m->invs[inv].gw[g]; ++x)
          if (fz_free_rect(m, inv, g, x, y, fw, fh, ignore)) {
            *og = g;
            *ox = x;
            *oy = y;
            *orot = r;
            return 1;
          }
    }
  return 0;
}

static void fz_stamp(fz_model *m, unsigned inv, unsigned g, unsigned x, unsigned y, unsigned fw,
                     unsigned fh, unsigned val) {
  unsigned dx, dy;
  for (dy = 0; dy < fh; ++dy)
    for (dx = 0; dx < fw; ++dx) m->occ[inv][g][y + dy][x + dx] = val;
}

static unsigned fz_pick(const fz_model *m) {
  unsigned i;
  for (i = 0; i < m->item_count; ++i)
    if (m->items[i].state == 0u) return i;
  if (m->item_count >= FZ_ITEMS) return FZ_NIL;
  return m->item_count;
}

/* The container-inventory policy: reuse the lowest-id detached inventory whose
 * shape matches exactly and whose cells are all free, else carve a new one.
 * With apply == 0 it only answers whether the attach could happen. */
static unsigned fz_attach(fz_model *m, uint32_t t, uint32_t handle, unsigned dest, int apply) {
  unsigned ng = fz_cng[t];
  unsigned i, k, cells = 0u;
  for (k = 0; k < ng; ++k)
    cells += (unsigned)fz_cwh[t][k * 2u] * (unsigned)fz_cwh[t][k * 2u + 1u];
  for (i = 0; i < m->inv_count; ++i) {
    int shape = 1;
    if (i == dest) continue; /* never the shell the item is standing in */
    if (!fz_detached(m, i)) continue;
    if (m->invs[i].ng != ng) continue;
    for (k = 0; k < ng; ++k)
      if (m->invs[i].gw[k] != fz_cwh[t][k * 2u] || m->invs[i].gh[k] != fz_cwh[t][k * 2u + 1u])
        shape = 0;
    if (!shape) continue;
    if (!fz_inv_empty(m, i)) continue;
    if (apply) m->invs[i].owner = handle;
    return i;
  }
  if (m->inv_count >= FZ_MAX_INVS) return FZ_NIL;
  if (ng > FZ_MAX_GRIDS - m->grid_count) return FZ_NIL;
  if (cells > FZ_MAX_CELLS - m->cell_top) return FZ_NIL;
  if (!apply) return m->inv_count;
  {
    unsigned id = m->inv_count++;
    m->invs[id].ng = ng;
    for (k = 0; k < ng; ++k) {
      m->invs[id].gw[k] = fz_cwh[t][k * 2u];
      m->invs[id].gh[k] = fz_cwh[t][k * 2u + 1u];
      fz_clear_grid(m, id, k);
    }
    m->invs[id].owner = handle;
    m->grid_count += ng;
    m->cell_top += cells;
    return id;
  }
}

/* Is `inv` the item's own container, or nested inside it at any depth? */
static int fz_cycle(const fz_model *m, unsigned inv, unsigned idx) {
  unsigned cur = inv, guard = 0u;
  if (m->items[idx].container != FZ_NIL && inv == m->items[idx].container) return 1;
  while (guard++ <= FZ_MAX_INVS) {
    uint32_t owner = m->invs[cur].owner;
    unsigned oidx;
    if (owner == FBS_INV_NONE || !fz_live_handle(m, owner)) return 0;
    oidx = owner & 0xFFFFu;
    if (oidx == idx) return 1;
    if (m->items[oidx].state != 1u) return 0; /* equipped: the chain ends */
    cur = m->items[oidx].inv;
  }
  return 0;
}

static void fz_unplace(fz_model *m, unsigned idx) {
  fz_item *r = &m->items[idx];
  unsigned fw, fh;
  if (r->state == 1u) {
    fz_fp(r->type, r->rot, &fw, &fh);
    fz_stamp(m, r->inv, r->grid, r->x, r->y, fw, fh, FZ_NIL);
  } else if (r->state == 2u) {
    m->slot_item[r->slot] = FZ_NIL;
  }
}

static void fz_kill_one(fz_model *m, unsigned idx) {
  fz_item *r = &m->items[idx];
  fz_unplace(m, idx);
  r->state = 0u;
  r->type = FBS_INV_NONE;
  r->stack = 0u;
  r->x = 0u;
  r->y = 0u;
  r->rot = 0u;
  r->slot = FZ_NIL;
  r->container = FZ_NIL;
}

/* Destroys `idx` and, recursively, everything inside it. */
static void fz_destroy(fz_model *m, unsigned idx) {
  unsigned queue[FZ_ITEMS];
  unsigned head = 0u, n = 0u, i;
  queue[n++] = idx;
  while (head < n) {
    unsigned cur = queue[head++];
    unsigned inside = m->items[cur].container;
    if (inside == FZ_NIL) continue;
    for (i = 0; i < m->item_count; ++i)
      if (m->items[i].state == 1u && m->items[i].inv == inside && n < FZ_ITEMS) queue[n++] = i;
  }
  for (i = 0; i < n; ++i) fz_kill_one(m, queue[i]);
}

/* Everything the model claims, checked through the public API. Returns 0 when
 * the store agrees, and prints the first disagreement otherwise. */
static int fz_compare(const fz_model *m, const fbs_inv_store *s, unsigned op) {
  unsigned i, g, x, y;
  uint64_t units = 0u;
  if (fbs_inv_item_count(s) != m->item_count) {
    printf("FAIL fuzz op %u: item_count %u != %u\n", op, fbs_inv_item_count(s), m->item_count);
    return 1;
  }
  if (fbs_inv_inventory_count(s) != m->inv_count) {
    printf("FAIL fuzz op %u: inventory_count %u != %u\n", op, fbs_inv_inventory_count(s),
           m->inv_count);
    return 1;
  }
  for (i = 0; i < m->item_count; ++i) {
    const fz_item *r = &m->items[i];
    fbs_inv_item h = fz_handle(m, i);
    fbs_inv_inventory owned = FBS_INV_NONE;
    if (r->state == 0u) {
      if (fbs_inv_item_live(s, h) != 0) {
        printf("FAIL fuzz op %u: item %u should be a tombstone\n", op, i);
        return 1;
      }
      continue;
    }
    units += r->stack;
    if (fbs_inv_item_live(s, h) != 1) {
      printf("FAIL fuzz op %u: item %u should be live\n", op, i);
      return 1;
    }
    {
      fbs_inv_type ty = FBS_INV_NONE;
      uint32_t st = 0;
      if (fbs_inv_item_type_of(s, h, &ty) != FBS_INV_OK || ty != r->type) {
        printf("FAIL fuzz op %u: item %u type\n", op, i);
        return 1;
      }
      if (fbs_inv_item_stack(s, h, &st) != FBS_INV_OK || st != r->stack || st < 1u ||
          st > fz_cap[r->type]) {
        printf("FAIL fuzz op %u: item %u stack\n", op, i);
        return 1;
      }
    }
    if (r->container == FZ_NIL) {
      if (fbs_inv_item_container(s, h, &owned) != FBS_INV_E_NOT_FOUND) {
        printf("FAIL fuzz op %u: item %u should own no inventory\n", op, i);
        return 1;
      }
    } else if (fbs_inv_item_container(s, h, &owned) != FBS_INV_OK || owned != r->container) {
      printf("FAIL fuzz op %u: item %u container link\n", op, i);
      return 1;
    }
    if (r->state == 2u) {
      fbs_inv_slot sl = FBS_INV_NONE;
      fbs_inv_inventory pi = FBS_INV_NONE;
      fbs_inv_grid pg = FBS_INV_NONE;
      uint16_t px = 0, py = 0;
      fbs_inv_rot pr = FBS_INV_ROT_0;
      if (fbs_inv_item_slot(s, h, &sl) != FBS_INV_OK || sl != r->slot) {
        printf("FAIL fuzz op %u: item %u slot\n", op, i);
        return 1;
      }
      if (fbs_inv_item_place(s, h, &pi, &pg, &px, &py, &pr) != FBS_INV_E_NOT_FOUND) {
        printf("FAIL fuzz op %u: equipped item %u still has an anchor\n", op, i);
        return 1;
      }
    } else {
      fbs_inv_inventory pi = FBS_INV_NONE;
      fbs_inv_grid pg = FBS_INV_NONE;
      uint16_t px = 0, py = 0;
      fbs_inv_rot pr = FBS_INV_ROT_0;
      unsigned fw, fh;
      if (fbs_inv_item_place(s, h, &pi, &pg, &px, &py, &pr) != FBS_INV_OK) {
        printf("FAIL fuzz op %u: item %u has no place\n", op, i);
        return 1;
      }
      if (pi != r->inv || pg != r->grid || px != r->x || py != r->y || (unsigned)pr != r->rot) {
        printf("FAIL fuzz op %u: item %u place\n", op, i);
        return 1;
      }
      fz_fp(r->type, r->rot, &fw, &fh);
      if (px + fw > m->invs[pi].gw[pg] || py + fh > m->invs[pi].gh[pg]) {
        printf("FAIL fuzz op %u: item %u is out of bounds\n", op, i);
        return 1;
      }
    }
  }
  for (i = 0; i < FZ_SLOTS; ++i) {
    fbs_inv_item held = FBS_INV_NONE;
    fbs_inv_status st = fbs_inv_slot_item(s, i, &held);
    if (m->slot_item[i] == FZ_NIL) {
      if (st != FBS_INV_E_NOT_FOUND) {
        printf("FAIL fuzz op %u: slot %u should be empty\n", op, i);
        return 1;
      }
    } else if (st != FBS_INV_OK || held != fz_handle(m, m->slot_item[i])) {
      printf("FAIL fuzz op %u: slot %u occupant\n", op, i);
      return 1;
    }
  }
  for (i = 0; i < m->inv_count; ++i) {
    fbs_inv_item owner = FBS_INV_NONE;
    fbs_inv_status st = fbs_inv_inventory_owner(s, i, &owner);
    uint16_t gc = 0;
    if (m->invs[i].owner == FBS_INV_NONE) {
      if (st != FBS_INV_E_NOT_FOUND) {
        printf("FAIL fuzz op %u: inventory %u should be a root\n", op, i);
        return 1;
      }
    } else if (st != FBS_INV_OK || owner != m->invs[i].owner) {
      printf("FAIL fuzz op %u: inventory %u owner\n", op, i);
      return 1;
    }
    if (fbs_inv_grid_count(s, i, &gc) != FBS_INV_OK || gc != m->invs[i].ng) {
      printf("FAIL fuzz op %u: inventory %u grid count\n", op, i);
      return 1;
    }
    for (g = 0; g < m->invs[i].ng; ++g) {
      uint16_t gw = 0, gh = 0;
      if (fbs_inv_grid_size(s, i, g, &gw, &gh) != FBS_INV_OK || gw != m->invs[i].gw[g] ||
          gh != m->invs[i].gh[g]) {
        printf("FAIL fuzz op %u: inventory %u grid %u size\n", op, i, g);
        return 1;
      }
      for (y = 0; y < m->invs[i].gh[g]; ++y)
        for (x = 0; x < m->invs[i].gw[g]; ++x) {
          fbs_inv_item got = FBS_INV_NONE;
          fbs_inv_status cs = fbs_inv_cell_item(s, i, g, (uint16_t)x, (uint16_t)y, &got);
          unsigned want = m->occ[i][g][y][x];
          if (want == FZ_NIL) {
            if (cs != FBS_INV_E_NOT_FOUND) {
              printf("FAIL fuzz op %u: cell %u/%u/%u,%u should be free\n", op, i, g, x, y);
              return 1;
            }
          } else if (cs != FBS_INV_OK || got != fz_handle(m, want)) {
            printf("FAIL fuzz op %u: cell %u/%u/%u,%u occupant\n", op, i, g, x, y);
            return 1;
          }
        }
    }
  }
  if (fbs_inv_total_units(s) != units) {
    printf("FAIL fuzz op %u: total units\n", op);
    return 1;
  }
  return 0;
}

static void test_t12_fuzz(void) {
  fbs_inv_config cfg = fbs_inv_config_default();
  fbs_inv_store *s;
  fz_model m, snap;
  rng r;
  unsigned op, in_txn = 0u, txn_left = 0u, applied = 0u, refused = 0u, ghost_snap = 0u;
  unsigned containers = 0u, cycles = 0u, nested = 0u;
  fbs_inv_item ghosts[8];
  unsigned ghost_n = 0u;
  unsigned char *blob = NULL, *blob2 = NULL;
  size_t bl = 0, bl2 = 0;
  unsigned i;

  cfg.max_types = FZ_TYPES;
  cfg.max_inventories = FZ_MAX_INVS;
  cfg.max_grids = FZ_MAX_GRIDS;
  cfg.max_cells = FZ_MAX_CELLS;
  cfg.max_items = FZ_ITEMS;
  cfg.max_slots = FZ_SLOTS;
  cfg.max_key_bytes = 128u;
  cfg.max_txn_ops = 2048u;
  s = make_store(&cfg);
  for (i = 0; i < FZ_TYPES; ++i) {
    char key[4];
    key[0] = 't';
    key[1] = (char)('0' + (int)i);
    key[2] = '\0';
    (void)add_type(s, key, fz_tw[i], fz_th[i], fz_cap[i], fz_tags[i],
                   fz_cng[i] ? fz_cwh[i] : NULL, (uint16_t)fz_cng[i]);
  }
  CHECK(fbs_inv_seal(s) == FBS_INV_OK);
  for (i = 0; i < FZ_ROOTS; ++i) {
    uint16_t wh[FZ_MAXG * 2u];
    unsigned k;
    for (k = 0; k < fz_root_ng[i]; ++k) {
      wh[k * 2u] = (uint16_t)fz_root_gw[i][k];
      wh[k * 2u + 1u] = (uint16_t)fz_root_gh[i][k];
    }
    CHECK(add_inv(s, wh, (uint16_t)fz_root_ng[i]) == i);
  }
  (void)add_slot(s, "slot0", fz_mask[0]);
  (void)add_slot(s, "slot1", fz_mask[1]);

  fz_init(&m);
  for (i = 0; i < 8u; ++i) ghosts[i] = FBS_INV_NONE;
  rng_seed(&r, 0x1B4D5EEDu);

  for (op = 0; op < FZ_OPS; ++op) {
    unsigned kind;
    fbs_inv_status st = FBS_INV_OK;
    int expect_ok = 0;

    if (!in_txn) {
      CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
      snap = m;
      ghost_snap = ghost_n;
      in_txn = 1u;
      txn_left = 1u + rng_below(&r, FZ_TXN_LEN);
    }

    kind = rng_below(&r, 20u);
    if (kind < 5u) { /* spawn at an explicit anchor */
      unsigned inv = rng_below(&r, m.inv_count);
      unsigned g = rng_below(&r, m.invs[inv].ng);
      uint32_t t = rng_below(&r, FZ_TYPES);
      unsigned x = rng_below(&r, FZ_DIM);
      unsigned y = rng_below(&r, FZ_DIM);
      unsigned rot = rng_below(&r, 2u);
      uint32_t stack = 1u + rng_below(&r, fz_cap[t] + 1u); /* sometimes over the cap */
      unsigned idx = fz_pick(&m);
      unsigned fw, fh;
      fbs_inv_item made = FBS_INV_NONE;
      fz_fp(t, rot, &fw, &fh);
      expect_ok = stack <= fz_cap[t] && idx != FZ_NIL &&
                  fz_free_rect(&m, inv, g, x, y, fw, fh, FZ_NIL) &&
                  (fz_cng[t] == 0u || fz_attach(&m, t, 0u, inv, 0) != FZ_NIL);
      st = fbs_inv_spawn_at(s, inv, g, t, stack, rot ? FBS_INV_ROT_90 : FBS_INV_ROT_0, (uint16_t)x,
                            (uint16_t)y, &made);
      if (st == FBS_INV_OK) {
        fz_item *w = &m.items[idx];
        uint32_t gen = fz_take_gen(&m);
        w->state = 1u;
        w->type = t;
        w->gen = gen;
        w->stack = stack;
        w->inv = inv;
        w->grid = g;
        w->x = x;
        w->y = y;
        w->rot = rot;
        w->slot = FZ_NIL;
        w->container = FZ_NIL;
        if (idx == m.item_count) m.item_count += 1u;
        if (fz_cng[t]) {
          w->container = fz_attach(&m, t, fz_handle(&m, idx), inv, 1);
          ++containers;
        }
        fz_stamp(&m, inv, g, x, y, fw, fh, idx);
        if (made != fz_handle(&m, idx)) {
          printf("FAIL fuzz op %u: spawn handle\n", op);
          CHECK(0);
          break;
        }
        if (m.invs[inv].owner != FBS_INV_NONE) ++nested;
      }
    } else if (kind < 8u) { /* spawn, auto placed */
      unsigned inv = rng_below(&r, m.inv_count);
      uint32_t t = rng_below(&r, FZ_TYPES);
      int rotate = (int)rng_below(&r, 2u);
      uint32_t stack = 1u + rng_below(&r, fz_cap[t]);
      unsigned idx = fz_pick(&m);
      unsigned g = 0, x = 0, y = 0, rot = 0, fw, fh;
      fbs_inv_item made = FBS_INV_NONE;
      expect_ok = idx != FZ_NIL && fz_find(&m, inv, t, rotate, FZ_NIL, &g, &x, &y, &rot) &&
                  (fz_cng[t] == 0u || fz_attach(&m, t, 0u, inv, 0) != FZ_NIL);
      st = fbs_inv_spawn(s, inv, t, stack, rotate, &made);
      if (st == FBS_INV_OK) {
        fz_item *w = &m.items[idx];
        uint32_t gen = fz_take_gen(&m);
        fz_fp(t, rot, &fw, &fh);
        w->state = 1u;
        w->type = t;
        w->gen = gen;
        w->stack = stack;
        w->inv = inv;
        w->grid = g;
        w->x = x;
        w->y = y;
        w->rot = rot;
        w->slot = FZ_NIL;
        w->container = FZ_NIL;
        if (idx == m.item_count) m.item_count += 1u;
        if (fz_cng[t]) {
          w->container = fz_attach(&m, t, fz_handle(&m, idx), inv, 1);
          ++containers;
        }
        fz_stamp(&m, inv, g, x, y, fw, fh, idx);
      }
    } else if (kind < 10u) { /* destroy */
      unsigned idx = m.item_count ? rng_below(&r, m.item_count) : FZ_NIL;
      unsigned ghost_pick = rng_below(&r, 8u);
      fbs_inv_item h = (idx == FZ_NIL) ? FBS_INV_NONE : fz_handle(&m, idx);
      if (ghost_n && ghost_pick == 0u) { /* sometimes a stale handle */
        h = ghosts[rng_below(&r, ghost_n)];
        idx = FZ_NIL;
        expect_ok = 0;
      } else {
        expect_ok = idx != FZ_NIL && m.items[idx].state != 0u;
      }
      st = fbs_inv_destroy(s, h);
      if (st == FBS_INV_OK) {
        if (ghost_n < 8u) ghosts[ghost_n++] = h;
        if (idx != FZ_NIL) fz_destroy(&m, idx);
      }
    } else if (kind < 14u) { /* move to an explicit anchor */
      unsigned idx = m.item_count ? rng_below(&r, m.item_count) : FZ_NIL;
      unsigned inv = rng_below(&r, m.inv_count);
      unsigned g = rng_below(&r, m.invs[inv].ng);
      unsigned x = rng_below(&r, FZ_DIM);
      unsigned y = rng_below(&r, FZ_DIM);
      unsigned rot = rng_below(&r, 2u);
      unsigned fw, fh;
      fbs_inv_item h = (idx == FZ_NIL) ? FBS_INV_NONE : fz_handle(&m, idx);
      int live = idx != FZ_NIL && m.items[idx].state != 0u;
      if (live) {
        fz_fp(m.items[idx].type, rot, &fw, &fh);
        expect_ok = !fz_cycle(&m, inv, idx) && fz_free_rect(&m, inv, g, x, y, fw, fh, idx);
        if (live && fz_cycle(&m, inv, idx)) ++cycles;
      }
      st = fbs_inv_move_to(s, h, inv, g, rot ? FBS_INV_ROT_90 : FBS_INV_ROT_0, (uint16_t)x,
                           (uint16_t)y);
      if (st == FBS_INV_OK) {
        fz_item *w = &m.items[idx];
        fz_unplace(&m, idx);
        w->state = 1u;
        w->inv = inv;
        w->grid = g;
        w->x = x;
        w->y = y;
        w->rot = rot;
        w->slot = FZ_NIL;
        fz_fp(w->type, rot, &fw, &fh);
        fz_stamp(&m, inv, g, x, y, fw, fh, idx);
      }
    } else if (kind < 15u) { /* move, auto placed */
      unsigned idx = m.item_count ? rng_below(&r, m.item_count) : FZ_NIL;
      unsigned inv = rng_below(&r, m.inv_count);
      int rotate = (int)rng_below(&r, 2u);
      unsigned g = 0, x = 0, y = 0, rot = 0, fw, fh;
      fbs_inv_item h = (idx == FZ_NIL) ? FBS_INV_NONE : fz_handle(&m, idx);
      int live = idx != FZ_NIL && m.items[idx].state != 0u;
      if (live)
        expect_ok = !fz_cycle(&m, inv, idx) &&
                    fz_find(&m, inv, m.items[idx].type, rotate, idx, &g, &x, &y, &rot);
      st = fbs_inv_move_auto(s, h, inv, rotate);
      if (st == FBS_INV_OK) {
        fz_item *w = &m.items[idx];
        fz_unplace(&m, idx);
        w->state = 1u;
        w->inv = inv;
        w->grid = g;
        w->x = x;
        w->y = y;
        w->rot = rot;
        w->slot = FZ_NIL;
        fz_fp(w->type, rot, &fw, &fh);
        fz_stamp(&m, inv, g, x, y, fw, fh, idx);
      }
    } else if (kind < 16u) { /* rotate in place */
      unsigned idx = m.item_count ? rng_below(&r, m.item_count) : FZ_NIL;
      unsigned rot = rng_below(&r, 2u);
      unsigned fw, fh;
      fbs_inv_item h = (idx == FZ_NIL) ? FBS_INV_NONE : fz_handle(&m, idx);
      int live = idx != FZ_NIL && m.items[idx].state == 1u;
      if (live) {
        const fz_item *w = &m.items[idx];
        fz_fp(w->type, rot, &fw, &fh);
        expect_ok = !fz_cycle(&m, w->inv, idx) &&
                    fz_free_rect(&m, w->inv, w->grid, w->x, w->y, fw, fh, idx);
      }
      st = fbs_inv_rotate(s, h, rot ? FBS_INV_ROT_90 : FBS_INV_ROT_0);
      if (st == FBS_INV_OK) {
        fz_item *w = &m.items[idx];
        fz_unplace(&m, idx);
        w->rot = rot;
        fz_fp(w->type, rot, &fw, &fh);
        fz_stamp(&m, w->inv, w->grid, w->x, w->y, fw, fh, idx);
      }
    } else if (kind < 18u) { /* merge */
      unsigned a = m.item_count ? rng_below(&r, m.item_count) : FZ_NIL;
      unsigned b = m.item_count ? rng_below(&r, m.item_count) : FZ_NIL;
      uint32_t count = rng_below(&r, 4u);
      uint32_t moved = 0;
      fbs_inv_item ha = (a == FZ_NIL) ? FBS_INV_NONE : fz_handle(&m, a);
      fbs_inv_item hb = (b == FZ_NIL) ? FBS_INV_NONE : fz_handle(&m, b);
      int live = a != FZ_NIL && b != FZ_NIL && m.items[a].state != 0u && m.items[b].state != 0u;
      if (live && a != b && m.items[a].type == m.items[b].type && count <= m.items[b].stack)
        expect_ok = 1;
      st = fbs_inv_stack_merge(s, ha, hb, count, &moved);
      if (st == FBS_INV_OK) {
        uint32_t head = fz_cap[m.items[a].type] - m.items[a].stack;
        uint32_t want = count ? count : m.items[b].stack;
        uint32_t n = want < m.items[b].stack ? want : m.items[b].stack;
        if (n > head) n = head;
        if (n != moved) {
          printf("FAIL fuzz op %u: merge moved %u, expected %u\n", op, moved, n);
          CHECK(0);
          break;
        }
        m.items[a].stack += n;
        m.items[b].stack -= n;
        if (m.items[b].stack == 0u) {
          if (ghost_n < 8u) ghosts[ghost_n++] = hb;
          fz_destroy(&m, b);
        }
      }
    } else if (kind < 19u) { /* split */
      unsigned idx = m.item_count ? rng_below(&r, m.item_count) : FZ_NIL;
      unsigned inv = rng_below(&r, m.inv_count);
      unsigned g = rng_below(&r, m.invs[inv].ng);
      unsigned x = rng_below(&r, FZ_DIM);
      unsigned y = rng_below(&r, FZ_DIM);
      unsigned rot = rng_below(&r, 2u);
      uint32_t count = 1u + rng_below(&r, 4u);
      unsigned fresh = fz_pick(&m);
      unsigned fw, fh;
      fbs_inv_item h = (idx == FZ_NIL) ? FBS_INV_NONE : fz_handle(&m, idx);
      fbs_inv_item made = FBS_INV_NONE;
      int live = idx != FZ_NIL && m.items[idx].state != 0u;
      if (live) {
        fz_fp(m.items[idx].type, rot, &fw, &fh);
        expect_ok = count >= 1u && count < m.items[idx].stack && fresh != FZ_NIL &&
                    fz_free_rect(&m, inv, g, x, y, fw, fh, FZ_NIL);
      }
      st = fbs_inv_stack_split_to(s, h, inv, g, rot ? FBS_INV_ROT_90 : FBS_INV_ROT_0, (uint16_t)x,
                                  (uint16_t)y, count, &made);
      if (st == FBS_INV_OK) {
        fz_item *w = &m.items[fresh];
        uint32_t gen = fz_take_gen(&m);
        w->state = 1u;
        w->type = m.items[idx].type;
        w->gen = gen;
        w->stack = count;
        w->inv = inv;
        w->grid = g;
        w->x = x;
        w->y = y;
        w->rot = rot;
        w->slot = FZ_NIL;
        w->container = FZ_NIL;
        if (fresh == m.item_count) m.item_count += 1u;
        fz_fp(w->type, rot, &fw, &fh);
        fz_stamp(&m, inv, g, x, y, fw, fh, fresh);
        m.items[idx].stack -= count;
      }
    } else { /* equip / unequip */
      unsigned sl = rng_below(&r, FZ_SLOTS);
      unsigned which = rng_below(&r, 2u);
      if (which == 0u) {
        unsigned idx = m.item_count ? rng_below(&r, m.item_count) : FZ_NIL;
        fbs_inv_item h = (idx == FZ_NIL) ? FBS_INV_NONE : fz_handle(&m, idx);
        int live = idx != FZ_NIL && m.items[idx].state != 0u;
        if (live && m.slot_item[sl] == FZ_NIL &&
            (fz_mask[sl] == 0u || (fz_tags[m.items[idx].type] & fz_mask[sl]) != 0u))
          expect_ok = 1;
        st = fbs_inv_equip(s, sl, h);
        if (st == FBS_INV_OK) {
          fz_item *w = &m.items[idx];
          fz_unplace(&m, idx);
          w->state = 2u;
          w->slot = sl;
          w->x = 0u;
          w->y = 0u;
          w->rot = 0u;
          m.slot_item[sl] = idx;
        }
      } else {
        unsigned inv = rng_below(&r, m.inv_count);
        int rotate = (int)rng_below(&r, 2u);
        unsigned idx = m.slot_item[sl];
        unsigned g = 0, x = 0, y = 0, rot = 0, fw, fh;
        if (idx != FZ_NIL)
          expect_ok = !fz_cycle(&m, inv, idx) &&
                      fz_find(&m, inv, m.items[idx].type, rotate, FZ_NIL, &g, &x, &y, &rot);
        st = fbs_inv_unequip_to(s, sl, inv, rotate);
        if (st == FBS_INV_OK) {
          fz_item *w = &m.items[idx];
          fz_unplace(&m, idx);
          w->state = 1u;
          w->inv = inv;
          w->grid = g;
          w->x = x;
          w->y = y;
          w->rot = rot;
          w->slot = FZ_NIL;
          fz_fp(w->type, rot, &fw, &fh);
          fz_stamp(&m, inv, g, x, y, fw, fh, idx);
        }
      }
    }

    if ((st == FBS_INV_OK) != (expect_ok != 0)) {
      printf("FAIL fuzz op %u kind %u: status %s, model expected %s\n", op, kind,
             fbs_inv_status_name(st), expect_ok ? "ok" : "failure");
      CHECK(0);
      break;
    }
    if (st == FBS_INV_OK) ++applied;
    else ++refused;

    if (fz_compare(&m, s, op)) {
      CHECK(0);
      break;
    }

    if ((op % FZ_FIXPOINT_EVERY) == 0u) {
      fbs_inv_store *round = NULL;
      blob = serialize_alloc(s, &bl);
      if (fbs_inv_deserialize(blob, bl, NULL, NULL, &round) != FBS_INV_OK) {
        printf("FAIL fuzz op %u: blob did not reload\n", op);
        CHECK(0);
        free(blob);
        break;
      }
      blob2 = serialize_alloc(round, &bl2);
      if (!blobs_equal(blob, bl, blob2, bl2)) {
        printf("FAIL fuzz op %u: ser/deser/ser is not a fixed point\n", op);
        CHECK(0);
        free(blob);
        free(blob2);
        fbs_inv_store_destroy(round);
        break;
      }
      free(blob);
      free(blob2);
      fbs_inv_store_destroy(round);
      blob = NULL;
      blob2 = NULL;
    }

    if (--txn_left == 0u) {
      unsigned outcome = rng_below(&r, 3u);
      if (outcome == 0u) {
        uint32_t floor = m.gen_floor; /* the floor is never rewound (INV-2) */
        CHECK(fbs_inv_txn_abort(s) == FBS_INV_OK);
        m = snap;
        m.gen_floor = floor;
        ghost_n = ghost_snap; /* an abort revives what this txn destroyed */
        if (fz_compare(&m, s, op)) {
          CHECK(0);
          break;
        }
      } else {
        CHECK(fbs_inv_txn_commit(s) == FBS_INV_OK);
      }
      in_txn = 0u;
    }
  }
  if (in_txn) CHECK(fbs_inv_txn_commit(s) == FBS_INV_OK);
  CHECK(applied > FZ_OPS / 8u); /* the run really did do work */
  CHECK(refused > FZ_OPS / 8u); /* and really did exercise the refusals */
  CHECK(containers > 100u);     /* containers were spawned (INV-10) */
  CHECK(cycles > 100u);         /* and cycles really were attempted */
  CHECK(nested > 10u);          /* and items really were put inside them */
  printf("fuzz: %u applied, %u refused, %u item slots, %u inventories, %u containers, %u cycles\n",
         applied, refused, fbs_inv_item_count(s), fbs_inv_inventory_count(s), containers, cycles);
  fbs_inv_store_destroy(s);
}
/* ------------------------------------------------------------------------- */
/* Container inventory recycling, and the policies the header now states      */
/* ------------------------------------------------------------------------- */

static void test_container_recycling(void) {
  static const uint16_t small_wh[2] = {2, 2};
  static const uint16_t big_wh[4] = {3, 1, 1, 3};
  fbs_inv_store *s = make_store(NULL);
  fbs_inv_type small = add_type(s, "pouch", 1, 1, 1, 0, small_wh, 1);
  fbs_inv_type big = add_type(s, "trunk", 2, 1, 1, 0, big_wh, 2);
  fbs_inv_inventory root = add_inv1(s, 4, 4);
  fbs_inv_inventory in1 = FBS_INV_NONE, in2 = FBS_INV_NONE, in3 = FBS_INV_NONE;
  fbs_inv_item a, b, c, gem;
  fbs_inv_type coin = add_type(s, "coin", 1, 1, 5, 0, NULL, 0);
  fbs_inv_status st;
  uint16_t gw = 0, gh = 0;

  a = spawn_at(s, root, 0, small, 1, FBS_INV_ROT_0, 0, 0);
  CHECK(fbs_inv_item_container(s, a, &in1) == FBS_INV_OK);
  CHECK(fbs_inv_inventory_count(s) == 2u);

  /* Destroying the container detaches its inventory but never renumbers it. */
  CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
  CHECK(fbs_inv_destroy(s, a) == FBS_INV_OK);
  CHECK(fbs_inv_txn_commit(s) == FBS_INV_OK);
  CHECK(fbs_inv_inventory_count(s) == 2u);

  /* A container of a different shape cannot take it over ... */
  b = spawn_at(s, root, 0, big, 1, FBS_INV_ROT_0, 0, 0);
  CHECK(fbs_inv_item_container(s, b, &in2) == FBS_INV_OK);
  CHECK(in2 != in1);
  CHECK(fbs_inv_inventory_count(s) == 3u);
  CHECK(fbs_inv_grid_size(s, in2, 0, &gw, &gh) == FBS_INV_OK && gw == 3 && gh == 1);
  CHECK(fbs_inv_grid_size(s, in2, 1, &gw, &gh) == FBS_INV_OK && gw == 1 && gh == 3);

  /* ... but a matching one does, and capacity stops growing. */
  c = spawn_at(s, root, 0, small, 1, FBS_INV_ROT_0, 2, 0);
  CHECK(fbs_inv_item_container(s, c, &in3) == FBS_INV_OK);
  CHECK(in3 == in1);
  CHECK(fbs_inv_inventory_count(s) == 3u);
  {
    fbs_inv_item owner = FBS_INV_NONE;
    CHECK(fbs_inv_inventory_owner(s, in1, &owner) == FBS_INV_OK && owner == c);
    CHECK(owner != a);
  }
  /* The item slot was recycled too: the trunk took the pouch's tombstoned
     index under a fresh generation, so the old handle can never come back. */
  CHECK((a & 0xFFFFu) == (b & 0xFFFFu));
  CHECK((a >> 16) != (b >> 16));
  CHECK(a != b);
  CHECK(fbs_inv_item_live(s, a) == 0);
  CHECK(fbs_inv_item_live(s, b) == 1);
  CHECK((c & 0xFFFFu) == 1u); /* and only then does the slot count grow */
  CHECK(fbs_inv_item_count(s) == 2u);

  /* A detached inventory the caller has filled is never recycled underneath it. */
  CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
  CHECK(fbs_inv_destroy(s, c) == FBS_INV_OK);
  CHECK(fbs_inv_txn_commit(s) == FBS_INV_OK);
  gem = spawn_at(s, in1, 0, coin, 2, FBS_INV_ROT_0, 0, 0); /* into the detached shell */
  {
    fbs_inv_item d;
    fbs_inv_inventory in4 = FBS_INV_NONE;
    d = spawn_at(s, root, 0, small, 1, FBS_INV_ROT_0, 3, 0);
    CHECK(fbs_inv_item_container(s, d, &in4) == FBS_INV_OK);
    CHECK(in4 != in1); /* in1 still holds the coin, so a new shell was carved */
    CHECK(cell_at(s, in1, 0, 0, 0) == gem);
    CHECK(fbs_inv_inventory_count(s) == 4u);
  }

  /* Recycling is undone exactly, like everything else. */
  {
    unsigned char *b0, *b1;
    size_t l0 = 0, l1 = 0;
    fbs_inv_item made = FBS_INV_NONE;
    b0 = serialize_alloc(s, &l0);
    CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
    CHECK(fbs_inv_destroy(s, b) == FBS_INV_OK);
    CHECK(fbs_inv_spawn_at(s, root, 0, big, 1, FBS_INV_ROT_0, 0, 0, &made) == FBS_INV_OK);
    CHECK(fbs_inv_item_container(s, made, &in2) == FBS_INV_OK);
    CHECK(fbs_inv_txn_abort(s) == FBS_INV_OK);
    b1 = serialize_alloc(s, &l1);
    CHECK(blobs_equal(b0, l0, b1, l1));
    CHECK(fbs_inv_item_live(s, b) == 1);
    free(b0);
    free(b1);
  }

  /* seal is idempotent, and only type registration is frozen by it */
  CHECK(fbs_inv_seal(s) == FBS_INV_OK);
  CHECK(fbs_inv_seal(s) == FBS_INV_OK);
  CHECK(fbs_inv_is_sealed(s) == 1);
  CHECK(add_inv1(s, 2, 2) == 4u);
  IN_TXN(s, fbs_inv_spawn(s, root, coin, 1, 0, &gem), st);
  CHECK(st == FBS_INV_OK);

  fbs_inv_store_destroy(s);
}

/* A blob whose grids are wider than the default max_grid_dim must still load
 * with cfg == NULL: the capacity is the larger of the default and what the blob
 * needs, so ser/deser/ser stays a fixed point for any legal store. */
static void test_large_grid_round_trip(void) {
  fbs_inv_config cfg = fbs_inv_config_default();
  fbs_inv_store *s, *t = NULL;
  fbs_inv_type ty;
  fbs_inv_inventory inv;
  unsigned char *b0, *b1;
  size_t l0 = 0, l1 = 0;
  uint16_t gw = 0, gh = 0;

  cfg.max_grid_dim = 200u;
  cfg.max_cells = 4096u;
  s = make_store(&cfg);
  ty = add_type(s, "long", 100, 1, 1, 0, NULL, 0);
  inv = add_inv1(s, 100, 2);
  (void)spawn_at(s, inv, 0, ty, 1, FBS_INV_ROT_0, 0, 1);
  b0 = serialize_alloc(s, &l0);

  CHECK(fbs_inv_deserialize(b0, l0, NULL, NULL, &t) == FBS_INV_OK);
  CHECK(fbs_inv_grid_size(t, 0, 0, &gw, &gh) == FBS_INV_OK && gw == 100 && gh == 2);
  b1 = serialize_alloc(t, &l1);
  CHECK(blobs_equal(b0, l0, b1, l1));
  free(b1);
  fbs_inv_store_destroy(t);

  /* With an explicit config the header's literal rule applies instead. */
  t = NULL;
  cfg = fbs_inv_config_default();
  cfg.max_cells = 4096u;
  CHECK(fbs_inv_deserialize(b0, l0, &cfg, NULL, &t) == FBS_INV_E_RANGE);
  CHECK(t == NULL);
  cfg.max_grid_dim = 100u;
  CHECK(fbs_inv_deserialize(b0, l0, &cfg, NULL, &t) == FBS_INV_OK);
  fbs_inv_store_destroy(t);

  free(b0);
  fbs_inv_store_destroy(s);
}

/* ------------------------------------------------------------------------- */
/* Review fixes: the five contract points amended after the module review     */
/* ------------------------------------------------------------------------- */

/* INV-1 — a container type must have max_stack == 1, because draining a
 * stackable container in fbs_inv_stack_merge would destroy its contents and
 * break the conservation invariant the header states for merges. */
static void test_inv1_container_stack_rule(void) {
  static const uint16_t wh[2] = {2, 2};
  fbs_inv_store *s = make_store(NULL);
  fbs_inv_type_desc d;
  fbs_inv_type t = A5_U32;
  unsigned k;

  d.width = 1;
  d.height = 1;
  d.tags = 0;
  d.container_wh = wh;
  d.container_grids = 1;
  for (k = 0; k < 4u; ++k) {
    static const uint32_t bad[4] = {2u, 5u, 99u, (1u << 24)};
    d.max_stack = bad[k];
    CHECK(fbs_inv_type_add(s, "sbag", 4u, &d, &t) == FBS_INV_E_RANGE);
    CHECK(t == A5_U32);
  }
  CHECK(fbs_inv_type_count(s) == 0u);

  /* max_stack == 1 is fine, and so is any stack on a non-container. */
  d.max_stack = 1u;
  CHECK(fbs_inv_type_add(s, "sbag", 4u, &d, &t) == FBS_INV_OK && t == 0u);
  d.container_wh = NULL;
  d.container_grids = 0;
  d.max_stack = 9u;
  CHECK(fbs_inv_type_add(s, "coin", 4u, &d, &t) == FBS_INV_OK && t == 1u);

  /* The conservation invariant the finding broke, now unreachable through the
     public API, still holds for every merge of the legal shapes. */
  {
    fbs_inv_inventory root = add_inv1(s, 4, 4);
    fbs_inv_inventory inside = FBS_INV_NONE;
    fbs_inv_item bag_a = spawn_at(s, root, 0, 0u, 1, FBS_INV_ROT_0, 0, 0);
    fbs_inv_item bag_b = spawn_at(s, root, 0, 0u, 1, FBS_INV_ROT_0, 1, 0);
    fbs_inv_item coins;
    uint32_t moved = 0xA5A5A5A5u;
    fbs_inv_status st;
    CHECK(fbs_inv_item_container(s, bag_b, &inside) == FBS_INV_OK);
    coins = spawn_at(s, inside, 0, 1u, 9, FBS_INV_ROT_0, 0, 0);
    CHECK(fbs_inv_total_units(s) == 11u);
    /* same type, so the merge is legal — but the cap is 1, so nothing moves
       and nothing is destroyed */
    IN_TXN(s, fbs_inv_stack_merge(s, bag_a, bag_b, 0, &moved), st);
    CHECK(st == FBS_INV_OK);
    CHECK(moved == 0u);
    CHECK(fbs_inv_total_units(s) == 11u);
    CHECK(fbs_inv_item_live(s, coins) == 1);
    CHECK(fbs_inv_item_live(s, bag_b) == 1);
  }

  /* A blob claiming a stackable container is refused, allocating nothing. */
  {
    fbs_inv_item h[RICH_HANDLES];
    fbs_inv_inventory invs[3];
    fbs_inv_slot hand = FBS_INV_NONE;
    fbs_inv_store *rich = build_rich(0, h, invs, &hand);
    size_t len = 0;
    unsigned char *good = serialize_alloc(rich, &len);
    unsigned char *bad = (unsigned char *)malloc(len);
    CHECK(bad != NULL);
    if (bad) {
      /* type 2 is "pack", the container; its max_stack is at record + 12 */
      memcpy(bad, good, len);
      bad[48u + 32u * 2u + 12u] = 5u;
      expect_schema_reject(bad, len, "stackable container type");
      free(bad);
    }
    free(good);
    fbs_inv_store_destroy(rich);
  }

  fbs_inv_store_destroy(s);
}

/* The defect the container fuzz found once containers were in the mix: the
 * recycling rule could hand a new container the very shell it was being placed
 * into, so the item ended up inside its own inventory — the cycle E_CYCLE
 * exists to prevent, reached without a single move. */
static void test_no_self_container(void) {
  static const uint16_t wh[2] = {2, 2};
  fbs_inv_store *s = make_store(NULL);
  fbs_inv_type pouch = add_type(s, "pouch", 1, 1, 1, 0, wh, 1);
  fbs_inv_inventory root = add_inv1(s, 4, 4);
  fbs_inv_inventory in_a = FBS_INV_NONE, in_b = FBS_INV_NONE, in_c = FBS_INV_NONE;
  fbs_inv_item a, b, c;
  fbs_inv_inventory where = FBS_INV_NONE;
  fbs_inv_grid g = FBS_INV_NONE;
  uint16_t x = 0, y = 0;
  fbs_inv_rot rot = FBS_INV_ROT_0;
  fbs_inv_status st;

  a = spawn_at(s, root, 0, pouch, 1, FBS_INV_ROT_0, 0, 0);
  CHECK(fbs_inv_item_container(s, a, &in_a) == FBS_INV_OK);
  CHECK(in_a == 1u);
  CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
  CHECK(fbs_inv_destroy(s, a) == FBS_INV_OK);
  CHECK(fbs_inv_txn_commit(s) == FBS_INV_OK);
  /* in_a is now a detached, empty shell of exactly the right shape */

  b = spawn_at(s, in_a, 0, pouch, 1, FBS_INV_ROT_0, 0, 0);
  CHECK(fbs_inv_item_container(s, b, &in_b) == FBS_INV_OK);
  CHECK(in_b != in_a); /* it must NOT have been given the shell it stands in */
  CHECK(fbs_inv_item_place(s, b, &where, &g, &x, &y, &rot) == FBS_INV_OK);
  CHECK(where == in_a);
  CHECK(fbs_inv_inventory_count(s) == 3u);
  /* and the cycle guard still refuses the move that would do it by hand */
  IN_TXN(s, fbs_inv_move_to(s, b, in_b, 0, FBS_INV_ROT_0, 0, 0), st);
  CHECK(st == FBS_INV_E_CYCLE);

  /* With a second detached shell available, the destination is skipped and the
     other one is recycled — the policy is not disabled, just made safe. */
  CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
  CHECK(fbs_inv_destroy(s, b) == FBS_INV_OK);
  CHECK(fbs_inv_txn_commit(s) == FBS_INV_OK);
  CHECK(fbs_inv_inventory_count(s) == 3u);
  c = spawn_at(s, in_a, 0, pouch, 1, FBS_INV_ROT_0, 1, 1);
  CHECK(fbs_inv_item_container(s, c, &in_c) == FBS_INV_OK);
  CHECK(in_c == in_b); /* the other shell, not the one it stands in */
  CHECK(fbs_inv_inventory_count(s) == 3u);

  fbs_inv_store_destroy(s);
}

/* INV-2 — a handle minted inside an aborted transaction is never reissued:
 * the store keeps an unserialized generation floor that only grows, while
 * abort still rewinds the serialized counter so the blob is byte-identical. */
static void test_inv2_generation_floor(void) {
  fbs_inv_store *s = make_store(NULL);
  fbs_inv_type t1 = add_type(s, "one", 1, 1, 5, 0, NULL, 0);
  fbs_inv_type t2 = add_type(s, "two", 1, 1, 5, 0, NULL, 0);
  fbs_inv_inventory inv = add_inv1(s, 4, 4);
  fbs_inv_item ghost = FBS_INV_NONE, after = FBS_INV_NONE;
  unsigned char *b0, *b1;
  size_t l0 = 0, l1 = 0;
  unsigned k;

  b0 = serialize_alloc(s, &l0);

  /* mint a handle, then throw the transaction away */
  CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
  CHECK(fbs_inv_spawn_at(s, inv, 0, t2, 2, FBS_INV_ROT_0, 0, 0, &ghost) == FBS_INV_OK);
  CHECK(ghost != FBS_INV_NONE);
  CHECK(fbs_inv_txn_abort(s) == FBS_INV_OK);

  /* T-7 is untouched: the rewound counter keeps the blob byte-identical */
  b1 = serialize_alloc(s, &l1);
  CHECK(blobs_equal(b0, l0, b1, l1));
  free(b1);

  /* the index is not issued any more, so the handle is not usable at all */
  CHECK(fbs_inv_item_live(s, ghost) < 0);

  /* the next spawn takes the same index but never the same handle */
  CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
  CHECK(fbs_inv_spawn_at(s, inv, 0, t1, 5, FBS_INV_ROT_0, 0, 0, &after) == FBS_INV_OK);
  CHECK(fbs_inv_txn_commit(s) == FBS_INV_OK);
  CHECK((after & 0xFFFFu) == (ghost & 0xFFFFu)); /* same slot ... */
  CHECK((after >> 16) != (ghost >> 16));         /* ... never the same bits */
  CHECK(after != ghost);
  CHECK(fbs_inv_item_live(s, ghost) == 0);
  {
    fbs_inv_type got = FBS_INV_NONE;
    uint32_t stack = 0;
    CHECK(fbs_inv_item_type_of(s, ghost, &got) == FBS_INV_E_STALE);
    CHECK(got == FBS_INV_NONE);
    CHECK(fbs_inv_item_stack(s, ghost, &stack) == FBS_INV_E_STALE);
    CHECK(fbs_inv_item_type_of(s, after, &got) == FBS_INV_OK && got == t1);
  }

  /* and it stays unissued however much churn follows */
  for (k = 0; k < 200u; ++k) {
    fbs_inv_item made = FBS_INV_NONE;
    fbs_inv_status st;
    IN_TXN(s, fbs_inv_spawn(s, inv, t1, 1, 0, &made), st);
    if (st != FBS_INV_OK) continue;
    CHECK(made != ghost);
    if ((k % 3u) == 0u) {
      IN_TXN(s, fbs_inv_destroy(s, made), st);
      CHECK(st == FBS_INV_OK);
    }
    /* an aborted mint in the middle of the churn is also never reissued */
    if ((k % 7u) == 0u) {
      fbs_inv_item lost = FBS_INV_NONE;
      CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
      if (fbs_inv_spawn(s, inv, t2, 1, 0, &lost) == FBS_INV_OK) {
        CHECK(lost != ghost);
        CHECK(fbs_inv_txn_abort(s) == FBS_INV_OK);
        CHECK(fbs_inv_item_live(s, lost) <= 0);
      } else {
        CHECK(fbs_inv_txn_abort(s) == FBS_INV_OK);
      }
    }
  }
  CHECK(fbs_inv_item_live(s, ghost) == 0);

  /* the floor survives a store_clear too */
  {
    fbs_inv_item fresh;
    fbs_inv_inventory inv2;
    fbs_inv_store_clear(s);
    inv2 = add_inv1(s, 2, 2);
    fresh = spawn_at(s, inv2, 0, t1, 1, FBS_INV_ROT_0, 0, 0);
    CHECK(fresh != ghost);
    CHECK(fbs_inv_item_live(s, ghost) == 0);
  }

  /* a reloaded store starts its floor at the blob's counter */
  {
    fbs_inv_store *r = NULL;
    unsigned char *b2;
    size_t l2 = 0;
    fbs_inv_item first = FBS_INV_NONE;
    fbs_inv_status st;
    b2 = serialize_alloc(s, &l2);
    CHECK(fbs_inv_deserialize(b2, l2, NULL, NULL, &r) == FBS_INV_OK);
    IN_TXN(r, fbs_inv_spawn(r, 0u, t1, 1, 0, &first), st);
    CHECK(st == FBS_INV_OK);
    CHECK(first != ghost);
    free(b2);
    fbs_inv_store_destroy(r);
  }

  free(b0);
  fbs_inv_store_destroy(s);
}

/* INV-4 — sealing is not transactional: abort never lifts it. */
static void test_inv4_seal_is_not_rolled_back(void) {
  fbs_inv_store *s = make_store(NULL);
  fbs_inv_type_desc d;
  fbs_inv_type t = FBS_INV_NONE;

  d.width = 1;
  d.height = 1;
  d.max_stack = 1;
  d.tags = 0;
  d.container_wh = NULL;
  d.container_grids = 0;

  CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
  CHECK(fbs_inv_type_add(s, "inside", 6u, &d, &t) == FBS_INV_OK);
  CHECK(fbs_inv_type_count(s) == 1u);
  CHECK(fbs_inv_seal(s) == FBS_INV_OK);
  CHECK(fbs_inv_is_sealed(s) == 1);
  CHECK(fbs_inv_txn_abort(s) == FBS_INV_OK);
  CHECK(fbs_inv_is_sealed(s) == 1); /* the seal stands ... */
  CHECK(fbs_inv_type_count(s) == 0u); /* ... while the registration is undone */
  CHECK(fbs_inv_type_add(s, "after", 5u, &d, &t) == FBS_INV_E_SEALED);
  /* and the rolled-back key bytes are usable again by nothing, since the
     catalog is frozen; the store is otherwise fully functional */
  {
    fbs_inv_inventory inv = add_inv1(s, 2, 2);
    CHECK(inv == 0u);
    CHECK(fbs_inv_is_sealed(s) == 1);
  }
  fbs_inv_store_destroy(s);
}

/* INV-5 — fbs_inv_slot_add is a mutator: it needs a transaction and abort
 * undoes it completely, key bytes included. */
static void test_inv5_slot_add_is_transactional(void) {
  fbs_inv_config cfg = fbs_inv_config_default();
  fbs_inv_store *s;
  fbs_inv_slot sl = FBS_INV_NONE, found = FBS_INV_NONE;
  fbs_inv_type t;
  fbs_inv_inventory inv;
  unsigned char *b0, *b1;
  size_t l0 = 0, l1 = 0;
  unsigned k;

  cfg.max_key_bytes = 32u;
  s = make_store(&cfg);
  t = add_type(s, "unit", 1, 1, 1, 0x1u, NULL, 0);
  inv = add_inv1(s, 2, 2);

  CHECK(fbs_inv_slot_add(s, "hand", 4u, 0u, &sl) == FBS_INV_E_TXN);
  CHECK(sl == FBS_INV_NONE);
  CHECK(fbs_inv_slot_find(s, "hand", 4u, &found) == FBS_INV_E_NOT_FOUND);

  b0 = serialize_alloc(s, &l0);

  CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
  CHECK(fbs_inv_slot_add(s, "hand", 4u, 0u, &sl) == FBS_INV_OK);
  CHECK(fbs_inv_slot_find(s, "hand", 4u, &found) == FBS_INV_OK && found == sl);
  CHECK(fbs_inv_txn_abort(s) == FBS_INV_OK);
  CHECK(fbs_inv_slot_find(s, "hand", 4u, &found) == FBS_INV_E_NOT_FOUND);
  CHECK(fbs_inv_slot_item(s, sl, &sl) == FBS_INV_E_INVALID); /* the id is gone */

  b1 = serialize_alloc(s, &l1);
  CHECK(blobs_equal(b0, l0, b1, l1));
  free(b1);

  /* the aborted key bytes are reclaimed, so a 32-byte arena survives churn */
  for (k = 0; k < 20u; ++k) {
    fbs_inv_slot tmp = FBS_INV_NONE;
    CHECK(fbs_inv_txn_begin(s) == FBS_INV_OK);
    CHECK(fbs_inv_slot_add(s, "abcdefgh", 8u, 0u, &tmp) == FBS_INV_OK);
    CHECK(fbs_inv_txn_abort(s) == FBS_INV_OK);
  }

  /* committed, it behaves exactly as before */
  sl = add_slot(s, "hand", 0x1u);
  {
    fbs_inv_item it = spawn_at(s, inv, 0, t, 1, FBS_INV_ROT_0, 0, 0);
    fbs_inv_status st;
    IN_TXN(s, fbs_inv_equip(s, sl, it), st);
    CHECK(st == FBS_INV_OK);
    CHECK(fbs_inv_slot_item(s, sl, &it) == FBS_INV_OK);
  }
  /* a poisoned transaction refuses it like any other mutator */
  {
    fbs_inv_slot tmp = FBS_INV_NONE;
    fbs_inv_config tight = fbs_inv_config_default();
    fbs_inv_store *p;
    fbs_inv_type pt;
    fbs_inv_inventory pi;
    fbs_inv_item pit;
    unsigned n;
    tight.max_txn_ops = 8u;
    p = make_store(&tight);
    pt = add_type(p, "unit", 1, 1, 1, 0, NULL, 0);
    pi = add_inv1(p, 4, 4);
    pit = spawn_at(p, pi, 0, pt, 1, FBS_INV_ROT_0, 0, 0);
    CHECK(fbs_inv_txn_begin(p) == FBS_INV_OK);
    for (n = 0; n < 10u; ++n) {
      if (fbs_inv_move_to(p, pit, pi, 0, FBS_INV_ROT_0, (uint16_t)(1u + n % 3u), 1) ==
          FBS_INV_E_FULL)
        break;
    }
    CHECK(fbs_inv_slot_add(p, "hand", 4u, 0u, &tmp) == FBS_INV_E_TXN);
    CHECK(tmp == FBS_INV_NONE);
    CHECK(fbs_inv_txn_abort(p) == FBS_INV_OK);
    fbs_inv_store_destroy(p);
  }

  free(b0);
  fbs_inv_store_destroy(s);
}

/* INV-9 — max_items tops out at 65535, so no item index can collide with the
 * 0xFFFF that FBS_INV_NONE puts in a handle's index bits. */
static void test_inv9_item_cap_boundary(void) {
  fbs_inv_config cfg = fbs_inv_config_default();
  fbs_inv_store *s = (fbs_inv_store *)0x1;

  cfg.max_items = 65536u;
  CHECK(fbs_inv_store_create(&cfg, NULL, &s) == FBS_INV_E_INVALID);
  CHECK(s == (fbs_inv_store *)0x1);
  cfg.max_items = 0u;
  CHECK(fbs_inv_store_create(&cfg, NULL, &s) == FBS_INV_E_INVALID);
  CHECK(s == (fbs_inv_store *)0x1);

  cfg.max_items = 65535u;
  s = NULL;
  CHECK(fbs_inv_store_create(&cfg, NULL, &s) == FBS_INV_OK);
  if (s) {
    fbs_inv_type t = add_type(s, "unit", 1, 1, 1, 0, NULL, 0);
    fbs_inv_inventory inv = add_inv1(s, 4, 4);
    fbs_inv_item it = spawn_at(s, inv, 0, t, 1, FBS_INV_ROT_0, 0, 0);
    CHECK(fbs_inv_item_count(s) == 1u);
    CHECK(fbs_inv_item_live(s, it) == 1);
    CHECK(fbs_inv_store_memory(s) > (size_t)65535u * 8u);
    fbs_inv_store_destroy(s);
  }
  /* a blob claiming more slots than the cap is refused */
  {
    unsigned char header[48];
    memset(header, 0, sizeof header);
    header[0] = 'F';
    header[1] = 'B';
    header[2] = 'I';
    header[3] = 'V';
    header[4] = 1;
    header[20] = 0x00;
    header[21] = 0x00;
    header[22] = 0x01; /* item_count = 65536 */
    header[36] = 1;    /* next_generation */
    expect_schema_reject(header, sizeof header, "item_count past the cap");
  }
}

/* ------------------------------------------------------------------------- */
/* Golden serialization fixture                                              */
/* ------------------------------------------------------------------------- */

static void test_fixture(void) {
  fbs_inv_item h[RICH_HANDLES];
  fbs_inv_inventory invs[3];
  fbs_inv_slot hand = FBS_INV_NONE;
  fbs_inv_store *s = build_rich(0, h, invs, &hand);
  fbs_inv_store *g = NULL;
  char path[512];
  size_t len = 0;
  unsigned char *blob = serialize_alloc(s, &len);
  FILE *fp;

  /* 48 header + 4*32 types + 2*2 container_wh + 4*16 inventories + 4*8 grids
     + 6*28 items + 2*24 slots + 24 key bytes */
  CHECK(len == 48u + 128u + 4u + 64u + 32u + 168u + 48u + 24u);

  sprintf(path, "%s/store.bin", g_fixture_dir);
  if (g_write_fixtures) {
    fp = fopen(path, "wb");
    ++g_checks;
    if (!fp) {
      ++g_fails;
      printf("FAIL cannot open %s for writing\n", path);
    } else {
      size_t wrote = fwrite(blob, 1u, len, fp);
      fclose(fp);
      CHECK(wrote == len);
      printf("wrote %s (%lu bytes)\n", path, (unsigned long)len);
    }
  } else {
    fp = fopen(path, "rb");
    ++g_checks;
    if (!fp) {
      ++g_fails;
      printf("FAIL cannot open fixture %s (run with --write-fixtures to create it)\n", path);
    } else {
      unsigned char golden[2048];
      size_t got = fread(golden, 1u, sizeof golden, fp);
      fclose(fp);
      CHECK(got == len);
      if (got == len) {
        CHECK(memcmp(golden, blob, len) == 0);
        /* the committed bytes must still load, still mean the same thing, and
           still re-serialize identically */
        CHECK(fbs_inv_deserialize(golden, got, NULL, NULL, &g) == FBS_INV_OK);
        if (g) {
          size_t l2 = 0;
          unsigned char *b2 = serialize_alloc(g, &l2);
          CHECK(blobs_equal(b2, l2, golden, got));
          expect_rich_state(g, h, invs, hand);
          free(b2);
          fbs_inv_store_destroy(g);
        }
      }
    }
  }
  free(blob);
  fbs_inv_store_destroy(s);
}

/* ------------------------------------------------------------------------- */

int main(int argc, char **argv) {
  int i;
  for (i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--write-fixtures") == 0) {
      g_write_fixtures = 1;
    } else if (strcmp(argv[i], "--fixture-dir") == 0 && i + 1 < argc) {
      g_fixture_dir = argv[++i];
    } else {
      printf("usage: %s [--write-fixtures] [--fixture-dir DIR]\n", argv[0]);
      return 2;
    }
  }

  test_t1_footprint_and_rotation();
  test_t2_counter_example();
  test_t3_bounds();
  test_t3b_scan_order();
  test_t3c_rotation_fallback();
  test_t3d_multi_grid();
  test_t4_merge();
  test_t4b_zero_is_destroyed();
  test_t4c_identity_is_the_type();
  test_t5_split();
  test_t5b_property();
  test_t6_cycles();
  test_t6b_recursive_destroy();
  test_t7_rollback_is_byte_identical();
  test_t7c_commit_is_not_a_no_op();
  test_t7d_journal_exhaustion();
  test_t7e_transaction_discipline();
  test_t8_determinism_and_round_trip();
  test_t8b_corruption();
  test_t8c_truncated_output();
  test_t9_equipment();
  test_t10_error_table();
  test_status_names();
  test_t11_allocator();
  test_invalid_arguments();
  test_config_validation();
  test_inv1_container_stack_rule();
  test_no_self_container();
  test_inv2_generation_floor();
  test_inv4_seal_is_not_rolled_back();
  test_inv5_slot_add_is_transactional();
  test_inv9_item_cap_boundary();
  test_container_recycling();
  test_large_grid_round_trip();
  test_t12_fuzz();
  test_fixture();

  printf("inventory: %d checks passed, %d failed\n", g_checks - g_fails, g_fails);
  return g_fails > 100 ? 100 : g_fails;
}
