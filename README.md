# fbs-inventory

Grid inventory library in C99 with stacking, equipment slots, nested containers and undoable transactions.

## What it does

You create a store, register item types, add inventories made of rectangular grids, then place, move, stack and equip items. Every call returns an `fbs_inv_status` code.

- **Item types.** `fbs_inv_type_add` registers a type under a byte-string key with a footprint (`width` x `height` cells), a `max_stack` (1 means not stackable), 64-bit `tags`, and optionally its own container grids. `fbs_inv_seal` freezes the catalog.
- **Grids and placement.** `fbs_inv_inventory_add` creates an inventory of one or more independent grids. An item sits at an anchor cell with rotation `FBS_INV_ROT_0` or `FBS_INV_ROT_90` and lives inside exactly one grid. `fbs_inv_can_place` is the single placement rule (in bounds, every covered cell free). `fbs_inv_find_place` returns the first fit in a fixed scan order: grids in index order, then rows top to bottom, and with `try_rotate` it tries 90 degrees on a grid before moving to the next one.
- **Mutations.** `fbs_inv_spawn` / `fbs_inv_spawn_at` create items, `fbs_inv_move_to` / `fbs_inv_move_auto` / `fbs_inv_rotate` move them, `fbs_inv_destroy` removes them. A failed move leaves the item where it was.
- **Stacking.** `fbs_inv_stack_merge` moves units up to the destination's cap and destroys the source when it reaches zero. `fbs_inv_stack_split_to` splits units into a new item at a given cell. Only items of the same type merge.
- **Containers.** Spawning a container type gives the item its own inventory (`fbs_inv_item_container`). Moving a container into itself or into anything nested inside it returns `FBS_INV_E_CYCLE`, at any depth. Destroying a container destroys its contents recursively.
- **Equipment slots.** `fbs_inv_slot_add` creates a keyed slot with an `accept_tags` mask (0 accepts anything, otherwise any shared tag bit). `fbs_inv_equip` returns `FBS_INV_E_OCCUPIED` instead of overwriting, and `fbs_inv_unequip_to` auto-places the item or changes nothing.
- **Queries.** `fbs_inv_cell_item` (O(1) cell lookup), `fbs_inv_item_place`, `fbs_inv_list_items` (ascending slot order), `fbs_inv_count_of` (optionally recursing into containers placed in grids) and `fbs_inv_total_units` (every inventory and every slot).
- **Save and load.** `fbs_inv_serialize` / `fbs_inv_deserialize` write and read a little-endian `FBIV` version 1 blob.

Item handles carry a 16-bit generation. Using a handle after its item is destroyed returns `FBS_INV_E_STALE`.

## When to use it

- Spatial inventories where items take up several cells and can be rotated, with bags inside bags and equipment slots.
- Drag-and-drop or crafting flows made of several steps that must either all happen or all be undone: open a transaction, try the steps, commit or abort.
- Saves, replays or network checks that compare inventory state byte for byte.
- Any engine that can call C. The library has no engine dependency.

## When not to use it

- Capacities are fixed when the store is created and nothing grows afterwards. Hard limits: 4096 types, 4096 inventories, 16384 grids, 2^22 cells, 65535 item slots, 1024 equipment slots, 1024 cells per grid axis, 2^24 units per stack, 64 grids per container type, 255-byte keys.
- Footprints are rectangles only. 180 and 270 degree rotations are reserved and return `FBS_INV_E_RANGE`. Weight or count limits and replication are out of scope for 0.1.0.
- Types cannot be removed, and cannot be added after `fbs_inv_seal`. A container type must have `max_stack == 1`.
- Every item or equipment change needs an open transaction, and a store allows one transaction at a time.
- The generation counter cycles through 1..65534, so a very old handle can alias a new item after wrap. The header states that handles are not identities across stores or save reloads: keep your own IDs if you need that.
- `fbs_inv_list_items`, `fbs_inv_count_of` and `fbs_inv_total_units` scan every issued item slot. `fbs_inv_count_of` counts items in grids only and stops at equipped containers.
- There is no UI, input handling or rendering. It is the rules and state only.

## Example

```c
#include <fbs/inventory.h>
#include <stdio.h>

#define TRY(x) do { if ((st = (x)) != FBS_INV_OK) goto done; } while (0)

int main(void) {
  static const uint16_t root_grid[2] = {4, 4}, pack_grid[2] = {3, 3};
  /* width, height, max_stack, tags, container grid sizes, container grid count */
  const fbs_inv_type_desc potion_d = {1, 1, 10, 0x1, NULL, 0};
  const fbs_inv_type_desc rifle_d = {1, 3, 1, 0x2, NULL, 0};
  const fbs_inv_type_desc pack_d = {2, 2, 1, 0x4, pack_grid, 1};
  fbs_inv_store *s = NULL;
  fbs_inv_type potion, rifle, pack;
  fbs_inv_inventory root, inside;
  fbs_inv_slot hands;
  fbs_inv_item bag, gun, a, b;
  uint32_t moved = 0;
  uint64_t potions = 0;
  fbs_inv_status st = fbs_inv_store_create(NULL, NULL, &s); /* default capacities */

  if (st != FBS_INV_OK) return 1;
  TRY(fbs_inv_type_add(s, "potion", 6, &potion_d, &potion));
  TRY(fbs_inv_type_add(s, "rifle", 5, &rifle_d, &rifle));
  TRY(fbs_inv_type_add(s, "pack", 4, &pack_d, &pack));
  TRY(fbs_inv_seal(s));
  TRY(fbs_inv_inventory_add(s, root_grid, 1, &root));

  TRY(fbs_inv_txn_begin(s));                        /* item changes need a transaction */
  TRY(fbs_inv_slot_add(s, "hands", 5, 0x2, &hands)); /* accepts tag 0x2 */
  TRY(fbs_inv_spawn(s, root, pack, 1, 1, &bag));
  TRY(fbs_inv_item_container(s, bag, &inside));     /* the pack's own 3x3 grid */
  TRY(fbs_inv_spawn(s, inside, potion, 7, 0, &a));
  TRY(fbs_inv_spawn(s, root, potion, 5, 0, &b));
  TRY(fbs_inv_stack_merge(s, a, b, 0, &moved));     /* fills a to its cap of 10 */
  TRY(fbs_inv_spawn(s, root, rifle, 1, 1, &gun));
  TRY(fbs_inv_equip(s, hands, gun));
  TRY(fbs_inv_txn_commit(s));
  TRY(fbs_inv_count_of(s, root, potion, 1, &potions));
  printf("moved %u, potions %llu, units %llu\n", (unsigned)moved,
         (unsigned long long)potions, (unsigned long long)fbs_inv_total_units(s));

  TRY(fbs_inv_txn_begin(s));
  TRY(fbs_inv_destroy(s, bag));                     /* takes the potions inside with it */
  TRY(fbs_inv_txn_abort(s));                        /* abort puts everything back */
  printf("after abort: units %llu, pack live %d\n",
         (unsigned long long)fbs_inv_total_units(s), fbs_inv_item_live(s, bag));
done:
  if (st != FBS_INV_OK) printf("error: %s\n", fbs_inv_status_name(st));
  fbs_inv_store_destroy(s);
  return st == FBS_INV_OK ? 0 : 1;
}
```

Add it as an executable with `target_link_libraries(your_app PRIVATE fbs::inventory)`. It prints `moved 3, potions 12, units 14` and `after abort: units 14, pack live 1`.

## Build and test

Run from this repository's root. In addition to CMake and the compiler named
below, install the build tool selected by your generator (for example Make or
Ninja).

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build --parallel 1
(cd build && ctest --output-on-failure)
```

This runs two tests. `inventory` is `tests/test_inventory.c`, which checks footprints and rotation, bounds, first-fit scan order, merge and split conservation, container cycles at any depth, recursive destroy, byte-identical rollback after abort, journal exhaustion, save/load round trips, rejection of corrupted blobs, equipment slots, one case per status code, allocator failure and NULL or bad arguments on every entry point. It also runs a 100,000-operation seeded fuzz against a reference model with a serialize/deserialize/serialize check after every operation, and compares a save against the committed golden blob `tests/fixtures/inventory/store.bin`. `inventory_example` runs `fbs_inventory_example` (`examples/basic.c`), which creates a store and prints the API version.

Options: `FBS_BUILD_TESTS` and `FBS_BUILD_EXAMPLES` (both ON). Requirements: CMake 3.16 or newer and a C99 compiler. The library uses only the standard C library and no floating point; on non-MSVC toolchains the CMake target also links `m`. There is no vendored code.

To use it from another CMake project, call `add_subdirectory` on a checkout or use FetchContent, pinned to a full commit hash:

```cmake
include(FetchContent)
FetchContent_Declare(fbs_inventory
  GIT_REPOSITORY https://github.com/finalbuildgames-com/fbs-inventory.git
  GIT_TAG <full-commit-sha>)
FetchContent_MakeAvailable(fbs_inventory)
target_link_libraries(your_app PRIVATE fbs::inventory)
```

This repository ships the C library only. No engine adapters or language bindings are included.

## Build modes and installation

`BUILD_SHARED_LIBS=ON` builds a shared library; the default is static.
`FBS_BUILD_TESTS` and `BUILD_TESTING` together enable the core test.
`FBS_BUILD_EXAMPLES` controls `fbs_inventory_example`; its CTest entry also requires
`BUILD_TESTING`. For a library-only build, set `FBS_BUILD_TESTS=OFF` and
`FBS_BUILD_EXAMPLES=OFF`.

```sh
cmake --install build --prefix "$PWD/install"
```

Installation supplies [the public header](include/fbs/inventory.h), the library,
license notices and `FinalBuildInventoryTargets.cmake` under
`${CMAKE_INSTALL_LIBDIR}/cmake/FinalBuildInventory`. It supplies no package config or
version config, so `find_package(FinalBuildInventory)` is unavailable. A consumer may
include the installed targets file explicitly and link `fbs::inventory`, or use
the source integration above. The [minimal program](examples/basic.c) and
[core tests](tests/test_inventory.c) show the implemented entry points.

## Design notes

- **Determinism.** No floating point, no global or static mutable state. First-fit scan order is part of the contract, and a destroyed item's slot is reused lowest index first. `tests/test_inventory.c` (`test_t8_determinism_and_round_trip`) builds the same store by two different routes and checks that the blobs are identical.
- **Memory.** One allocation per store, sized from `fbs_inv_config`; nothing allocates after create. `fbs_inv_config_default` gives 64 types, 32 inventories, 128 grids, 8192 cells, 1024 items, 32 slots, 4096 key bytes, 256 journal entries and 64 cells per grid axis. Pass an `fbs_inv_allocator` (`alloc`, `free`, `user`) or NULL for `malloc`/`free`. `fbs_inv_store_memory` reports the block size. `test_t11_allocator` checks there is exactly one allocation.
- **Transactions.** Each mutator writes inverse records to a fixed undo journal before it changes state, and `fbs_inv_txn_abort` replays them. Abort restores a byte-identical blob (`test_t7_rollback_is_byte_identical`). If the journal fills, the mutator returns `FBS_INV_E_FULL` and the transaction is poisoned: commit returns `FBS_INV_E_TXN` and only abort is allowed. Sealing and `fbs_inv_store_clear` are not undone by abort. The store-local generation floor is also not serialized or rolled back: it prevents immediate handle reuse after abort while the serialized counter rewinds, but it still wraps.
- **Threading.** No internal locking and no shared state between stores. Synchronize access to a single store yourself.
- **Errors.** Statuses are negative `fbs_inv_status` values; `fbs_inv_status_name` turns one into a string. On error, outputs are left untouched, except `FBS_INV_E_TRUNCATED`, which writes the required size or count.
- **Versioning.** `FBS_INV_VERSION` and `fbs_inv_version()` return 100 (major * 10000 + minor * 100 + patch, so 0.1.0). Blobs start with the magic `FBIV` and schema version 1; a mismatched or corrupted blob returns `FBS_INV_E_SCHEMA`. A deserialized store is sealed with no transaction open.

## License

MIT, Copyright (c) 2026 Micah Anthony (Final Build Games). See [LICENSE](LICENSE). This is an original C implementation with no third-party runtime code. Marketplace products were used only as specification references; their source and assets are excluded. See [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).
