# nDPI example tools

This directory contains sample programs that link against libnDPI, mainly **ndpiReader** (CLI over pcaps and live capture) and **ndpiSimpleIntegration**. DPDK-specific notes live in [README.DPDK](README.DPDK).

## ndpiReader and custom memory allocators

nDPI can use application-provided allocators via `ndpi_set_memory_alloction_functions()` (see `ndpi_api.h` / `ndpi_memory.c`). **Every pointer obtained through `ndpi_malloc()`, `ndpi_calloc()`, `ndpi_strdup()`, APIs that allocate internally (e.g. `ndpi_init_bin()`), or memory owned by the library must be released with the matching `ndpi_free()` path that uses the same allocator configuration as at allocation time.**

ndpiReader installs its hooks in **`ndpiReader_install_memory_hooks()`**, which is called from **`main()` immediately after the API version check** and **before**:

- `parseOptions()` (CLI parsing uses `ndpi_strdup`, bins, etc.),
- internal unit tests (`run_unit_tests()` when enabled),
- early-exit paths such as `--protos-dump`, `-x` / host checks, `help()` / extcap setup (these call `ndpi_init_detection_module()` and related APIs),
- `init_doh_bins()` for DoH/DoT analysis.

That ordering avoids the bug where memory was allocated while hooks were still unset (library fallback to libc) and later freed after hooks pointed at custom wrappers, which is undefined behavior for non-trivial allocators.

### For your own application

1. Call `ndpi_set_memory_alloction_functions()` **once**, before **any** `ndpi_malloc` / `ndpi_init_detection_module` / other nDPI entry point that may allocate.
2. Do not change hooks after pointers may exist unless you fully control lifetimes and never mix allocators on the same pointer.
3. If you use `ndpi_strdup()` or similar from the public API, free with `ndpi_free()` under the same hook configuration.
