# nDPI example tools

This directory contains sample programs that link against libnDPI, mainly **ndpiReader** (CLI over pcaps and live capture) and **ndpiSimpleIntegration**. DPDK-specific notes live in [README.DPDK](README.DPDK).

## Custom memory allocators

nDPI can use application-provided allocators via `ndpi_set_memory_alloction_functions()` (see `ndpi_api.h` / `ndpi_memory.c`). **Every pointer obtained through `ndpi_malloc()`, `ndpi_calloc()`, `ndpi_strdup()`, APIs that allocate internally (e.g. `ndpi_init_bin()`), or memory owned by the library must be released with the matching `ndpi_free()` path that uses the same allocator configuration as at allocation time.**
From a practical point of view, that means that the application code must installs its hooks once, via `ndpi_set_memory_alloction_functions()` **before ANY library functions**.

**IF** your own application wants to use `ndpi_malloc()` and similar functions also for its own allocations, `ndpi_set_memory_alloction_functions()` **must** be called before **ANY** allocations, from the library and from the application, both. All these memory must be freed via `ndpi_free()`.
