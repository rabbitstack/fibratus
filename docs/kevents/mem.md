# Memory events

Memory events include reserving, committing, or freeing the state of a region of pages in the virtual process address space.

#### VirtualAlloc

Allocates, commits, or changes the state of a region of pages in the virtual address space. If the `pid` parameter is different than the calling process id, memory allocation is performed in the address space of another process. `VirtualAlloc` events carry the following parameters:

- `alloc_type` designates the type of memory allocation. It can be the combination of `COMMIT`, `RESERVE`, `RESET`, `RESET_UNDO`, `PHYSICAL`, `LARGE_PAGES`, `TOP_DOWN`, and `WRITE_WATCH`.
- `base_address` is the starting address of the allocated region.
- `page_type` represents the type of pages in the allocated region. It can be one of `IMAGE`, `MAPPED`, or `PRIVATE`.
- `protection` designates the memory protection for the region of allocated pages. It can be the combination of `EXECUTE`, `EXECUTE_READ`, `EXECUTE_READWRITE`, `EXECUTE_WRITECOPY`, `NOACCESS`, `READONLY`, `READWRITE`, `WRITECOPY`, `TARGETS_INVALID`, `TARGETS_NO_UPDATE`, `GUARD`, `NOCACHE`, and `WRITECOMBINE`. 
- `protection_mask` is an abbreviated form of the pages protection flag. e.g. `RWX`
- `region_size` is the size of the allocated region in bytes.
- `pid`, `exe`, `name` represent process identifier, process executable path, and the image name of the process into which the region is allocated.

#### VirtualFree

Releases, decommits, or releases and decommits a region of pages within the virtual process address space. If the `pid` parameter is different than the calling process id, memory release is performed in the address space of another process. `VirtualFree` events contain the following parameters:

- `alloc_type` designates the type of free operation that can be `DECOMMIT` or `RELEASE`.
- `base_address` is the base address of the region of pages to be freed.
- `region_size` represents the size of the region of memory to be freed, in bytes.
- `pid`, `exe`, `name` represent process identifier, process executable path, and the image name of the process for which the pages are freed.
