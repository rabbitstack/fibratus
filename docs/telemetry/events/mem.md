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

#### MapViewFile

Maps a view of a file mapping into the process address space. These events contain the following parameters:

- `file_key` is the address of the file object for which the mapping is performed.
- `offset` represents the file offset where the view is to begin.
- `pid` is the process identifier where the file mapping is performed.
- `protection` specifies the page protection of the file mapping object. Can be the compatible combination of the following values: `READONLY`, `EXECUTE`, `EXECUTE_READ`, `READWRITE`, `WRITECOPY`, `NOCACHE`, `EXECUTE_WRITECOPY` and `EXECUTE_READWRITE`. 
- `section_type` describes the type of the mapped section. It can be `DATA`, `IMAGE`, `IMAGE_NO_EXECUTE`, `PAGEFILE` or `PHYSICAL`. 
- `view_base` is the base memory address in the process address space where mapping begins.
- `view_size` represents the number of bytes of a file mapping to map to a view.

#### UnmapViewFile

Unmaps a mapped view of a file from the process's virtual address space.

- `file_key` is the address of the file object for which the unmapping is performed.
- `offset` represents the file offset where the view to unmap begins.
- `pid` is the process identifier where the file unmapping is performed.
- `protection` specifies the page protection of the file mapping object that is being unmapped. Can be the compatible combination of the following values: `READONLY`, `EXECUTE`, `EXECUTE_READ`, `READWRITE`, `WRITECOPY`, `NOCACHE`, `EXECUTE_WRITECOPY` and `EXECUTE_READWRITE`. 
- `section_type` describes the type of the unmapped section. It can be `DATA`, `IMAGE`, `IMAGE_NO_EXECUTE`, `PAGEFILE` or `PHYSICAL`. 
- `view_base` is the base memory address in the process address space where unmapping begins.
- `view_size` represents the number of bytes of a file mapping to unmap.
