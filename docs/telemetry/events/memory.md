# Memory Events

##### Memory events include reserving, committing, or freeing the state of a region of pages, and also, mapping/unmapping the section view into/from the virtual process address space.

### `VirtualAlloc`

`VirtualAlloc` event is published in response to memory allocation of a region of pages in the virtual address space. If the `pid` parameter is different than the calling process id, memory allocation is performed in the address space of another process. `VirtualAlloc` events carry the following parameters:

| PARAMETER  | DESCRIPTION |
| :---        |    :----   |
| `alloc_type` | designates the type of memory allocation. It can be the combination of `COMMIT`, `RESERVE`, `RESET`, `RESET_UNDO`, `PHYSICAL`, `LARGE_PAGES`, `TOP_DOWN`, and `WRITE_WATCH` |
| `base_address` | Starting address of the allocated region. |
| `page_type` | Type of pages in the allocated region. It can be one of `IMAGE`, `MAPPED`, or `PRIVATE` |
| `protection` | Memory protection for the region of allocated pages. It can be the combination of `EXECUTE`, `EXECUTE_READ`, `EXECUTE_READWRITE`, `EXECUTE_WRITECOPY`, `NOACCESS`, `READONLY`, `READWRITE`, `WRITECOPY`, `TARGETS_INVALID`, `TARGETS_NO_UPDATE`, `GUARD`, `NOCACHE`, and `WRITECOMBINE` |
| `protection_mask` | Abbreviated form of the pages protection flag, for example, `RWX` |
| `region_size` | Size of the allocated region in bytes. |
| `pid` | Process identifier where the memory allocation occurs. |
| `exe` | Process executable path where the memory allocation occurs. |
| `name` | Process name where the memory allocation occurs. |

### `VirtualFree`

`VirtualFree`  event is captured when the memory manager releases, decommits, or releases and decommits a region of pages within the virtual process address space. If the `pid` parameter is different than the calling process id, memory release is performed in the address space of another process. `VirtualFree` events contain the following parameters:

| PARAMETER  | DESCRIPTION |
| :---        |    :----   |
| `alloc_type` | designates the type of a freed memory region. It can be the combination of `COMMIT`, `RESERVE`, `RESET`, `RESET_UNDO`, `PHYSICAL`, `LARGE_PAGES`, `TOP_DOWN`, and `WRITE_WATCH` |
| `base_address` | Starting address of the freed region. |
| `region_size` | Size of the freed region in bytes. |
| `pid` | Process identifier where the memory release occurs. |
| `exe` | Process executable path where the memory release occurs. |
| `name` | Process name where the memory release occurs. |


### `MapViewFile`

`MapViewFile` is published when the view of a file mapping is mapped into the process address space. This event contain the following parameters:

| PARAMETER  | DESCRIPTION |
| :---        |    :----   |
| `file_key` | Address of the file object for which the mapping is performed. |
| `offset` | File offset where the view is to begin. |
| `pid` | Process identifier where the file mapping is performed. |
| `protection` | Specifies the page protection of the file mapping object. Can be the compatible combination of the following values: `READONLY`, `EXECUTE`, `EXECUTE_READ`, `READWRITE`, `WRITECOPY`, `NOCACHE`, `EXECUTE_WRITECOPY` and `EXECUTE_READWRITE`
| `section_type` | Type of the mapped section. It can be `DATA`, `IMAGE`, `IMAGE_NO_EXECUTE`, `PAGEFILE` or `PHYSICAL` |
| `view_base` | Base memory address in the process address space where mapping begins. |
| `view_size` | Number of bytes of a file mapping to map to a view. |

### `UnmapViewFile`

`UnmapViewFile` trigger as a response to unmapping a mapped view of a file from the process's virtual address space. This event has the following parameters:

| PARAMETER  | DESCRIPTION |
| :---        |    :----   |
| `file_key` | Address of the file object for which the unmapping is performed. |
| `offset` | File offset where the view to unmap begins. |
| `pid` | Process identifier where the file unmapping is performed. |
| `protection` | specifies the page protection of the file mapping object that is being unmapped. Can be the compatible combination of the following values: `READONLY`, `EXECUTE`, `EXECUTE_READ`, `READWRITE`, `WRITECOPY`, `NOCACHE`, `EXECUTE_WRITECOPY` and `EXECUTE_READWRITE` |
| `section_type` | Type of the unmapped section. It can be `DATA`, `IMAGE`, `IMAGE_NO_EXECUTE`, `PAGEFILE` or `PHYSICAL` |
| `view_base` | Base memory address in the process address space where unmapping begins. |
| `view_size` | Number of bytes of a file mapping to unmap. |
