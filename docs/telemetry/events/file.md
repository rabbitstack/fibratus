# File Events

##### File events encompass a variety of file system related activities such as creating or opening directories/files/devices, writing or reading data, altering file metadata and so on.

### `CreateFile`

The `CreateFile` event is triggered when the kernel serves create/open requests for files or I/O devices. The most commonly used I/O devices are as follows: file, file stream, directory, physical disk, volume, console buffer, tape drive, communications resource, mailslot, and pipe. `CreateFile` events have the following parameters:

| PARAMETER  | DESCRIPTION |
| :---        |    :----   |
| `file_object` | File object pointer as seen from the kernel perspective. You can use this parameter to correlate file events. |
| `file_path` | File/directory path or device name, for example, `C:\ProgramData\AVG\Antivirus\psi.db-journal` |
| `irp` | I/O request packet value that identifies the file system activity. |
| `tid` | Thread identifier that initiated the I/O operation. |
| `create_disposition` | Identifies the file system operation performed on the file or device. Can be `SUPERSEDE` (replaces the file if it already exists, otherwise creates a new file), `OPEN` (opens the file if it exists), `CREATE` (creates a new file or fails if the file already exists), `OPENIF` (opens the file if it already exists, otherwise creates a new file), `OVERWRITE` (opens and overwrites the file if it already exists) and `OVERWRITEIF` (opens and overwrites the file if it already exists, otherwise creates a new file). |
| `create_options` | Options to be applied when creating or opening the file, as a compatible combination of the following values: `DIRECTORY_FILE`, `WRITE_THROUGH`, `SEQUENTIAL_ONLY`, `NO_INTERMEDIATE_BUFFERING`, `SYNCHRONOUS_IO_ALERT`, `SYNCHRONOUS_IO_NONALERT`, `NON_DIRECTORY_FILE`, `CREATE_TREE_CONNECTION`, `COMPLETE_IF_OPLOCKED`, `NO_EA_KNOWLEDGE`, `OPEN_REMOTE_INSTANCE`, `RANDOM_ACCESS`, `DELETE_ON_CLOSE`,`OPEN_BY_FILE_ID`, `FOR_BACKUP_INTENT`, `NO_COMPRESSION`, `OPEN_REQUIRING_OPLOCK`,`DISALLOW_EXCLUSIVE`, `RESERVE_OPFILTER`, `OPEN_REPARSE_POINT`, `OPEN_NO_RECALL` and `OPEN_FOR_FREE_SPACE_QUERY` |
| `share_mask` | Specifies the sharing mode of the file or device, which can be the combination of `READ`, `WRITE`, and `DELETE` values. This flag determines the permission granularity which enables a process to share a file or device while another process has the file or device open. |
| `type` | Idefines the file type. Possible values are `File`, `Directory`, `Pipe`, `Console`, `Mailslot`, `Other`, `Unknown` |
| `attributes` | Denotes the file attributes. Possible values are `READONLY`, `HIDDEN`, `SYSTEM`, `DIRECTORY`, `COMPRESSED`, `ENCRYPTED`, `JUNCTION`, `SPARSE`,`TEMPORARY`, `DEVICE`, `NORMAL`, `OFFLINE`, `UNINDEXED`, `STREAM`, `VIRTUAL`, `NOSCRUB`, `RECALLOPEN`, `RECALLACCESS`, `PINNED`, `UNPINNED`, `UNKNOWN` |
| `status` | Represents the system status message, for example, `Success` |


### `WriteFile` `ReadFile`

`WriteFile` and `ReadFile` events occur when a process writes data to a file or reads data from the file or I/O device respectively. They contain the following parameters:

| PARAMETER  | DESCRIPTION |
| :---        |    :----   |
| `file_object` | File object pointer as seen from the kernel perspective. You can use this parameter to correlate file events. |
| `file_path` | Represents the file/directory or device name the data is written to or read from. |
| `irp` | I/O request packet value that identifies the file system activity. |
| `io_size` | Specifies the number of bytes read or written. |
| `offset` | Offset in the file where the data is read or written. |
| `type` | Defines the file type. Possible values include `File`, `Directory`, `Pipe`, `Console`, `Mailslot`, `Other`, `Unknown` |


### `DeleteFile` `RenameFile` `CloseFile`

`DeleteFile` is fired when the file is removed from the file system. `RenameFile` signals file or directory renaming. `CloseFile` fires when file handle is closed. These events share the following parameters:

| PARAMETER  | DESCRIPTION |
| :---        |    :----   |
| `file_object` | File object pointer as seen from the kernel perspective. You can use this parameter to correlate file events. |
| `file_path` | Represents the file path/directory involved in the operation. |
| `irp` | I/O request packet value that identifies the file system activity. |
| `type` | Defines the file type. Possible values include `File`, `Directory`, `Pipe`, `Console`, `Mailslot`, `Other`, `Unknown` |


### `SetFileInformation`

`SetFileInformation` is published when the file metadata are manipulated for the given information class. The event contains the following parameters:

| PARAMETER  | DESCRIPTION |
| :---        |    :----   |
| `class` | File information class. For example, the `Basic` information class means the process altered file timestamps or basic attributes. Refer to [this](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_file_information_class) link for a full list of the file information class enumerations. |
| `file_object` | File object pointer as seen from the kernel perspective. |
| `file_path` | Represents the file whose information class is manipulated. |
| `irp` | I/O request packet value that identifies the file system activity. |
| `type` | Defines the file type. Possible values include `File`, `Pipe`, `Mailslot`, `Other`, `Unknown` |


### `EnumDirectory`

The `EnumDirectory` event is triggered in response to directory enumeration requests. The event has the following parameters:

| PARAMETER  | DESCRIPTION |
| :---        |    :----   |
| `dir` | Specifies the directory that was requested for enumeration. |
| `file_path` | Pattern for directory enumeration, for example, `*` |
| `class` | Identifies the requested directory enumeration class. |
| `file_object` | File object pointer as seen from the kernel perspective. |
| `irp` | I/O request packet value that identifies the file system activity. |
