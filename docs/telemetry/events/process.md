# Process Events

##### Process events are fired as a stimulus to the process life-cycle changes. When the kernel puts into motion a process or terminates it, the `CreateProcess` and `TerminateProcess` events are emitted respectively. `OpenProcess` event fires when the process attemps to acquire an existing local process object. The following sections summarize all the distinct event parameters that are associated with process events captured by **Fibratus**

### `CreateProcess` `TerminateProcess`

| PARAMETER  | DESCRIPTION |
| :---        |    :----   |
| `pid`      | Process identifier. This value is valid from the time a process is created until it is terminated.       |
| `tid`      | Thread identifier inside process address space that generated the event.       |
| `ppid` | Parent identifier of the child process. Process identifier numbers are reused, so they only identify a process for the lifetime of that process. It is possible that the process identified by `ppid` is terminated, so `ppid` may not refer to a running process. It is also possible that `ppid` incorrectly refers to a process that reuses a process identifier. |
| `real_ppid` | Real parent process identifier useful for detecting process spoofing. |
| `name` | Process name including file extension, for example, `cmd.exe` |
| `cmdline` | Full process command line, for example, `C:\Windows\system32\cmd.exe /cdir /-C /W`) |
| `exe` | Full name of the process executable, for example, `C:\Windows\system32\cmd.exe` |
| `sid` | Security identifier under which this process runs, for example, `S-1-5-18` |
| `kproc` | Represents the address of the `KPROCESS` object in the kernel. |
| `directory_table_base` | Represents the address of the directory table that holds process memory page mappings. |
| `session_id` | Unique identifier for the current session under which process was started or terminated. |
| `status` | Exit status of the started/stopped process. |
| `start_time` | Designates the instant when the process was started. Start time is available only in `CreateProcess` events. |
| `domain` | Represents the domain name under which the process is started. |
| `username` | Represents the username that started the process. |
| `flags` | Represents process creation flags. Can be `WOW64`, `PROTECTED`, or `PACKAGED` to designate 32-bit process is created in 64-bit Windows system,  process is to be run as a protected process, or a process packaged with the [MSIX](https://learn.microsoft.com/en-us/windows/msix/overview) technology respectively. |
| `token_integrity_level` | Process token integrity level. Can be `PROTECTED`, `SYSTEM`, `HIGH`, `MEDIUM`, `MEDIUM+`, `LOW` and `UNTRUSTED`. |
| `token_is_elevated` | Indicates if the process token is elevated. |
| `token_elevation_type` | Indicates the process token elevation type. Can be `FULL` or `LIMITED`. |

### `OpenProcess`

| PARAMETER  | DESCRIPTION |
| :---        |    :----   |
| `desired_access` | Value that represents the desired access bitmask to the process object. |
| `desired_access_names` | List of human-readable desired access strings, for example, `TERMINATE,QUERY_INFORMATION`. For a full list and detailed explanation of available access rights, head to the official [docs](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights). |
| `name` | Name of the local process that was opened. |
| `exe` | Full path of the local process object that was open. |
| `pid` | Process identifier of the local process that was opened. |
| `status` | System status of the open operation, for example, `Success` |

## Process state

Fibratus keeps a snapshot of all running processes including their state such as basic process attributes, allocated file handles, dynamically-linked libraries, PE (Portable Executable) metadata and other resources. The snapshot is updated dynamically as processes get spawn or die. Each time an event is captured, its **process state** is fetched from the snapshot and attached to the event. This state machine semantically enriches each individual event with the aim on providing a powerful context for [rules](/rulelang/), [filtering](/filters/introduction.md), and [scripting](/filaments/introduction.md).

Process state comprises the following attributes and resources:

- process name
- process identifier as well as its parent process identifier
- process command line
- current working directory
- process SID
- session identifier
- process token properties
- environment variables
- threads
- modules
- handles
- memory mappings
- PE metadata
