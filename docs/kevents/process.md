# Process events

#### CreateProcess and TerminateProcess

Process events are fired up as a stimulus to the process' life-cycle changes. When the kernel puts into motion a process or terminates it, the `CreateProcess` and `TerminateProcess` events are emitted respectively. The following list summarizes all the distinct event parameters that are associated with process events.

- `pid` is the process' identifier. This value is valid from the time a process is created until it is terminated.
- `tid` is the thread identifier inside process address space that generated the event.
- `ppid` represents the parent identifier of the child process. Process identifier numbers are reused, so they only identify a process for the lifetime of that process. It is possible that the process identified by `ppid` is terminated, so `ppid` may not refer to a running process. It is also possible that `ppid` incorrectly refers to a process that reuses a process identifier.
- `real_ppid` is the process identifier useful for detecting process spoofing.
- `name` is the process' image name including file extension (e.g. `cmd.exe`).
- `cmdline` is the full process' command line (e.g. `C:\Windows\system32\cmd.exe /cdir /-C /W`).
- `exe` is the full name of the process' executable (e.g. `C:\Windows\system32\cmd.exe`)
- `sid` is the security identifier under which this process is run. (e.g. `S-1-5-18`)
- `kproc` represents the address of the process object in the kernel.
- `directory_table_base` represents the address of the directory table that holds process' memory page mappings.
- `session_id` is the unique identifier for the current session under which process was started or terminated.
- `status` is the exit status of the started/stopped process.
- `start_time` designates the instant when the process was started.
- `domain` represents the domain name under which the process is started.
- `username` represents the username that started the process.

#### OpenProcess

`OpenProcess` event is triggered when a process tries to acquire an existing local process object. This event contains the following parameters:

- `desired_access` is the hexadecimal value that represents the desired access to the process object.
- `desired_access_names` is the list of human-readable desired access strings (e.g. `TERMINATE,QUERY_INFORMATION`). For a full list and detailed explanation of available access rights, head to the official [docs](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights).
- `name` is the name of the local process that was opened.
- `exe` is the full path of the local process object that was open.
- `pid` is the identifier of the local process that was opened.
- `status` contains the result of the process object open operation. (e.g. `Success`)

### Process state  {docsify-ignore}

Fibratus keeps a snapshot of all running processes including their state such as basic process attributes, allocated file handles, dynamically-linked libraries, PE (Portable Executable) metadata and other resources. The snapshot is updated dynamically as processes get spawn or die. Each time a kernel event is triggered, its process' state is fetched from the snapshot and attached to the event. This state machine semantically enriches each individual event with the aim on providing a powerful context for [filtering](/filters/introduction.md) and [scripting](/filaments/introduction.md).

Process state comprises the following attributes and resources:

- process name
- process identifier as well as its parent process identifier
- process command line
- current working directory
- process SID
- session identifier
- environment variables
- threads
- modules
- handles
- PE metadata
