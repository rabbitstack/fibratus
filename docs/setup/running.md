# Running

### Permission requirements {docsify-ignore}

Fibratus requires **administrator** privileges to start/stop ETW sessions. During execution, Fibratus performs the following operations on your system:

- takes a snapshot of allocated system handles. You can control this option through [configuration](/kevents/handle?id=handle-state) flags
- periodically writes the current event sequence into volatile registry value
- writes logs to disk. The default logs directory location is `%PROGRAMFILES%\Fibratus\Logs`
- grants the `SeDebugPrivilege` to its process token. However, you can disable granting this privilege by setting the `debug-privilege` option to `false`
- transports kernel events over the wire when non-console output is active
- inspects process image [PE](/pe/introduction.md) metadata. Again, you can disable this feature through [config](/pe/introduction) file
- executes [YARA](/yara/introduction.md) rules on freshly created process images or other image files when the [YARA scanner](/yara/introduction) is enabled
- spins up an embedded Python interpreter to run [filaments](/filaments/introduction)

### Resource overhead {docsify-ignore}

The resource utilization greatly depends on the type of workloads, the amount of data collected by Fibratus, and the output sink responsible for transporting events. Some benchmarks were performed with Fibratus and Elasticsearch running on the same machine along with other userspace processes. Since ingesting non-trivial amount of data puts a strain on the file system (writing and merging of the Lucene segments) and the network I/O, this was a perfect scenario for stressing out Fibratus. All kernel events, except handle events, were captured and shipped to Elasticsearch. The following resource utilization was recorded:

- 3-6% single CPU core
- ~170 MB memory usage

### Standalone binary {docsify-ignore}

To start collecting kernel events, you can run Fibratus from the command line:

```
$ fibratus run
```

The continuous stream of kernel events will start rendering on the console.

```
  ...
681951 2020-11-07 14:24:57.1839809 +0100 CET - 2 cmd.exe (6328) - CreateFile (file_name➜ C:\WINDOWS\system32\config\systemprofile\AppData\Local\Microsoft\WindowsApps\, file_object➜ ffffa88c7ea077d0, irp➜ ffffa88c746b2a88, operation➜ supersede, share_mask➜ rw-, type➜ directory)
681952 2020-11-07 14:24:57.1840451 +0100 CET - 2 cmd.exe (6328) - RegOpenKey (key_handle➜ 0, key_name➜ HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore, status➜ key not found)
681953 2020-11-07 14:24:57.1840626 +0100 CET - 2 cmd.exe (6328) - RegOpenKey (key_handle➜ 0, key_name➜ HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\StateSeparation\RedirectionMap\Keys, status➜ key not found)
681954 2020-11-07 14:24:57.1840751 +0100 CET - 2 cmd.exe (6328) - RegOpenKey (key_handle➜ 0, key_name➜ HKEY_LOCAL_MACHINE\Software\Microsoft\LanguageOverlay\OverlayPackages\en-US, status➜ key not found)
681955 2020-11-07 14:24:57.1841104 +0100 CET - 2 cmd.exe (6328) - CreateFile (file_name➜ C:\WINDOWS\system32\en-US\cmd.exe.mui, file_object➜ ffffa88c7ea077d0, irp➜ ffffa88c746b2a88, operation➜ open, share_mask➜ r-d, type➜ directory)
681956 2020-11-07 14:24:57.1848044 +0100 CET - 2 cmd.exe (6328) - TerminateThread (base_prio➜ 8, entrypoint➜ 7ff7762382b0, io_prio➜ 2, kstack➜ fffff10cf0785000, kstack_limit➜ fffff10cf077e000, page_prio➜ 5, pid➜ 6328, tid➜ 11716, ustack➜ d020700000, ustack_limit➜ d020604000)
681957 2020-11-07 14:24:57.1848713 +0100 CET - 2 cmd.exe (6328) - UnloadImage (base_address➜ 7ff776220000, default_address➜ 7ff776220000, file_name➜ C:\Windows\System32\cmd.exe, image_size➜ 413696, pid➜ 6328)
681958 2020-11-07 14:24:57.1848779 +0100 CET - 2 cmd.exe (6328) - UnloadImage (base_address➜ 7fffaaba0000, default_address➜ 7fffaaba0000, file_name➜ C:\Program Files\AVG\Antivirus\aswhook.dll, image_size➜ 73728, pid➜ 6328)
681959 2020-11-07 14:24:57.1848954 +0100 CET - 2 cmd.exe (6328) - UnloadImage (base_address➜ 7fffc97a0000, default_address➜ 7fffc97a0000, file_name➜ C:\Windows\System32\KernelBase.dll, image_size➜ 2764800, pid➜ 6328)
681967 2020-11-07 14:24:57.184997 +0100 CET - 2 erl.exe (5236) - TerminateProcess (comm➜ C:\WINDOWS\system32\cmd.exe /c handle.exe /accepteula -s -p 5236 2> nul, directory_table_base➜ 2300cb000, exe➜ C:\WINDOWS\system32\cmd.exe, exit_status➜ 1, kproc➜ ffffa88c70ee7080, name➜ cmd.exe, pid➜ 6328, ppid➜ 5236, session_id➜ 0, sid➜ NT AUTHORITY\SYSTEM)
681968 2020-11-07 14:24:57.1853111 +0100 CET - 2  (6328) - RegOpenKey (key_handle➜ ffffc980980b55f0, key_name➜ HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\bam\State\UserSettings\S-1-5-18, status➜ success)
681969 2020-11-07 14:24:57.1853224 +0100 CET - 2  (6328) - RegQueryValue (key_handle➜ ffffc980abd657d0, key_name➜ HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\bam\State\UserSettings\S-1-5-18\\Device\HarddiskVolume4\Windows\System32\cmd.exe, status➜ key not found)
681970 2020-11-07 14:24:57.1853581 +0100 CET - 5 aswidsagent.exe (7812) - CreateFile (file_name➜ C:\WINDOWS\SYSTEM32\CMD.EXE, file_object➜ ffffa88c7a8053e0, irp➜ ffffa88c7b711608, operation➜ open, share_mask➜ rw-, type➜ file)
681971 2020-11-07 14:24:57.185952 +0100 CET - 4 AVGSvc.exe (4000) - CreateFile (file_name➜ C:\ProgramData\AVG\Antivirus\psi.db-journal, file_object➜ ffffa88c7ea02500, irp➜ ffffa88c73ff8a88, operation➜ supersede, share_mask➜ rw-, type➜ directory)
681972 2020-11-07 14:24:57.1860706 +0100 CET - 4 AVGSvc.exe (4000) - ReadFile (file_name➜ C:\ProgramData\AVG\Antivirus\psi.db, file_object➜ ffffa88c72c7c260, io_size➜ 16, irp➜ ffffa88c73ff8a88, offset➜ 24, type➜ file)
  ...
```

Each line is comprised of the following fields:

- monotonic sequence value
- timestamp of event occurrence
- CPU where the event was captured
- the process name and the pid that produced the event
- event type
- event parameters

A different [rendering template](/outputs/console?id=templates) can be used to customize the line format or you can opt to change the output format to, for example, JSON.

The console output is the default kernel events sink, even though you can route the kernel event flow to [Elasticsearch](https://www.elastic.co/elasticsearch/) or [RabbitMQ](https://www.rabbitmq.com/) sinks, just to name a few. [Learn](/outputs/introduction) more about output sinks.

To stop Fibratus, hit the `Ctr-C` key combination.

### Windows service {docsify-ignore}

If you prefer long-running jobs, you might consider running Fibratus as Windows Service. Execute the following command to register the instance of the Fibratus service within the Service Control Manager:

```
$ fibratus install-service
```

Now, it's time to start the Fibratus service:

```
$ fibratus start-service
```

If any errors occur during service startup, they we'll be logged to Windows Events Log. To stop the Fibratus service use the `fibratus stop-service` command. Service removal is accomplished through `fibratus remove-service` command.

## CLI {docsify-ignore}

Invoking the `fibratus` binary without any parameters reveals available CLI commands. You can obtain help information for each available command by appending the `--help` or `-h` option after the command name. Let's briefly describe available commands.

### run

The main command for bootstrapping Fibratus or running a filament. It accepts an optional filter expression. Examples:

- collect all events
  ```
  $ fibratus run
  ```

- run the `watch_files` filament
  ```
  $ fibratus run -f watch_files
  ```

- collect fs events originated from the `cmd.exe` process
  ```
  $ fibratus run kevt.category = 'file' and ps.name = 'cmd.exe'
  ```

- collect fs events and enable PE introspection
  ```
  $ fibratus run kevt.category = 'file' --pe.enabled=true
  ```

### capture

Dumps the kernel event flow to specialized kcap (capture) file. It accepts an optional filter expression. Examples:

- capture all events to `events.kcap` capture file
  ```
  $ fibratus capture -o events
  ```

- capture network events from the specific destination IP address
  ```
  $ fibratus capture kevt.category = 'net' and net.dip = 172.17.2.3 -o events
  ```

### replay

Replays the kernel event flow from the kcap file. It accepts an optional filter expression. Examples:

- replay all events from the `events.kcap` capture file
  ```
  $ fibratus replay -k events
  ```

- replay events that contain a specific resource name in the PE resource directory
  ```
  $ fibratus replay pe.resources[Company] contains 'blackwater' -k events
  ```

### config

Prints the options loaded from configuration sources including files, command line flags or environment variables. Sensitive data, such as passwords are  masked out.

### install-service

Installs the Fibratus service within the Windows Service Control Manager. If this command is successful, the Fibratus service will appear in the Windows Services Manager console.

### start-service

Starts the Fibratus service that was previously registered within the Windows Service Control Manager.

### stop-service

Stops the Fibratus Windows service.

### restart-service

Restarts the Fibratus Windows service.

### remove-service

Removes the Fibratus service from the Windows Service Control Manager.

### docs

Launches the default web browser and opens the Fibratus documentation site.

### list

The `list` command consists of various subcommands:

  * `filaments`: displays available filaments. Filaments live in the `%PROGRAMFILES\Fibratus\Filaments` directory, but you can override this location with the `--filament.path` flag or the corresponding key in the `yaml` configuration file.
  * `fields`: shows all [field names](/filters/fields) that can be used in filter expressions.
  * `kevents`: shows available kernel event types.

### stats

Returns the runtime metrics that are exposed through the [expvar](https://golang.org/pkg/expvar/) HTTP endpoint. Useful for debugging.

### version

Displays the Fibratus version along with the commit hash and the Go compiler version.
