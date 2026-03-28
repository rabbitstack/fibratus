# Quick start

By default, Fibratus operates in rule engine mode. It loads the rule set from the `%PROGRAM FILES%\Fibratus\Rules` directory and sends security alerts to [Eventlog](/alerts/senders/eventlog) or other configurable [sinks](/alerts/senders). Optionally, it takes response actions when the rule is fired, such as killing the process. To see Fibratus in action, we can trigger a rule by performing the following actions:

- spin up a command line prompt
- list credentials from the vault by using the `VaultCmd` tool
```
$ VaultCmd.exe /listcreds:"Windows Credentials" /all
```

- `Credential discovery via VaultCmd tool` rule should trigger displaying the alert in the Eventlog `Application` channel.

To learn more about detection rules, head to [rules](/filters/rules).

### Event forwarding 

To start forwarding events to [output](/outputs/introduction) sinks, run Fibratus from the command line in event forwarding mode:

```
$ fibratus service stop
$ fibratus run --forward
```

The continuous stream of events will start rendering on the console.

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

The console output is the default events output, even though you can route the event flow to [Elasticsearch](https://www.elastic.co/elasticsearch/) or [RabbitMQ](https://www.rabbitmq.com/) sinks, just to name a few. [Learn](/outputs/introduction) more about output sinks.

To stop Fibratus, hit the `Ctr-C` key combination.
