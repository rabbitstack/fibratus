Fibratus
========

![alt text]( https://github.com/rabbitstack/fibratus/blob/master/fibratus.png "fibratus logo" )

**NOT YET RELEASED**

**Fibratus** is a tool which is able to capture the most of the Windows kernel activity - process/thread creation and termination, 
file system I/O, registry, network activity, DLL loading/unloading and much more. 
Fibratus has a very simple CLI which encapsulates the machinery to start the kernel event stream collector, 
set kernel event filters or run the lightweight Python modules called **filaments**. You can use filaments to extend Fibratus with your own arsenal of tools.

## Running Fibratus

Fibratus is composed of a single binary which can be run from terminal console. Although default Windows console would suffice, for better user experience a more sophisticated terminal emulators like [ConEmu](https://conemu.github.io) or [Cmder](http://cmder.net) are recommended. Run `fibratus --help` for usage instructions.

```
Usage:
    fibratus run ([--filament=<filament>] | [--filters <kevents>...])
    fibratus list-kevents
    fibratus list-filaments
    fibratus -h | --help
    fibratus --version

Options:
    -h --help                 Show this screen.
    --filament=<filament>     Specify the filament to execute.
    --version                 Show version.
```
To capture all of the supported kernel events issue `fibratus run` command without any argument.

```
5550 20:28:14.882000 3 cmd.exe (4396) - UnloadImage (base=0x77950000, checksum=1313154, image=ntdll.dll, path=\Device\HarddiskVolume2\Windows\SysWOW64\ntdll.dll, pid=4396, size=1536.0)
5551 20:28:14.882000 3 erl.exe (2756) - TerminateProcess (comm=C:\Windows\system32\cmd.exe /cdir /-C /W c:/Users/Nedo/AppData/Roaming/RabbitMQ/db/rabbit@NEDOPC-mnesia, exe=C:\Windows\system32\cmd.exe, name=cmd.exe, pid=4396, ppid=2756)
5552 20:28:14.882000 3 erl.exe (2756) - CloseFile (file=\Device\HarddiskVolume2\Windows, tid=1672)
5631 20:28:17.286000 2 taskmgr.exe (3532) - RegQueryKey (hive=REGISTRY\MACHINE\SYSTEM, node=ControlSet001\Control\Nls\Locale, pid=3532, status=0, tid=4324)
5632 20:28:17.286000 2 taskmgr.exe (3532) - RegOpenKey (hive=REGISTRY\MACHINE\SYSTEM, node=ControlSet001\Control\Nls\Locale\Software\Microsoft\DirectUI, pid=3532, status=3221225524, tid=4324)
5633 20:28:17.288000 2 taskmgr.exe (3532) - CreateFile (file=\Device\HarddiskVolume2\Windows\system32\xmllite.dll, file_type=REPARSE_POINT, operation=OPEN, share_mask=rwd, tid=4324)
5634 20:28:17.288000 2 taskmgr.exe (3532) - CloseFile (file=\Device\HarddiskVolume2\Windows\system32\xmllite.dll, tid=4324)
5635 20:28:17.288000 2 taskmgr.exe (3532) - CreateFile (file=\Device\HarddiskVolume2\Windows\system32\xmllite.dll, file_type=FILE, operation=OPEN, share_mask=r-d, tid=4324)
5636 20:28:17.288000 2 taskmgr.exe (3532) - LoadImage (base=0x7fefab90000, checksum=204498, image=xmllite.dll, path=\Windows\System32\xmllite.dll, pid=3532, size=217088)
5637 20:28:17.288000 2 taskmgr.exe (3532) - CloseFile (file=\Device\HarddiskVolume2\Windows\system32\xmllite.dll, tid=4324)
5638 20:28:17.300000 2 taskmgr.exe (3532) - RegQueryKey (hive=REGISTRY\MACHINE\SYSTEM, node=ControlSet001\Control\Nls\Locale\, pid=3532, status=0, tid=4324)
5639 20:28:17.300000 2 taskmgr.exe (3532) - RegOpenKey (hive=REGISTRY\MACHINE\SYSTEM, node=ControlSet001\Control\Nls\Locale\SOFTWARE\Microsoft\CTF\KnownClasses, pid=3532, status=3221225524, tid=4324)
5640 20:28:17.300000 3 taskmgr.exe (3532) - RegQueryKey (hive=REGISTRY\MACHINE\SYSTEM, node=ControlSet001\Control\Nls\Locale\, pid=3532, status=0, tid=4324)
5641 20:28:17.300000 3 taskmgr.exe (3532) - RegOpenKey (hive=REGISTRY\MACHINE\SYSTEM, node=ControlSet001\Control\Nls\Locale\SOFTWARE\Microsoft\CTF\KnownClasses, pid=3532, status=3221225524, tid=4324)
5642 20:28:17.302000 2 taskmgr.exe (3532) - UnloadImage (base=0x7fefab90000, checksum=204498, image=xmllite.dll, path=\Windows\System32\xmllite.dll, pid=3532, size=212.0)
````
