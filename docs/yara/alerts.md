# Alerts

Alert notifications are automatically sent via the sender specified by the `alert-via` option. The alert will contain any tag that was defined in the YARA rule. The following is an example of a YARA alert.

```
Possible malicious process, notepad.exe (8424), detected at 12 Oct 2020 18:33:58 CEST.

Rule matches
  Rule: FakeNotepad
  Namespace: default
  Meta: map[author:Usurper]
  Tags: [notepad]

Process information

Name: notepad.exe
PID: 8424
PPID: 8424
Comm: "C:\WINDOWS\system32\notepad.exe"
Cwd: C:\Users\nedo\
SID: ARCHRABBIT\nedo
Session ID: 1

Env:
  ALLUSERSPROFILE: C:\ProgramData
  APPDATA: C:\Users\nedo\AppData\Roaming
  COMPUTERNAME: ARCHRABBIT
  ComSpec: C:\WINDOWS\system32\cmd.exe
  CommonProgramFiles: C:\Program Files\Common Files
  CommonProgramFiles(x86): C:\Program Files (x86)\Common Files
  CommonProgramW6432: C:\Program Files\Common Files
  DriverData: C:\Windows\System32\Drivers\DriverData
  ERLANG_HOME: C:\Program Files\erl-23.0
  FPS_BROWSER_APP_PROFILE_STRING: Internet Explorer
  FPS_BROWSER_USER_PROFILE_STRING:  
  SESSIONNAME: Console
  SystemDrive: C:

Threads:
  ID: 888 IO prio: 2, Base prio: 8, Page prio: 5, Ustack base: f96af50000, Ustack limit: f96af3f000, Kstack base: ffff9982c4f1c000, Kstack limit: f96af3f000, Entrypoint: 7ff96cad3d60
  ID: 7084 IO prio: 2, Base prio: 8, Page prio: 5, Ustack base: f96aed0000, Ustack limit: f96aebf000, Kstack base: ffff9982c45cd000, Kstack limit: f96aebf000, Entrypoint: 7ff7a0240110
  ID: 7492 IO prio: 2, Base prio: 8, Page prio: 5, Ustack base: f96b280000, Ustack limit: f96b26f000, Kstack base: ffff9982c4fc1000, Kstack limit: f96b26f000, Entrypoint: 7ff96cad3d60
  ID: 13496 IO prio: 2, Base prio: 8, Page prio: 5, Ustack base: f96afd0000, Ustack limit: f96afbf000, Kstack base: ffff9982c4518000, Kstack limit: f96afbf000, Entrypoint: 7ff96acdb0c0

Modules:
  Name: C:\Windows\System32\notepad.exe, Size: 204800, Checksum: 0, Base address: 7ff7a0220000, Default base address: 7ff7a0220000
  Name: C:\Windows\System32\ntdll.dll, Size: 2031616, Checksum: 0, Base address: 7ff96caa0000, Default base address: 7ff96caa0000
  Name: C:\Windows\System32\kernel32.dll, Size: 729088, Checksum: 0, Base address: 7ff96ab50000, Default base address: 7ff96ab50000
  Name: C:\Program Files\AVG\Antivirus\aswhook.dll, Size: 73728, Checksum: 0, Base address: 7ff94baa0000, Default base address: 7ff94baa0000 Name: C:\Windows\System32\KernelBase.dll, Size: 2764800, Checksum: 0, Base address: 7ff969d00000, Default base address: 7ff969d00000
  Name: C:\Windows\System32\gdi32.dll, Size: 155648, Checksum: 0, Base address: 7ff96c080000, Default base address: 7ff96c080000
  Name: C:\Windows\System32\win32u.dll, Size: 135168, Checksum: 0, Base address: 7ff96ab20000, Default base address: 7ff96ab20000
  Name: C:\Windows\System32\gdi32full.dll, Size: 1654784, Checksum: 0, Base address: 7ff96a880000, Default base address: 7ff96a880000
  Name: C:\Windows\System32\msvcp_win.dll, Size: 647168, Checksum: 0, Base address: 7ff96a060000, Default base address: 7ff96a060000
  Name: C:\Windows\System32\ucrtbase.dll, Size: 1024000, Checksum: 0, Base address: 7ff96aa20000, Default base address: 7ff96aa20000
  Name: C:\Windows\System32\user32.dll, Size: 1654784, Checksum: 0, Base address: 7ff96b8b0000, Default base address: 7ff96b8b0000
  Name: C:\Windows\System32\msvcrt.dll, Size: 647168, Checksum: 0, Base address: 7ff96c880000, Default base address: 7ff96c880000
  Name: C:\Windows\System32\combase.dll, Size: 3366912, Checksum: 0, Base address: 7ff96ac40000, Default base address: 7ff96ac40000
  Name: C:\Windows\System32\rpcrt4.dll, Size: 1179648, Checksum: 0, Base address: 7ff96bc60000, Default base address: 7ff96bc60000
  Name: C:\Windows\System32\bcryptprimitives.dll, Size: 524288, Checksum: 0, Base address: 7ff969a30000, Default base address: 7ff969a30000 Name: C:\Windows\System32\SHCore.dll, Size: 692224, Checksum: 0, Base address: 7ff96b6b0000, Default base address: 7ff96b6b0000
  Name: C:\Windows\System32\advapi32.dll, Size: 667648, Checksum: 0, Base address: 7ff96bbb0000, Default base address: 7ff96bbb0000
  Name: C:\Windows\System32\sechost.dll, Size: 618496, Checksum: 0, Base address: 7ff96b610000, Default base address: 7ff96b610000

Handles:
  Num: 4 Type: Event, Name: , Object: 0x0, PID: 8424 Num: 12 Type: Event, Name: , Object: 0x0, PID: 8424
  Num: 16 Type: WaitCompletionPacket, Name: , Object: 0x0, PID: 8424
  Num: 20 Type: IoCompletion, Name: , Object: 0x0, PID: 8424
  Num: 24 Type: TpWorkerFactory, Name: , Object: 0x0, PID: 8424
  Num: 28 Type: IRTimer, Name: , Object: 0x0, PID: 8424
  Num: 32 Type: WaitCompletionPacket, Name: , Object: 0x0, PID: 8424
  Num: 36 Type: IRTimer, Name: , Object: 0x0, PID: 8424
  Num: 40 Type: WaitCompletionPacket, Name: , Object: 0x0, PID: 8424
  Num: 56 Type: Directory, Name: \KnownDlls, Object: 0x0, PID: 8424
  Num: 60 Type: Event, Name: , Object: 0x0, PID: 8424 Num: 64 Type: Event, Name: , Object: 0x0, PID: 8424
  Num: 80 Type: ALPC Port, Name: , Object: 0x0, PID: 8424 Num: 96 Type: Key, Name: HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Nls\Sorting\Versions, Object: 0x0, PID: 8424
  Num: 108 Type: Key, Name: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options, Object: 0x0, PID: 8424
  Num: 112 Type: Mutant, Name: , Object: 0x0, PID: 8424
  Num: 116 Type: Event, Name: , Object: 0x0, PID: 8424
  Num: 120 Type: IoCompletion, Name: , Object: 0x0, PID: 8424
  Num: 124 Type: WindowStation, Name: \Sessions\1\Windows\WindowStations\WinSta0, Object: 0x0, PID: 8424
  Num: 128 Type: Desktop, Name: \Default, Object: 0x0, PID: 8424
  Num: 132 Type: WindowStation, Name: \Sessions\1\Windows\WindowStations\WinSta0, Object: 0x0, PID: 8424
  Num: 144 Type: Key, Name: HKEY_LOCAL_MACHINE, Object: 0x0, PID: 8424 Num: 152 Type: Event, Name: , Object: 0x0, PID: 8424 Num: 160 Type:

Entrypoint: 20110
Image base: 140000000
Build date: 2028-08-09 02:09:05 +0000 UTC
Number of symbols: 0
Number of sections: 7
Sections:
  Name: .text, Size: 132608, Entropy: 0.000000, Md5:
  Name: .rdata, Size: 35840, Entropy: 0.000000, Md5:
  Name: .data, Size: 3072, Entropy: 0.000000, Md5:
  Name: .pdata, Size: 4096, Entropy: 0.000000, Md5:
  Name: .didat, Size: 512, Entropy: 0.000000, Md5:
  Name: .rsrc, Size: 3072, Entropy: 0.000000, Md5:
  Name: .reloc, Size: 1024, Entropy: 0.000000, Md5:
Resources:
  CompanyName: Microsoft Corporation
  FileDescription: Notepad
  FileVersion: 10.0.18362.693 (WinBuild.160101.0800)
  InternalName: Notepad
  LegalCopyright: © Microsoft Corporation. All rights reserved. 
  OriginalFilename: NOTEPAD.EXE
  ProductName: Microsoft® Windows® Operating System
  ProductVersion: 10.0.18362.693
```
