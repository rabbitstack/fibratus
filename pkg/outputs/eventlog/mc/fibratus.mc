;//************** Event categories ************
MessageId=1
SymbolicName=Registry
Language=English
Registry
.
MessageId=2
SymbolicName=File
Language=English
File
.
MessageId=3
SymbolicName=Network
Language=English
Network
.
MessageId=4
SymbolicName=Process
Language=English
Process
.
MessageId=5
SymbolicName=Thread
Language=English
Thread
.
MessageId=6
SymbolicName=Image
Language=English
Image
.
MessageId=7
SymbolicName=Handle
Language=English
Handle
.
MessageId=8
SymbolicName=Other
Language=English
Other
.
MessageId=9
SymbolicName=Other
Language=English
Memory
.

;//*********** Event types **************
MessageId=15
SymbolicName=CreateProcess
Language=English
CreateProcess creates a new process and its primary thread.
.
MessageId=16
SymbolicName=TerminateProcess
Language=English
TerminateProcess terminates the process and all of its threads.
.
MessageId=17
SymbolicName=OpenProcess
Language=English
OpenProcess opens the process handle.
.
MessageId=18
SymbolicName=LoadImage
Language=English
LoadImage loads the module into the address space of the calling process.
.
MessageId=19
SymbolicName=Connect
Language=English
Connect establishes a connection to the socket.
.
MessageId=20
SymbolicName=CreateFile
Language=English
CreateFile creates or opens a file or I/O device.
.
MessageId=21
SymbolicName=RegDeleteKey
Language=English
RegDeleteKey removes the registry key.
.
MessageId=22
SymbolicName=RegDeleteValue
Language=English
RegDeleteValue removes the registry value.
.
MessageId=23
SymbolicName=RegCreateKey
Language=English
RegCreateKey creates a registry key or opens it if the key already exists.
.
MessageId=24
SymbolicName=RegSetValue
Language=English
RegSetValue sets the data for the value of a registry key.
.
MessageId=25
SymbolicName=CreateHandle
Language=English
CreateHandle creates a new handle object.
.
MessageId=26
SymbolicName=DeleteFile
Language=English
DeleteFile removes the file from the file system.
.
MessageId=27
SymbolicName=CreateThread
Language=English
CreateThread creates a local/remote thread to execute within the virtual address space of the process.
.
MessageId=28
SymbolicName=TerminateThread
Language=English
TerminateThread terminates a thread within the process.
.
MessageId=29
SymbolicName=OpenThread
Language=English
OpenThread opens the thread handle.
.
MessageId=30
SymbolicName=UnloadImage
Language=English
UnloadImage unloads the module from the address space of the calling process.
.
MessageId=31
SymbolicName=WriteFile
Language=English
WriteFile writes data to the file or I/O device.
.
MessageId=32
SymbolicName=ReadFile
Language=English
ReadFile reads data from the file or I/O device.
.
MessageId=33
SymbolicName=RenameFile
Language=English
RenameFile changes the file name.
.
MessageId=34
SymbolicName=CloseFile
Language=English
CloseFile closes the file handle.
.
MessageId=35
SymbolicName=SetFileInformation
Language=English
SetFileInformation sets the file meta information.
.
MessageId=36
SymbolicName=EnumDirectory
Language=English
EnumDirectory enumerates a directory or dispatches a directory change notification to registered listeners.
.
MessageId=37
SymbolicName=RegOpenKey
Language=English
RegOpenKey opens the registry key.
.
MessageId=38
SymbolicName=RegQueryKey
Language=English
RegQueryKey enumerates subkeys of the parent key.
.
MessageId=39
SymbolicName=RegQueryValue
Language=English
RegQueryValue reads the data for the value of a registry key.
.
MessageId=40
SymbolicName=Accept
Language=English
Accept accepts the connection request from the socket queue.
.
MessageId=41
SymbolicName=Send
Language=English
Send sends data over the wire.
.
MessageId=42
SymbolicName=Recv
Language=English
Recv receives data from the socket.
.
MessageId=43
SymbolicName=Disconnect
Language=English
Disconnect terminates data reception on the socket.
.
MessageId=44
SymbolicName=Reconnect
Language=English
Reconnect reconnects to the socket.
.
MessageId=45
SymbolicName=Retransmit
Language=English
Retransmit retransmits unacknowledged TCP
.
MessageId=46
SymbolicName=CloseHandle
Language=English
CloseHandle closes the handle object.
.
MessageId=47
SymbolicName=CloseKey
Language=English
CloseKey closes the registry key.
.
MessageId=49
SymbolicName=VirtualAlloc
Language=English
Reserves, commits, or changes the state of a region of memory within the process virtual address space.
.
MessageId=50
SymbolicName=VirtualFree
Language=English
Releases or decommits a region of memory within the process virtual address space.
.
MessageId=51
SymbolicName=MapViewFile
Language=English
Maps a view of a file mapping into the address space of a calling process.
.
MessageId=52
SymbolicName=UnmapViewFile
Language=English
Unmaps a mapped view of a file from the calling process's address space.
.
MessageId=53
SymbolicName=DuplicateHandle
Language=English
Duplicates handle.
.
MessageId=54
SymbolicName=DuplicateHandle
Language=English
Query DNS.
.
MessageId=55
SymbolicName=DuplicateHandle
Language=English
Receives DNS response.
.
