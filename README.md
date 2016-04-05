**NOT YET RELEASED**

**Fibratus** is a tool which is able to capture the most of the Windows kernel activity - process/thread creation and termination, 
file system I/O, registry, network activity, DLL loading/unloading and much more. 
Fibratus has a very simple CLI which encapsulates the machinery to start the kernel event stream collector, 
set kernel event filters or run the lightweight Python modules called **filaments**. You can use filaments to extend Fibratus with your own arsenal of tools.

#### Running Fibratus

Fibratus is composed of a single binary which can be run from terminal console. Although default Windows console would suffice, for better user experience a more sophisticated terminal emulators like (https://conemu.github.io)[ConEmu] or (http://cmder.net)[Cmder] are recommended.
