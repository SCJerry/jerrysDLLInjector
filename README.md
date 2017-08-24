# jerrysDLLInjector
a basic DLL injector created for learning purpose using WinAPI CreateRemoteThread(LoadLibraryA)

The principal of this injector is simple and can be summarize to the following steps:
1. Open the process
2. wirte the dll path into the process's memory space
3. remotely load the dll by creating a thread to that process (so basically like calling LoadLibraryA in that process)
4. DLL loaded (͡° ͜ʖ ͡°)
