<div align="center">
    <img src="https://githacks.org/_xeroxz/pclone/-/raw/78ec8745ad117f42640063ef3bd10e5946f7ad6d/img/pclone-icon.png"/>
</div>

# pclone

pclone is small project designed to clone running processes. The cloning does not clone threads nor handles, it does however clone all virtual memory. 
It does this by swapping dirbase in the clones EPROCESS structure. It also swaps the PEB in the EPROCESS structure so the clone will list the same loaded modules
as the cloned process.

# usage

To make a `pclone_ctx` you must create a `vdm_ctx` and you must have a process id you want to clone. Once you have both of those you can clone a process.

```cpp
pclone_ctx clone_ctx(vdm, util::get_pid("notepad.exe"));

// clone_pid is the pid of the new clone process
// clone_handle is a PROCESS_ALL_ACCESS handle which you can
// use to call VirtualAllocEx, ReadProcessMemory, WriteProcessMemory... etc...
const auto [clone_pid, clone_handle] = clone_ctx.clone();
```

# example

As you can see here I clone notepad using a `RuntimeBroker.exe` as a dummy process to use as the clone. The loaded modules list the ones in notepad.exe and all the virtual memory is the same
as it is in notepad.exe

<img src="https://imgur.com/XDADPMA.png"/>