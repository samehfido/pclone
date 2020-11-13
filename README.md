# pclone (Process Cloning)

pclone is small project designed to clone running processes. The cloning does not clone threads nor handles, it does however clone all virtual memory. 
It does this by swapping dirbase in the clones EPROCESS structure. It also swaps the PEB in the EPROCESS structure so the clone will list the same loaded modules
as the cloned process.