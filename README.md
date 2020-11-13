<div align="center">
    <img src="https://githacks.org/_xeroxz/pclone/-/raw/78ec8745ad117f42640063ef3bd10e5946f7ad6d/img/pclone-icon.png"/>
</div>

# pclone (Process Cloning)

pclone is small project designed to clone running processes. The cloning does not clone threads nor handles, it does however clone all virtual memory. 
It does this by swapping dirbase in the clones EPROCESS structure. It also swaps the PEB in the EPROCESS structure so the clone will list the same loaded modules
as the cloned process.