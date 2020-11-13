# pangineDSM-import

The APIs and data structures for Pangine disassembler project to get, read, and output (in capnp) information from a third-party disassembler

The project presently contains Ghidra scripts to generate function start addresses.

You do *NOT* need to manually install this repo if you are using other Golang projects that reference this repo.

------------------------------
To install:
```bash
go get -u github.com/pangine/pangineDSM-import/...
```

Create *ghidraScript/headlessLoc.txt* containing one line, which is the absolute address of Ghidra headless executable.

For example:
> /usr/homebrew/Caskroom/ghidra/9.1.2_PUBLIC,20200212/ghidra_9.1.2_PUBLIC/support/analyzeHeadless
