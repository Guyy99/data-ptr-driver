kDriver written by Guy.-.#9302

Features:
- KM/UM communication use a .DATA ptr swap to hook a function in win32kbase.sys that can be called from UM.
- Can Get Process ID, Get Module Base, Get PEB and Read/Write memory on processes in the UM.
- Can scan for patterns, get module base of drivers, and write to read-only memory in the KM.
- Also includes the Driver class that you would put in your UM process in order to return desired information from UM.

