# Bypass-ASLR
Bypass ONLY ASLR and NX using GOT and PLT

Bypass writed in python2 with pwntools, 80% commented, obs: x64
Compile with: gcc elf.c -o elf -fno-stack-protector -z execstack -no-pie -w
respectively: disable stack cookie (Canary), disable stack protector (NX), disable instructions randomization, does not show warning messages
libc used: /usr/lib/libc.so.6

Dependencies:
pip2 install pwntools

Obs: 
if your os uses another libc redo the address calculations
we bypass NX too for not sending any raw shellcode on the stack
