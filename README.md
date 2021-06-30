# Bypass-ASLR
Bypass ONLY ASLR and NX using GOT and PLT

Bypass writed in python2 with pwntools, 80% commented, obs: x64 <br/> 
Compile with: gcc elf.c -o elf -fno-stack-protector -z execstack -no-pie -w <br/> 
respectively: disable stack cookie (Canary), disable stack protector (NX), disable instructions randomization, does not show warning messages <br/> 
libc used: /usr/lib/libc.so.6 <br/> 

Enable ASLR: sudo sysctl kernel.randomize_va_space=1
0 - ASLR Disable
1 - ASLR partially enabled
2 - FULL ASLR (the exploit does not bypass this)

Dependencies:
pip2 install pwntools

Obs: 
if your os uses another libc redo the address calculations
we bypass NX too for not sending any raw shellcode on the stack
