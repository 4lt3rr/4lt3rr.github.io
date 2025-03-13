---
title: "[DREAMHACK] - seccomp"
published: 2025-03-12
description: ""
image: "../image.png"
tags:
  - PWN
category: "Wargame"
draft: true
---

# Description

>
> This problem is given the binary and source code of the service (seccomp) running on the server.
> Find a vulnerability in the program and obtain a shell by exploiting it, then read the “flag” file.
> You can earn points by verifying the contents of the “flag” file on the Wargame site.
> The format of the flag is DH {...} This is it.

# Analysis

Start with analysis the code

```c
// gcc -o seccomp seccomp.cq
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/unistd.h>
#include <linux/audit.h>
#include <sys/mman.h>

int mode = SECCOMP_MODE_STRICT;

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

int syscall_filter() {
    #define syscall_nr (offsetof(struct seccomp_data, nr))
    #define arch_nr (offsetof(struct seccomp_data, arch))

    /* architecture x86_64 */
    #define REG_SYSCALL REG_RAX
    #define ARCH_NR AUDIT_ARCH_X86_64
    struct sock_filter filter[] = {
        /* Validate architecture. */
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, arch_nr),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_NR, 1, 0),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
        /* Get system call number. */
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr),
        };

    struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
    .filter = filter,
        };
    if ( prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 ) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)\n");
        return -1;
        }

    if ( prctl(PR_SET_SECCOMP, mode, &prog) == -1 ) {
        perror("Seccomp filter error\n");
        return -1;
        }
    return 0;
}


int main(int argc, char* argv[])
{
    void (*sc)();
    unsigned char *shellcode;
    int cnt = 0;
    int idx;
    long addr;
    long value;

    initialize();

    shellcode = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    while(1) {
        printf("1. Read shellcode\n");
        printf("2. Execute shellcode\n");
        printf("3. Write address\n");
        printf("> ");

        scanf("%d", &idx);

        switch(idx) {
            case 1:
                if(cnt != 0) {
                    exit(0);
                }

                syscall_filter();
                printf("shellcode: ");
                read(0, shellcode, 1024);
                cnt++;
                break;
            case 2:
                sc = (void *)shellcode;
                sc();
                break;
            case 3:
                printf("addr: ");
                scanf("%ld", &addr);
                printf("value: ");
                scanf("%ld", addr);
                break;
            default:
                break;
        }
    }
    return 0;
}
```

The program uses `seccomp`to filter syscalls through the `syscall_filter()` function. However, the filter only checks the architecture (x86_64) without restricting specific syscalls. This makes the use of `seccomp` ineffective, as it does not actually block any potentially dangerous system calls.

The program allocates an RWX memory region using `mmap()`, allowing `shellcode` injection and execution. The user can input `shellcode`, store it in memory, and execute it. Additionally, the program provides an option to write a value to an arbitrary memory address using `scanf("%ld", addr);`, which introduces a serious security vulnerability.

Key risks include arbitrary code execution due to RWX memory, unrestricted `syscalls`, and an arbitrary memory write vulnerability. An attacker could exploit these flaws to gain control over the program, execute malicious code, or escalate privileges.
