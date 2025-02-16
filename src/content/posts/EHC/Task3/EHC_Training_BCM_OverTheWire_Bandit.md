---
title: "[TRAINING BCM] - Bandit OverTheWire"
published: 2025-02-11
description: ""
image: "./logo.jpg"
tags:
  - EHC
category: "EHC TRAINING BCM"
draft: false
---

# Tản mạn

Đây là task cuối cùng mình làm, và sau task này sẽ training off... Và mình không thể tham gia đợt training off này, thật là buồn :<

Dưới đây là write-up các level `Bandit` mình đã giải

# Level 0

## Goal

The goal of this level is for you to log into the game using SSH. The host to which you need to connect is `bandit.labs.overthewire.org`, on port `2220`. The username is `bandit0` and the password is `bandit0`. Once logged in, go to the Level 1 page to find out how to beat Level 1.

## Solution

Ở level này thì ta được yêu cầu là sử dụng `ssh` để connect vào server của `bandit`. Thì rất cơ bản ta sẽ sẽ dụng lệnh như sau:

```sh
$ ssh bandit0@bandit.labs.overthewire.org -p 2220
The authenticity of host '[bandit.labs.overthewire.org]:2220 ([16.16.163.126]:2220)' can't be established.
ED25519 key fingerprint is SHA256:C2ihUBV7ihnV1wUXRb4RrEcLfXC5CXlhmAAM/urerLY.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Please type 'yes', 'no' or the fingerprint: yes
Warning: Permanently added '[bandit.labs.overthewire.org]:2220' (ED25519) to the list of known hosts.
                         _                     _ _ _
                        | |__   __ _ _ __   __| (_) |_
                        | '_ \ / _` | '_ \ / _` | | __|
                        | |_) | (_| | | | | (_| | | |_
                        |_.__/ \__,_|_| |_|\__,_|_|\__|


                      This is an OverTheWire game server.
            More information on http://www.overthewire.org/wargames

bandit0@bandit.labs.overthewire.org's password:

      ,----..            ,----,          .---.
     /   /   \         ,/   .`|         /. ./|
    /   .     :      ,`   .'  :     .--'.  ' ;
   .   /   ;.  \   ;    ;     /    /__./ \ : |
  .   ;   /  ` ; .'___,/    ,' .--'.  '   \' .
  ;   |  ; \ ; | |    :     | /___/ \ |    ' '
  |   :  | ; | ' ;    |.';  ; ;   \  \;      :
  .   |  ' ' ' : `----'  |  |  \   ;  `      |
  '   ;  \; /  |     '   :  ;   .   \    .\  ;
   \   \  ',  /      |   |  '    \   \   ' \ |
    ;   :    /       '   :  |     :   '  |--"
     \   \ .'        ;   |.'       \   \ ;
  www. `---` ver     '---' he       '---" ire.org


Welcome to OverTheWire!

If you find any problems, please report them to the #wargames channel on
discord or IRC.

--[ Playing the games ]--

  This machine might hold several wargames.
  If you are playing "somegame", then:

    * USERNAMES are somegame0, somegame1, ...
    * Most LEVELS are stored in /somegame/.
    * PASSWORDS for each level are stored in /etc/somegame_pass/.

  Write-access to homedirectories is disabled. It is advised to create a
  working directory with a hard-to-guess name in /tmp/.  You can use the
  command "mktemp -d" in order to generate a random and hard to guess
  directory in /tmp/.  Read-access to both /tmp/ is disabled and to /proc
  restricted so that users cannot snoop on eachother. Files and directories
  with easily guessable or short names will be periodically deleted! The /tmp
  directory is regularly wiped.
  Please play nice:

    * don't leave orphan processes running
    * don't leave exploit-files laying around
    * don't annoy other players
    * don't post passwords or spoilers
    * again, DONT POST SPOILERS!
      This includes writeups of your solution on your blog or website!

--[ Tips ]--

  This machine has a 64bit processor and many security-features enabled
  by default, although ASLR has been switched off.  The following
  compiler flags might be interesting:

    -m32                    compile for 32bit
    -fno-stack-protector    disable ProPolice
    -Wl,-z,norelro          disable relro

  In addition, the execstack tool can be used to flag the stack as
  executable on ELF binaries.

  Finally, network-access is limited for most levels by a local
  firewall.

--[ Tools ]--

 For your convenience we have installed a few useful tools which you can find
 in the following locations:

    * gef (https://github.com/hugsy/gef) in /opt/gef/
    * pwndbg (https://github.com/pwndbg/pwndbg) in /opt/pwndbg/
    * gdbinit (https://github.com/gdbinit/Gdbinit) in /opt/gdbinit/
    * pwntools (https://github.com/Gallopsled/pwntools)
    * radare2 (http://www.radare.org/)

--[ More information ]--

  For more information regarding individual wargames, visit
  http://www.overthewire.org/wargames/

  For support, questions or comments, contact us on discord or IRC.

  Enjoy your stay!

bandit0@bandit:~$ whoami
bandit0
```

Và thế là ta đã connect thành công

# Level 0 → Level 1

## Goal

The password for the next level is stored in a file called readme located in the home directory. Use this password to log into bandit1 using SSH. Whenever you find a password for a level, use SSH (on port 2220) to log into that level and continue the game.

## Solution

Theo như yêu cầu thì ta sẽ cần phải đọc một file `readme` để có được password, nhưng trước tiên để xác định được file đó ở đâu ta sẽ sẽ dụng `ls` để list ra những thứ có trong thư mục ta đang làm việc và kiểm tra xem có file `readme` ở đó không:

```sh
bandit0@bandit:~$ ls
readme
```

Sau khi đã kiểm tra rồi thì ta sẽ dụng `cat` để đọc nội dung bên trong file đó:

```sh
bandit0@bandit:~$ cat readme
Congratulations on your first steps into the bandit game!!
Please make sure you have read the rules at https://overthewire.org/rules/
If you are following a course, workshop, walkthrough or other educational activity,
please inform the instructor about the rules as well and encourage them to
contribute to the OverTheWire community so we can keep these games free!

The password you are looking for is: ZjLjTmM6FvvyRnrb2rfNWOZOTa6ip5If
```

# Level 1 → Level 2

## Goal

The password for the next level is stored in a file called - located in the home directory

## Solution

Điều đặc biệt ở level này là khi ta sử dụng `cat -` thì sẽ không được nên ta sẽ chuyển sang dùng `cat ./-`:

```sh
bandit1@bandit:~$ ls
-
bandit1@bandit:~$ ls -la
total 24
-rw-r-----  1 bandit2 bandit1   33 Sep 19 07:08 -
drwxr-xr-x  2 root    root    4096 Sep 19 07:08 .
drwxr-xr-x 70 root    root    4096 Sep 19 07:09 ..
-rw-r--r--  1 root    root     220 Mar 31  2024 .bash_logout
-rw-r--r--  1 root    root    3771 Mar 31  2024 .bashrc
-rw-r--r--  1 root    root     807 Mar 31  2024 .profile
bandit1@bandit:~$ cat -
^C
bandit1@bandit:~$ cat ./-
263JGJPfgU6LtdEvgfWU1XP5yac29mFx
```

Và khi research sâu hơn thì mình thấy được một phần `reply` này khác là hay:

![alt text](image.png)

Và giải thích bằng tiếng việt ngắn gọn lại là:

- Khi sử dụng dấu `-` trên dòng lệnh Unix, hầu hết các tiện ích (như cat, grep, …) đều quy ước rằng `-` không phải là tên của một file thông thường mà là một kí hiệu đặc biệt chỉ định cho luồng chuẩn (STDIN cho đầu vào hoặc STDOUT cho đầu ra)

- Do đó khi ta sử dụng `cat -` thì cat sẽ không mở file có tên `-` mà sẽ đọc dữ liệu từ đầu vào chuẩn (ví dụ, từ bàn phím hoặc từ kết quả của một pipeline).

- Nên để khắc phục điều này ta sử dụng `cat < -` hoặc `cat ./-`. Kí hiệu `./` giúp chỉ rõ ra `-` là một file mà ta cần đọc

# Level 2 → Level 3

## Goal

The password for the next level is stored in a file called spaces in this filename located in the home directory

## Solution

Ở level này ta sẽ cần phải đọc một file với tên có dính `space` trong đó, và điều này làm ta không thể đọc file bằng cách `cat <filename>` như trước  được  vì lúc này `cat` sẽ hiểu giữa các khoảng cách là một file riêng biệt và chúng sẽ báo lỗi:

```sh
bandit2@bandit:~$ ls
spaces in this filename
bandit2@bandit:~$ cat spaces in this filename
cat: spaces: No such file or directory
cat: in: No such file or directory
cat: this: No such file or directory
cat: filename: No such file or directory
```

Vì thế để đọc được file này ta cần để file name đó vào `" "`:

```sh
bandit2@bandit:~$ ls
spaces in this filename
bandit2@bandit:~$ cat "spaces in this filename"
MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx
```

Hoặc sử dụng `\`:

```sh
bandit2@bandit:~$ ls
spaces in this filename
bandit2@bandit:~$ cat spaces\ in\ this\ filename
MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx
```

# Level 3 → Level 4

## Goal

The password for the next level is stored in a hidden file in the inhere directory.

## Solution

Ở level này khá đơn giản, ta chỉ cần xử dụng `ls -la` để check xem trong thư mục `inhere` có gì (bao gồm cả các file/dir bị ẩn) và rồi xử dụng `cat` để đọc file đó mà thôi:

```sh
bandit3@bandit:~$ cd inhere/
bandit3@bandit:~/inhere$ ls -la
total 12
drwxr-xr-x 2 root    root    4096 Sep 19 07:08 .
drwxr-xr-x 3 root    root    4096 Sep 19 07:08 ..
-rw-r----- 1 bandit4 bandit3   33 Sep 19 07:08 ...Hiding-From-You
bandit3@bandit:~/inhere$ cat ...Hiding-From-You
2WmrDFRmJIq3IPxneAaMGhap0pFhF3NJ
```

# Level 4 → Level 5

## Goal

The password for the next level is stored in the only human-readable file in the inhere directory. Tip: if your terminal is messed up, try the “reset” command.

## Solution

Ở level này ta sẽ được giới thiệu với một lệnh mới đó là `file`, lệnh này sẽ cho chúng ta biết được thông tin của một file đó có gì, và ở đây khi ta sử dụng `ls -la` thì nó sẽ hiện ra rất nhiều file, và chỉ có một file chứa password, việc check từng file sẽ khá lâu nên ta sẽ xử dụng `file` để xem xem file nào là file `ASCII text` tức là trong nó chứa những thứ mà ta có thể đọc được...:

```sh
bandit4@bandit:~/inhere$ ls -la
total 48
drwxr-xr-x 2 root    root    4096 Sep 19 07:08 .
drwxr-xr-x 3 root    root    4096 Sep 19 07:08 ..
-rw-r----- 1 bandit5 bandit4   33 Sep 19 07:08 -file00
-rw-r----- 1 bandit5 bandit4   33 Sep 19 07:08 -file01
-rw-r----- 1 bandit5 bandit4   33 Sep 19 07:08 -file02
-rw-r----- 1 bandit5 bandit4   33 Sep 19 07:08 -file03
-rw-r----- 1 bandit5 bandit4   33 Sep 19 07:08 -file04
-rw-r----- 1 bandit5 bandit4   33 Sep 19 07:08 -file05
-rw-r----- 1 bandit5 bandit4   33 Sep 19 07:08 -file06
-rw-r----- 1 bandit5 bandit4   33 Sep 19 07:08 -file07
-rw-r----- 1 bandit5 bandit4   33 Sep 19 07:08 -file08
-rw-r----- 1 bandit5 bandit4   33 Sep 19 07:08 -file09
bandit4@bandit:~/inhere$ file ./*
./-file00: data
./-file01: data
./-file02: data
./-file03: data
./-file04: data
./-file05: data
./-file06: data
./-file07: ASCII text
./-file08: data
./-file09: data
```

Và sau khi xác định được file đó rồi thì ta sử dụng `cat` để đọc file đó mà thôi:

```sh
bandit4@bandit:~/inhere$ cat ./-file07
4oQYVPkxZOOEOO5pTW81FB8j8lxXGUQw
```

# Level 5 → Level 6

## Goal

The password for the next level is stored in a file somewhere under the inhere directory and has all of the following properties:

- human-readable
- 1033 bytes in size
- not executable

## Solution

Ở đây ta sẽ phải tìm file thoả mãn các yêu cầu:

- human-readable
- 1033 bytes in size
- not executable

Và khi sử dụng `ls -la` thì xuất hiện rất hiện thư mục trong đó:

```sh
bandit5@bandit:~/inhere$ ls
maybehere00  maybehere02  maybehere04  maybehere06  maybehere08  maybehere10  maybehere12  maybehere14  maybehere16  maybehere18
maybehere01  maybehere03  maybehere05  maybehere07  maybehere09  maybehere11  maybehere13  maybehere15  maybehere17  maybehere19
bandit5@bandit:~/inhere$ ls -la maybehere00
total 72
drwxr-x---  2 root bandit5 4096 Sep 19 07:08 .
drwxr-x--- 22 root bandit5 4096 Sep 19 07:08 ..
-rwxr-x---  1 root bandit5 1039 Sep 19 07:08 -file1
-rwxr-x---  1 root bandit5  551 Sep 19 07:08 .file1
-rw-r-----  1 root bandit5 9388 Sep 19 07:08 -file2
-rw-r-----  1 root bandit5 7836 Sep 19 07:08 .file2
-rwxr-x---  1 root bandit5 7378 Sep 19 07:08 -file3
-rwxr-x---  1 root bandit5 4802 Sep 19 07:08 .file3
-rwxr-x---  1 root bandit5 6118 Sep 19 07:08 spaces file1
-rw-r-----  1 root bandit5 6850 Sep 19 07:08 spaces file2
-rwxr-x---  1 root bandit5 1915 Sep 19 07:08 spaces file3
```

Việc xử dụng file để check từng dir như vậy là điều rất mất thời gian. Nên ở đây ta sẽ dùng thêm lệnh `grep` với pipe (`|`). Pipe như một được ống và nó sẽ chuyển `output` của lệnh này sang cho lệnh khác, và ở đây ta sẽ xử dụng output của lệnh `file` và chuyển sang cho lệnh `grep` với cú pháp: `<command> | grep <something>`.  Như ở trên ta thấy nó chứa rất nhiều thư mục và ta không thể nào mà xử lý từng cái được nên ta sẽ xử dụng lệnh `file */{.,}*` để cho ta tất cả thông tin của file nằm trong `inhere`. Trong đó `*/*` sẽ in ra hết toàn bộ thông tin của file, nhưng nó sẽ không in những file bị ẩn, nên ta cần phải sử dụng thêm `{.,}` để bao gồm các file bắt đầu với `.` và `,`. Để biết thêm thông tin ta có thể đọc ở [đây](https://unix.stackexchange.com/a/186219). Cứ như thế ta sử dụng nó kèm với `ASCII` như theo yêu cầu:

```sh
bandit5@bandit:~/inhere$ file */{.,}* | grep ASCII
maybehere00/.file1:       ASCII text, with very long lines (550)
maybehere00/.file2:       ASCII text, with very long lines (7835)
maybehere01/.file2:       ASCII text, with very long lines (3069)
maybehere02/.file1:       ASCII text, with very long lines (6350)
maybehere02/.file2:       ASCII text, with very long lines (2576)
maybehere03/.file1:       ASCII text, with very long lines (9768)
maybehere03/.file2:       ASCII text, with very long lines (8879)
maybehere04/.file1:       ASCII text, with very long lines (2439)
maybehere04/.file2:       ASCII text, with very long lines (6143)
maybehere05/.file1:       ASCII text, with very long lines (3200)
maybehere05/.file2:       ASCII text, with very long lines (5916)
maybehere06/.file1:       ASCII text, with very long lines (1270)
maybehere06/.file2:       ASCII text, with very long lines (8975)
maybehere07/.file1:       ASCII text, with very long lines (3064)
maybehere07/.file2:       ASCII text, with very long lines (1000)
maybehere08/.file1:       ASCII text, with very long lines (8168)
maybehere08/.file2:       ASCII text, with very long lines (746)
maybehere09/.file1:       ASCII text, with very long lines (6762)
maybehere09/.file2:       ASCII text, with very long lines (8516)
maybehere10/.file1:       ASCII text, with very long lines (7091)
maybehere10/.file2:       ASCII text
maybehere11/.file1:       ASCII text, with very long lines (451)
maybehere11/.file2:       ASCII text, with very long lines (2500)
maybehere12/.file1:       ASCII text, with very long lines (5814)
maybehere12/.file2:       ASCII text, with very long lines (8243)
maybehere13/.file1:       ASCII text, with very long lines (5257)
maybehere13/.file2:       ASCII text, with very long lines (8951)
maybehere14/.file1:       ASCII text, with very long lines (3426)
maybehere14/.file2:       ASCII text, with very long lines (1502)
maybehere15/.file1:       ASCII text, with very long lines (2158)
maybehere15/.file2:       ASCII text
maybehere16/.file1:       ASCII text, with very long lines (5425)
maybehere16/.file2:       ASCII text, with very long lines (8471)
maybehere17/.file1:       ASCII text, with very long lines (894)
maybehere17/.file2:       ASCII text, with very long lines (8340)
maybehere18/.file1:       ASCII text, with very long lines (5701)
maybehere18/.file2:       ASCII text, with very long lines (2083)
maybehere19/.file1:       ASCII text, with very long lines (7208)
maybehere19/.file2:       ASCII text, with very long lines (4739)
maybehere00/-file1:       ASCII text, with very long lines (1038)
maybehere00/-file2:       ASCII text, with very long lines (9387)
maybehere00/spaces file1: ASCII text, with very long lines (6117)
maybehere00/spaces file2: ASCII text, with very long lines (6849)
maybehere01/-file1:       ASCII text, with very long lines (6027)
maybehere01/-file2:       ASCII text
maybehere01/spaces file1: ASCII text, with very long lines (4138)
maybehere01/spaces file2: ASCII text, with very long lines (4542)
maybehere02/-file1:       ASCII text, with very long lines (3800)
maybehere02/spaces file1: ASCII text, with very long lines (6745)
maybehere02/spaces file2: ASCII text, with very long lines (8487)
maybehere03/-file1:       ASCII text, with very long lines (314)
maybehere03/-file2:       ASCII text, with very long lines (6594)
maybehere03/spaces file1: ASCII text, with very long lines (2189)
maybehere03/spaces file2: ASCII text, with very long lines (3384)
maybehere04/-file1:       ASCII text, with very long lines (4409)
maybehere04/-file2:       ASCII text, with very long lines (2618)
maybehere04/spaces file1: ASCII text, with very long lines (5531)
maybehere04/spaces file2: ASCII text, with very long lines (2490)
maybehere05/-file1:       ASCII text, with very long lines (2345)
maybehere05/-file2:       ASCII text, with very long lines (5958)
maybehere05/spaces file1: ASCII text, with very long lines (879)
maybehere05/spaces file2: ASCII text, with very long lines (2419)
maybehere06/-file1:       ASCII text, with very long lines (5730)
maybehere06/-file2:       ASCII text, with very long lines (1075)
maybehere06/spaces file1: ASCII text, with very long lines (4072)
maybehere06/spaces file2: ASCII text, with very long lines (4250)
maybehere07/-file1:       ASCII text, with very long lines (3662)
maybehere07/-file2:       ASCII text, with very long lines (2487)
maybehere07/spaces file1: ASCII text, with very long lines (4129)
maybehere07/spaces file2: ASCII text, with very long lines (9063)
maybehere08/-file1:       ASCII text, with very long lines (1076)
maybehere08/-file2:       ASCII text, with very long lines (3824)
maybehere08/spaces file1: ASCII text
maybehere08/spaces file2: ASCII text, with very long lines (3692)
maybehere09/-file1:       ASCII text, with very long lines (3627)
maybehere09/-file2:       ASCII text, with very long lines (773)
maybehere09/spaces file1: ASCII text, with very long lines (5300)
maybehere09/spaces file2: ASCII text, with very long lines (8715)
maybehere10/-file1:       ASCII text, with very long lines (1051)
maybehere10/-file2:       ASCII text, with very long lines (1990)
maybehere10/spaces file1: ASCII text, with very long lines (8268)
maybehere10/spaces file2: ASCII text, with very long lines (3569)
maybehere11/-file1:       ASCII text, with very long lines (1210)
maybehere11/-file2:       ASCII text, with very long lines (4558)
maybehere11/spaces file1: ASCII text, with very long lines (3146)
maybehere11/spaces file2: ASCII text, with very long lines (502)
maybehere12/-file1:       ASCII text, with very long lines (9677)
maybehere12/-file2:       ASCII text
maybehere12/spaces file1: ASCII text, with very long lines (2156)
maybehere12/spaces file2: ASCII text, with very long lines (2459)
maybehere13/-file1:       ASCII text, with very long lines (1358)
maybehere13/-file2:       ASCII text, with very long lines (1422)
maybehere13/spaces file1: ASCII text, with very long lines (3951)
maybehere13/spaces file2: ASCII text, with very long lines (951)
maybehere14/-file1:       ASCII text, with very long lines (4281)
maybehere14/-file2:       ASCII text, with very long lines (8350)
maybehere14/spaces file1: ASCII text, with very long lines (1381)
maybehere14/spaces file2: ASCII text, with very long lines (870)
maybehere15/-file1:       ASCII text, with very long lines (8793)
maybehere15/-file2:       ASCII text, with very long lines (9498)
maybehere15/spaces file1: ASCII text, with very long lines (1622)
maybehere15/spaces file2: ASCII text
maybehere16/-file1:       ASCII text, with very long lines (4276)
maybehere16/-file2:       ASCII text, with very long lines (5300)
maybehere16/spaces file1: ASCII text, with very long lines (9772)
maybehere16/spaces file2: ASCII text, with very long lines (3145)
maybehere17/-file1:       ASCII text, with very long lines (1132)
maybehere17/-file2:       ASCII text, with very long lines (1790)
maybehere17/spaces file1: ASCII text, with very long lines (8360)
maybehere17/spaces file2: ASCII text, with very long lines (3386)
maybehere18/-file1:       ASCII text, with very long lines (9696)
maybehere18/-file2:       ASCII text
maybehere18/spaces file1: ASCII text, with very long lines (7333)
maybehere18/spaces file2: ASCII text, with very long lines (6347)
maybehere19/-file1:       ASCII text, with very long lines (6301)
maybehere19/-file2:       ASCII text, with very long lines (5593)
maybehere19/spaces file1: ASCII text, with very long lines (7185)
maybehere19/spaces file2: ASCII text, with very long lines (8784)
```

Và với số lượng file nhiều như thế này ta sẽ khó có thể check từng file một để có được mật khẩu. Vì thế ta còn một yếu tố cuối cùng là xác định file có size là `1033 bytes`, và ta sẽ có thể lấy được file size bằng cách sử dụng `du` với flag `-a` và `-b` (dùng `du --help` để biết rõ về 2 flags này):

```sh
bandit5@bandit:~/inhere$ du -b -a | grep 1033
1033    ./maybehere07/.file2
bandit5@bandit:~/inhere$ du -b -a | grep 1033
1033    ./maybehere07/.file2
bandit5@bandit:~/inhere$ file ./maybehere07/.file2
./maybehere07/.file2: ASCII text, with very long lines (1000)
bandit5@bandit:~/inhere$ cat ./maybehere07/.file2
HWasnPhtq9AVKe0dmk45nxy20cvUa6EG
```

### Bonus

Mình có tham khảo thêm một số cách làm ở ngoài nữa thì thấy họ sử dụng một lệnh duy nhất là tìm được file luôn:

```sh
bandit5@bandit:~/inhere$ find . -type f -size 1033c ! -executable -exec file '{}' \; | grep ASCII
./maybehere07/.file2: ASCII text, with very long lines (1000)
bandit5@bandit:~/inhere$ cat ./maybehere07/.file2
HWasnPhtq9AVKe0dmk45nxy20cvUa6EG
```

Trong đó:

- `-size` được  sử dụng để xác định số bytes ta cần tìm (`c` đại diện cho byte)
- `-type f` là chỉ tìm `file`
- `-exec file '{}' \;` để thực thi lệnh `file` để đọc tất cả các file mà `find` tìm được `{}` được ví như `placeholder` cho các filename mà `find` tìm được và `\;` đánh dấu cho sự kết thúc của lệnh được thực thi bởi `-exec`. Ta có thể dụng dấu `+` thay vì `\;`


# Level 6 -> Level 7

## Goal

The password for the next level is stored somewhere on the server and has all of the following properties:

- owned by user bandit7
- owned by group bandit6
- 33 bytes in size

## Solution

Giống như ở level trước ở đây ta sẽ xử dụng lệnh `find` cho nhanh.

```sh
bandit6@bandit:~$ find / -type f -user bandit7 -group bandit6 -size 33c
bandit6@bandit:~$ find / -type f -user bandit7 -group bandit6 -size 33c
find: ‘/drifter/drifter14_src/axTLS’: Permission denied
find: ‘/root’: Permission denied
find: ‘/snap’: Permission denied
find: ‘/tmp’: Permission denied
find: ‘/proc/tty/driver’: Permission denied
find: ‘/proc/3944599/task/3944599/fdinfo/6’: No such file or directory
find: ‘/proc/3944599/fdinfo/5’: No such file or directory
find: ‘/home/bandit31-git’: Permission denied
find: ‘/home/ubuntu’: Permission denied
find: ‘/home/bandit5/inhere’: Permission denied
find: ‘/home/bandit30-git’: Permission denied
find: ‘/home/drifter8/chroot’: Permission denied
find: ‘/home/drifter6/data’: Permission denied
find: ‘/home/bandit29-git’: Permission denied
find: ‘/home/bandit28-git’: Permission denied
find: ‘/home/bandit27-git’: Permission denied
find: ‘/lost+found’: Permission denied
find: ‘/etc/polkit-1/rules.d’: Permission denied
find: ‘/etc/multipath’: Permission denied
find: ‘/etc/stunnel’: Permission denied
find: ‘/etc/xinetd.d’: Permission denied
find: ‘/etc/credstore.encrypted’: Permission denied
find: ‘/etc/ssl/private’: Permission denied
find: ‘/etc/sudoers.d’: Permission denied
find: ‘/etc/credstore’: Permission denied
find: ‘/dev/shm’: Permission denied
find: ‘/dev/mqueue’: Permission denied
find: ‘/var/log/amazon’: Permission denied
find: ‘/var/log/unattended-upgrades’: Permission denied
find: ‘/var/log/chrony’: Permission denied
find: ‘/var/log/private’: Permission denied
find: ‘/var/tmp’: Permission denied
find: ‘/var/spool/cron/crontabs’: Permission denied
find: ‘/var/spool/bandit24’: Permission denied
find: ‘/var/spool/rsyslog’: Permission denied
find: ‘/var/cache/ldconfig’: Permission denied
find: ‘/var/cache/apt/archives/partial’: Permission denied
find: ‘/var/cache/pollinate’: Permission denied
find: ‘/var/cache/private’: Permission denied
find: ‘/var/cache/apparmor/2425d902.0’: Permission denied
find: ‘/var/cache/apparmor/baad73a1.0’: Permission denied
find: ‘/var/lib/polkit-1’: Permission denied
find: ‘/var/lib/amazon’: Permission denied
/var/lib/dpkg/info/bandit7.password
find: ‘/var/lib/apt/lists/partial’: Permission denied
<...>
```

Nó cho ta rất nhiều output và đa số toàn là bị `permission denied`, ở đây khi mình lướt một vòng thì đã tìm ra ngay file ta cần read, nhưng để mở rộng thêm thì ta có thể sử dụng thêm `2>/dev/null` để ẩn hết các dòng thông báo lỗi `Permission denied`:

```sh
bandit6@bandit:~$ find / -type f -user bandit7 -group bandit6 -size 33c 2>/dev/null
/var/lib/dpkg/info/bandit7.password
bandit6@bandit:~$ cat /var/lib/dpkg/info/bandit7.password
morbNTDkSW6jIlUc0ymOdMaLnOlFVAaj
```

# Level 7 → Level 8

## Goal

The password for the next level is stored in the file data.txt next to the word millionth

## Solution

Ở level này khá đơn giản nên mình sẽ làm nhanh luôn:

```sh
bandit7@bandit:~$ cat data.txt | grep millionth
millionth       dfwvzFQi4mU0wfNbFOe9RoWskMLg7eEc
```

# Level 8 -> Level 9

## Goal

The password for the next level is stored in the file data.txt and is the only line of text that occurs only once

## Solution

Ở level này ta sẽ xử dụng lệnh `uniq` - lệnh này sẽ filter các dòng liền kề từ input và ghi vào output. Với flag `-u` nó sẽ filter các line chỉ xuất hiện duy nhất một lần. Và điều kiện để sử dụng `uniq` là input phải được `sort` trước:

```sh
bandit8@bandit:~$ sort data.txt | uniq -u
4CKMh1JI91bUIZZPXDqGanal4xvAg0JM
```

# Level 9 → Level 10

## Goal

The password for the next level is stored in the file data.txt in one of the few human-readable strings, preceded by several ‘=’ characters.

## Solution

Level này ta sẽ cần sử dụng đến lệnh `strings`, lệnh này sẽ giúp ta xem được các chuỗi có thể đọc được trong một file là gì:

```sh
bandit9@bandit:~$ strings data.txt | grep "="
}========== the
p\l=
;c<Q=.dEXU!
3JprD========== passwordi
qC(=
~fDV3========== is
7=oc
zP=
~de=
3k=fQ
~o=0
69}=
%"=Y
=tZ~07
D9========== FGUW5ilLVJrxX9kMYMmlN4MgbpfMiqey
N=~[!N
zA=?0j
```

# Level 10 → Level 11

## Goal

The password for the next level is stored in the file data.txt, which contains base64 encoded data

## Solution

```sh
bandit10@bandit:~$ cat data.txt
VGhlIHBhc3N3b3JkIGlzIGR0UjE3M2ZaS2IwUlJzREZTR3NnMlJXbnBOVmozcVJyCg==
```

Như ta đã thấy, dữ liệu đã bị mã hoá `base64` và việc ta cần làm là giải mã ngược lại. Ta sẽ xử dụng lệnh `base64` với flag `-d` được viết tắt là `--decode`:

```sh
bandit10@bandit:~$ cat data.txt
VGhlIHBhc3N3b3JkIGlzIGR0UjE3M2ZaS2IwUlJzREZTR3NnMlJXbnBOVmozcVJyCg==
bandit10@bandit:~$ cat data.txt | base64 --decode
The password is dtR173fZKb0RRsDFSGsg2RWnpNVj3qRr
```

# Level 11 → Level 12

## Goal

The password for the next level is stored in the file data.txt, where all lowercase (a-z) and uppercase (A-Z) letters have been rotated by 13 positions

## Solution

Ở level này ta sẽ cần làm việc với lệnh `tr` - translate. Lệnh này sẽ giúp ta chuyển kí tự này thành kí tự khác dựa trên syntax:
`tr <old_chars> <new_chars>`:

```sh
bandit11@bandit:~$ cat data.txt
Gur cnffjbeq vf 7k16JArUVv5LxVuJfsSVdbbtaHGlw9D4
bandit11@bandit:~$ cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'
The password is 7x16WNeHIi5YkIhWsfFIqoognUTyj9Q4
```

Ta có thể đọc thêm ở [đây](https://en.wikipedia.org/wiki/ROT13) để biết thêm về ROT13

# Level 12 → Level 13

## Goal

The password for the next level is stored in the file data.txt, which is a hexdump of a file that has been repeatedly compressed. For this level it may be useful to create a directory under /tmp in which you can work. Use mkdir with a hard to guess directory name. Or better, use the command “mktemp -d”. Then copy the datafile using cp, and rename it using mv (read the manpages!)

## Solution

Theo như gợi ý thì bây giờ ta sẽ tạo một dir ở `/tmp` và từ đó copy file `data.txt` vào thư mục đã tạo này.

```sh
bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ cp /home/bandit12/data.txt .
bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ ls
data.txt
```

Và ở level này nó tương đối khá dài vì ta phải `decompress` nhiều lần một file và sau đây là cách làm:

- Đầu tiên ta sẽ check file `hexdump` đó và `revert` nó để có được dữ liệu thật, vì thứ ta tác động là dữ liệu thật của nó chứ không phải là `hexdump`:

  ```sh
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ mv data.txt hexdump
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ cat hexdump | head
  00000000: 1f8b 0808 dfcd eb66 0203 6461 7461 322e  .......f..data2.
  00000010: 6269 6e00 013e 02c1 fd42 5a68 3931 4159  bin..>...BZh91AY
  00000020: 2653 59ca 83b2 c100 0017 7fff dff3 f4a7  &SY.............
  00000030: fc9f fefe f2f3 cffe f5ff ffdd bf7e 5bfe  .............~[.
  00000040: faff dfbe 97aa 6fff f0de edf7 b001 3b56  ......o.......;V
  00000050: 0400 0034 d000 0000 0069 a1a1 a000 0343  ...4.....i.....C
  00000060: 4686 4341 a680 068d 1a69 a0d0 0068 d1a0  F.CA.....i...h..
  00000070: 1906 1193 0433 5193 d4c6 5103 4646 9a34  .....3Q...Q.FF.4
  00000080: 0000 d320 0680 0003 264d 0346 8683 d21a  ... ....&M.F....
  00000090: 0686 8064 3400 0189 a683 4fd5 0190 001e  ...d4.....O.....
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ xxd -r hexdump compress
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ cat compress | head
  ���fdata2.bin>��BZh91AY&SYʃ�����������������ݿ~[���߾��o������;V4�i���CF�CA���␦i��hѠ�3Q���QFF�4� �&MF���␦��d4���O���4шC�
  ␦d�F�␦hɦ�0�hh�2*�`Q��S/                                                                                               @i�&F��@�@4i��h�
                        ���]�N��')!L��L�5��O�Z
  �=g!Wb^
  �d     �����#�{B��9�v�/tJ���<N�7o�#E�_#
    54�)A����
            tOJQ��#�̜�匔a���JB�a�}6�"�YⵟQ���*��0h���}�����|�␦!   &��n�"��{�
                                                                            �Go7
                                                                                6a�ީ�/�F��8��S6��Gα�S7�H1R�A��&�l(�$��e�\�l�ن�"G�ՋX�Vz�
                                                                                                                                      ���\c�%    a,Sd�}$���`�Ǿ
  ␦�G�Cp���C�ˈ*J�K���g��g����#mAj(��`��.R)}��N0��&F�]0b&(�N�KgT8�BJ���.Ƀ���]��BC*�Y>bandit12@bandit:/tmp/tmp.NKu9e3fLlX$
  ```
  Dữ liệu lúc này trông ổn hơn lúc đầu. Ta sử dụng `xxd -r` với flag `-r` để `revert` (ta có thể check nó trong manpage)

  ```sh
         -r | -revert
              Reverse operation: convert (or patch) hexdump into binary.  If not writing to stdout, xxd writes into its output file without truncating  it.  Use  the
              combination  -r  -p  to  read plain hexadecimal dumps without line number information and without a particular column layout. Additional Whitespace and
              line-breaks are allowed anywhere.
  ```

- Dữ liệu lúc này vẫn chưa đúng thứ ta cần lắm nên ta sẽ check xem `file type` của nó là gì thông qua command `file`, từ đó dùng command tương ứng với loại file đó để `decompress`:

  ```sh
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ file compress
  compress: gzip compressed data, was "data2.bin", last modified: Thu Sep 19 07:08:15 2024, max compression, from Unix, original size modulo 2^32 574
  ```

  Từ dữ liệu trên ta sẽ thấy được đó là `gzip`, vậy ta sẽ dùng command `gzip` để `decompress`, ta sẽ thực hiện điều đó với `-d`:

    ```sh
    bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ mv compress compress.gz
    bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ ls
    compress.gz  hexdump
    bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ gzip -d compress.gz
    bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ ls
    compress  hexdump
    ```
- Tiếp tục dùng `file` để check và dùng `command` tương ứng để `decompress`. Lần này là `bzip2`, ta có thể dùng flag `-d` để `decompress`:

  ```sh
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ file compress
  compress: bzip2 compressed data, block size = 900k
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ mv compress compress.bz2
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ ls
  compress.bz2  hexdump
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ bzip2 -d compress.bz2
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ ls
  compress  hexdump
  ```

- Tiếp tục đến khi nào ta có tìm được file đọc được:

  ```sh
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ file compress
  compress: gzip compressed data, was "data4.bin", last modified: Thu Sep 19 07:08:15 2024, max compression, from Unix, original size modulo 2^32 20480
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ mv compress compress.gz
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ gzip -d compress.gz
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ file compress
  compress: POSIX tar archive (GNU)
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ xxd compress | head
  00000000: 6461 7461 352e 6269 6e00 0000 0000 0000  data5.bin.......
  00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
  00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
  00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
  00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
  00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
  00000060: 0000 0000 3030 3030 3634 3400 3030 3030  ....0000644.0000
  00000070: 3030 3000 3030 3030 3030 3000 3030 3030  000.0000000.0000
  00000080: 3030 3234 3030 3000 3134 3637 3237 3436  0024000.14672746
  00000090: 3733 3700 3031 3132 3637 0020 3000 0000  737.011267. 0...
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ mv compress compress.tar
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ tar -xf compress.tar
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ ls
  compress.tar  data5.bin  hexdump
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ file data5.bin
  data5.bin: POSIX tar archive (GNU)
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ tar -xf data5.bin
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ ls
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ tar -xf data5.bin
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ ls
  compress.tar  data5.bin  data6.bin  hexdump
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ file data6.bin
  data6.bin: bzip2 compressed data, block size = 900k
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ bzip2 -d data6.bin
  bzip2: Can't guess original name for data6.bin -- using data6.bin.out
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ ls
  compress.tar  data5.bin  data6.bin.out  hexdump
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ file data6.bin.out
  data6.bin.out: POSIX tar archive (GNU)
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ tar -xf data6.bin.out
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ ls
  compress.tar  data5.bin  data6.bin.out  data8.bin  hexdump
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ file data8.bin
  data8.bin: gzip compressed data, was "data9.bin", last modified: Thu Sep 19 07:08:15 2024, max compression, from Unix, original size modulo 2^32 49
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ mv data8.bin data8.gz
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ gzip -d data8.gz
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ ls
  compress.tar  data5.bin  data6.bin.out  data8  hexdump
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ file data8
  data8: ASCII text
  bandit12@bandit:/tmp/tmp.NKu9e3fLlX$ cat data8
  The password is FO5dwFsc0cbaIiH0h8J2eUks2vdTDwAn
  ```
  **Mở rộng:** Ngoài việc sử dụng `file` ra ta có thể dùng `xxd` để check các byte đầu của nó để xem định dạng file của nó là gì và check ở [đây](https://en.wikipedia.org/wiki/List_of_file_signatures)

# Level 13 → Level 14

## Goal

The password for the next level is stored in /etc/bandit_pass/bandit14 and can only be read by user bandit14. For this level, you don’t get the next password, but you get a private SSH key that can be used to log into the next level. Note: localhost is a hostname that refers to the machine you are working on

## Solution

Ở level này ta không thể lấy mật khẩu một cách thong thường nữa, như mọi khi ta `ssh` bằng password, thì ở đây nó đã cho ta một file `private` trước rồi, và file này là file `identify`, với nó `ssh` có thể định dạng được người connect vào mà không cần password, nói dễ hiểu nó như một tấm thẻ `passport` để thông hành vậy

```sh
bandit13@bandit:~$ ls
sshkey.private
bandit13@bandit:~$ ssh
usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface] [-b bind_address]
           [-c cipher_spec] [-D [bind_address:]port] [-E log_file]
           [-e escape_char] [-F configfile] [-I pkcs11] [-i identity_file]
           [-J destination] [-L address] [-l login_name] [-m mac_spec]
           [-O ctl_cmd] [-o option] [-P tag] [-p port] [-R address]
           [-S ctl_path] [-W host:port] [-w local_tun[:remote_tun]]
           destination [command [argument ...]]
       ssh [-Q query_option]
bandit13@bandit:~$ ssh -i sshkey.private bandit14@bandit.labs.overthewire.org -p 2220
The authenticity of host '[bandit.labs.overthewire.org]:2220 ([127.0.0.1]:2220)' can't be established.
ED25519 key fingerprint is SHA256:C2ihUBV7ihnV1wUXRb4RrEcLfXC5CXlhmAAM/urerLY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Please type 'yes', 'no' or the fingerprint: yes
Could not create directory '/home/bandit13/.ssh' (Permission denied).
Failed to add the host to the list of known hosts (/home/bandit13/.ssh/known_hosts).
                         _                     _ _ _
                        | |__   __ _ _ __   __| (_) |_
                        | '_ \ / _` | '_ \ / _` | | __|
                        | |_) | (_| | | | | (_| | | |_
                        |_.__/ \__,_|_| |_|\__,_|_|\__|


                      This is an OverTheWire game server.
            More information on http://www.overthewire.org/wargames

!!! You are trying to log into this SSH server with a password on port 2220 from localhost.
!!! Connecting from localhost is blocked to conserve resources.
!!! Please log out and log in again.


      ,----..            ,----,          .---.
     /   /   \         ,/   .`|         /. ./|
    /   .     :      ,`   .'  :     .--'.  ' ;
   .   /   ;.  \   ;    ;     /    /__./ \ : |
  .   ;   /  ` ; .'___,/    ,' .--'.  '   \' .
  ;   |  ; \ ; | |    :     | /___/ \ |    ' '
  |   :  | ; | ' ;    |.';  ; ;   \  \;      :
  .   |  ' ' ' : `----'  |  |  \   ;  `      |
  '   ;  \; /  |     '   :  ;   .   \    .\  ;
   \   \  ',  /      |   |  '    \   \   ' \ |
    ;   :    /       '   :  |     :   '  |--"
     \   \ .'        ;   |.'       \   \ ;
  www. `---` ver     '---' he       '---" ire.org


Welcome to OverTheWire!

If you find any problems, please report them to the #wargames channel on
discord or IRC.

--[ Playing the games ]--

  This machine might hold several wargames.
  If you are playing "somegame", then:

    * USERNAMES are somegame0, somegame1, ...
    * Most LEVELS are stored in /somegame/.
    * PASSWORDS for each level are stored in /etc/somegame_pass/.

  Write-access to homedirectories is disabled. It is advised to create a
  working directory with a hard-to-guess name in /tmp/.  You can use the
  command "mktemp -d" in order to generate a random and hard to guess
  directory in /tmp/.  Read-access to both /tmp/ is disabled and to /proc
  restricted so that users cannot snoop on eachother. Files and directories
  with easily guessable or short names will be periodically deleted! The /tmp
  directory is regularly wiped.
  Please play nice:

    * don't leave orphan processes running
    * don't leave exploit-files laying around
    * don't annoy other players
    * don't post passwords or spoilers
    * again, DONT POST SPOILERS!
      This includes writeups of your solution on your blog or website!

--[ Tips ]--

  This machine has a 64bit processor and many security-features enabled
  by default, although ASLR has been switched off.  The following
  compiler flags might be interesting:

    -m32                    compile for 32bit
    -fno-stack-protector    disable ProPolice
    -Wl,-z,norelro          disable relro

  In addition, the execstack tool can be used to flag the stack as
  executable on ELF binaries.

  Finally, network-access is limited for most levels by a local
  firewall.

--[ Tools ]--

 For your convenience we have installed a few useful tools which you can find
 in the following locations:

    * gef (https://github.com/hugsy/gef) in /opt/gef/
    * pwndbg (https://github.com/pwndbg/pwndbg) in /opt/pwndbg/
    * gdbinit (https://github.com/gdbinit/Gdbinit) in /opt/gdbinit/
    * pwntools (https://github.com/Gallopsled/pwntools)
    * radare2 (http://www.radare.org/)

--[ More information ]--

  For more information regarding individual wargames, visit
  http://www.overthewire.org/wargames/

  For support, questions or comments, contact us on discord or IRC.

  Enjoy your stay!

bandit14@bandit:~$ cat /etc/bandit_pass/bandit14
MU4VWeTyJk8ROof1qqmcBPaLh7lDCPvS
```

# Level 14 → Level 15

## Goal

The password for the next level can be retrieved by submitting the password of the current level to port 30000 on localhost

## Solution

```sh
bandit14@bandit:~$ nc localhost 30000
MU4VWeTyJk8ROof1qqmcBPaLh7lDCPvS
Correct!
8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo
```

# Level 15 → Level 16

## Goal

The password for the next level can be retrieved by submitting the password of the current level to port 30001 on localhost using SSL/TLS encryption.

Helpful note: Getting “DONE”, “RENEGOTIATING” or “KEYUPDATE”? Read the “CONNECTED COMMANDS” section in the manpage.

## Solution

Vậy theo như task ta sẽ sử dụng `OpenSSL` để connect vào và lấy mất khẩu, đọc manpage ta biết được:

```sh
       s_client
           This  implements  a  generic  SSL/TLS  client  which can establish a transparent connection to a remote server speaking SSL/TLS. It's intended for testing purposes only and provides only rudimentary interface functionality but internally uses mostly all functionality of the OpenSSL ssl library.
        -connect host:port
           This specifies the host and optional port to connect to. It is possible to select the host and port using the optional target positional argument instead.
           If neither this nor the target positional argument are specified then an attempt is made to connect to the local host on port 4433.
```

Theo thông tin trên thì ta biết được rằng `s_client` sẽ triển khai một client đơn giản để kết nối với máy chủ bằng `SSL/TLS`:

```sh
bandit15@bandit:~$ openssl s_client -connect localhost:30001
CONNECTED(00000003)
Can't use SSL_get_servername
depth=0 CN = SnakeOil
verify error:num=18:self-signed certificate
verify return:1
depth=0 CN = SnakeOil
verify return:1
---
Certificate chain
 0 s:CN = SnakeOil
   i:CN = SnakeOil
   a:PKEY: rsaEncryption, 4096 (bit); sigalg: RSA-SHA256
   v:NotBefore: Jun 10 03:59:50 2024 GMT; NotAfter: Jun  8 03:59:50 2034 GMT
---
Server certificate
<...>
8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo
Correct!
kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx

closed
```

# Level 16 → Level 17

## Goal

The credentials for the next level can be retrieved by submitting the password of the current level to a port on localhost in the range 31000 to 32000. First find out which of these ports have a server listening on them. Then find out which of those speak SSL/TLS and which don’t. There is only 1 server that will give the next credentials, the others will simply send back to you whatever you send to it.


## Solution

Với đề yêu cần cần sử dụng port scan tools để quét các cổng như thế này thì mình luôn nghĩ ngay tới `nmap`, một công cụ fuzzing khá tuyệt vời mà mình biết:

```sh
bandit16@bandit:~$ nmap -p 31000-32000 localhost -T5 -sV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-15 14:32 UTC
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00015s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT      STATE SERVICE     VERSION
31046/tcp open  echo
31518/tcp open  ssl/echo
31691/tcp open  echo
31790/tcp open  ssl/unknown
31960/tcp open  echo
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port31790-TCP:V=7.94SVN%T=SSL%I=7%D=2/15%Time=67B0A579%P=x86_64-pc-linu
SF:x-gnu%r(GenericLines,32,"Wrong!\x20Please\x20enter\x20the\x20correct\x2
SF:0current\x20password\.\n")%r(GetRequest,32,"Wrong!\x20Please\x20enter\x
SF:20the\x20correct\x20current\x20password\.\n")%r(HTTPOptions,32,"Wrong!\
SF:x20Please\x20enter\x20the\x20correct\x20current\x20password\.\n")%r(RTS
SF:PRequest,32,"Wrong!\x20Please\x20enter\x20the\x20correct\x20current\x20
SF:password\.\n")%r(Help,32,"Wrong!\x20Please\x20enter\x20the\x20correct\x
SF:20current\x20password\.\n")%r(FourOhFourRequest,32,"Wrong!\x20Please\x2
SF:0enter\x20the\x20correct\x20current\x20password\.\n")%r(LPDString,32,"W
SF:rong!\x20Please\x20enter\x20the\x20correct\x20current\x20password\.\n")
SF:%r(SIPOptions,32,"Wrong!\x20Please\x20enter\x20the\x20correct\x20curren
SF:t\x20password\.\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 162.95 seconds
bandit16@bandit:~$ openssl s_client -connect localhost:31790
read R BLOCK
kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx
KEYUPDATE

```
Kết quả cho thấy có 2 cổng sử dụng `ssl` nhưng với cổng `31518/tcp` và service của nó là `echo`, tức là tất cả dữ liệu nào mình gửi vào nó nó sẽ trả lại y hệt nên ta sẽ dùng cổng còn lại. Và trong lúc dùng `openssl` để connect vào thì mình bị lỗi này và nó khồng ra key đúng cho mình, nên mình đã đọc trên mạng và thấy cách thay thế là dùng `echo` để truyền `password` thông qua `pipe` vào `openssl`:

```sh
bandit16@bandit:~$ echo 'kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx' | openssl s_client -quiet -connect localhost:31790
Can't use SSL_get_servername
depth=0 CN = SnakeOil
verify error:num=18:self-signed certificate
verify return:1
depth=0 CN = SnakeOil
verify return:1
Correct!
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvmOkuifmMg6HL2YPIOjon6iWfbp7c3jx34YkYWqUH57SUdyJ
imZzeyGC0gtZPGujUSxiJSWI/oTqexh+cAMTSMlOJf7+BrJObArnxd9Y7YT2bRPQ
Ja6Lzb558YW3FZl87ORiO+rW4LCDCNd2lUvLE/GL2GWyuKN0K5iCd5TbtJzEkQTu
DSt2mcNn4rhAL+JFr56o4T6z8WWAW18BR6yGrMq7Q/kALHYW3OekePQAzL0VUYbW
JGTi65CxbCnzc/w4+mqQyvmzpWtMAzJTzAzQxNbkR2MBGySxDLrjg0LWN6sK7wNX
x0YVztz/zbIkPjfkU1jHS+9EbVNj+D1XFOJuaQIDAQABAoIBABagpxpM1aoLWfvD
KHcj10nqcoBc4oE11aFYQwik7xfW+24pRNuDE6SFthOar69jp5RlLwD1NhPx3iBl
J9nOM8OJ0VToum43UOS8YxF8WwhXriYGnc1sskbwpXOUDc9uX4+UESzH22P29ovd
d8WErY0gPxun8pbJLmxkAtWNhpMvfe0050vk9TL5wqbu9AlbssgTcCXkMQnPw9nC
YNN6DDP2lbcBrvgT9YCNL6C+ZKufD52yOQ9qOkwFTEQpjtF4uNtJom+asvlpmS8A
vLY9r60wYSvmZhNqBUrj7lyCtXMIu1kkd4w7F77k+DjHoAXyxcUp1DGL51sOmama
+TOWWgECgYEA8JtPxP0GRJ+IQkX262jM3dEIkza8ky5moIwUqYdsx0NxHgRRhORT
8c8hAuRBb2G82so8vUHk/fur85OEfc9TncnCY2crpoqsghifKLxrLgtT+qDpfZnx
SatLdt8GfQ85yA7hnWWJ2MxF3NaeSDm75Lsm+tBbAiyc9P2jGRNtMSkCgYEAypHd
HCctNi/FwjulhttFx/rHYKhLidZDFYeiE/v45bN4yFm8x7R/b0iE7KaszX+Exdvt
SghaTdcG0Knyw1bpJVyusavPzpaJMjdJ6tcFhVAbAjm7enCIvGCSx+X3l5SiWg0A
R57hJglezIiVjv3aGwHwvlZvtszK6zV6oXFAu0ECgYAbjo46T4hyP5tJi93V5HDi
Ttiek7xRVxUl+iU7rWkGAXFpMLFteQEsRr7PJ/lemmEY5eTDAFMLy9FL2m9oQWCg
R8VdwSk8r9FGLS+9aKcV5PI/WEKlwgXinB3OhYimtiG2Cg5JCqIZFHxD6MjEGOiu
L8ktHMPvodBwNsSBULpG0QKBgBAplTfC1HOnWiMGOU3KPwYWt0O6CdTkmJOmL8Ni
blh9elyZ9FsGxsgtRBXRsqXuz7wtsQAgLHxbdLq/ZJQ7YfzOKU4ZxEnabvXnvWkU
YOdjHdSOoKvDQNWu6ucyLRAWFuISeXw9a/9p7ftpxm0TSgyvmfLF2MIAEwyzRqaM
77pBAoGAMmjmIJdjp+Ez8duyn3ieo36yrttF5NSsJLAbxFpdlc1gvtGCWW+9Cq0b
dxviW8+TFVEBl1O4f7HVm6EpTscdDxU+bCXWkfjuRb7Dy9GOtt9JPsX8MBTakzh3
vBgsyi/sN3RqRBcGU40fOoZyfAMT8s1m/uYv52O6IgeuZ/ujbjY=
-----END RSA PRIVATE KEY-----
```

Và việc ta cần làm là lấy `RSA` key đó và connect vào level sau thôi

# Level 17 → Level 18

## Goal

There are 2 files in the homedirectory: passwords.old and passwords.new. The password for the next level is in passwords.new and is the only line that has been changed between passwords.old and passwords.new

NOTE: if you have solved this level and see ‘Byebye!’ when trying to log into bandit18, this is related to the next level, bandit19

## Solution


Challenge này thì khá là đơn giản ta chỉ cần sử dụng lệnh `diff` để so sánh sự khác giữa 2 file thôi
```sh
bandit17@bandit:~$ diff passwords.new passwords.old
42c42
< x2gLTTjFwMOhQ8oWNbMN362QKxfRqGlO
---
> ktfgBvpMzWKR5ENj26IbLGSblgUG9CzB
```

Password của ta sẽ là `x2gLTTjFwMOhQ8oWNbMN362QKxfRqGlO` vì mình đặt vị trí thứ nhất là `password.new`

# Level 18 → Level 19

## Goal

The password for the next level is stored in a file readme in the homedirectory. Unfortunately, someone has modified .bashrc to log you out when you log in with SSH.

## Solution

`.bashrc` là một file chạy tất cả những command khi terminal vừa load, điều này đồng nghĩa với việc nó cũng sẽ chạy khi ta login vô bằng `ssh` vì cơ bản nó cũng sẽ mở ra cho ta một terminal

Đọc manpage `ssh` ta thấy:

![alt text](image-2.png)

Điều này cho ta biết, khi ta connect bằng `ssh` và người dùng được xác định (tức là đúng password), thì lúc này `ssh` sẽ thực hiện command mà ta cung cấp, và nếu không có thì nó sẽ mở một shell để tương tác giữa người dùng và terminal. Khi có yêu cầu phiên tương tác, SSH mặc định sẽ chỉ yêu cầu một `pseudo-terminal (pty)` nếu máy khách có. Ta có thể dùng `-t` để bắt buộc cấp một `pseudo-terminal (pty)` kể cả khi không cần thiết. Vì thế dới đây mình sẽ làm 2 cách:

- Cách 1:
  ```sh
  alter ^ Sol in ~
  $ ssh bandit18@bandit.labs.overthewire.org -p 2220 cat readme
                          _                     _ _ _
                          | |__   __ _ _ __   __| (_) |_
                          | '_ \ / _` | '_ \ / _` | | __|
                          | |_) | (_| | | | | (_| | | |_
                          |_.__/ \__,_|_| |_|\__,_|_|\__|


                        This is an OverTheWire game server.
              More information on http://www.overthewire.org/wargames

  bandit18@bandit.labs.overthewire.org's password:
  cGWpMaKXVwDUNgPAVJbWYuGHVn9zl3j8
  ```

- Cách 2:

```sh
alter ^ Sol in ~
$ ssh bandit18@bandit.labs.overthewire.org -p 2220 -t /bin/sh
                         _                     _ _ _
                        | |__   __ _ _ __   __| (_) |_
                        | '_ \ / _` | '_ \ / _` | | __|
                        | |_) | (_| | | | | (_| | | |_
                        |_.__/ \__,_|_| |_|\__,_|_|\__|


                      This is an OverTheWire game server.
            More information on http://www.overthewire.org/wargames

bandit18@bandit.labs.overthewire.org's password:
$ ls
readme
$ cat readme
cGWpMaKXVwDUNgPAVJbWYuGHVn9zl3j8
```

# Level 19 → Level 20

## Goal

To gain access to the next level, you should use the setuid binary in the homedirectory. Execute it without arguments to find out how to use it. The password for this level can be found in the usual place (/etc/bandit_pass), after you have used the setuid binary.

## Solution

Như đã giải thích trong phần [[TRAINING BCM] - Lý thuyết về Linux](https://4lt3rr.github.io/posts/ehc/task2/training_bcm_ehc_ly_thuyet_ve_linux/), một file setuid sẽ giúp ta thực hiện quyền của người sở hữu nó cụ thể ở đây:

```sh
bandit19@bandit:~$ id
uid=11019(bandit19) gid=11019(bandit19) groups=11019(bandit19)
bandit19@bandit:~$ ls -la
total 36
drwxr-xr-x  2 root     root      4096 Sep 19 07:08 .
drwxr-xr-x 70 root     root      4096 Sep 19 07:09 ..
-rwsr-x---  1 bandit20 bandit19 14880 Sep 19 07:08 bandit20-do
-rw-r--r--  1 root     root       220 Mar 31  2024 .bash_logout
-rw-r--r--  1 root     root      3771 Mar 31  2024 .bashrc
-rw-r--r--  1 root     root       807 Mar 31  2024 .profile
```

Ta thấy ta đang ở user `bandit19` và file SUID `bandit20-do` kia là do user `bandit20` sở hữu, tức là khi ta chạy file này là ta đang chạy với quyền của user `bandit20`:

```sh
bandit19@bandit:~$ ls -la
total 36
drwxr-xr-x  2 root     root      4096 Sep 19 07:08 .
drwxr-xr-x 70 root     root      4096 Sep 19 07:09 ..
-rwsr-x---  1 bandit20 bandit19 14880 Sep 19 07:08 bandit20-do
-rw-r--r--  1 root     root       220 Mar 31  2024 .bash_logout
-rw-r--r--  1 root     root      3771 Mar 31  2024 .bashrc
-rw-r--r--  1 root     root       807 Mar 31  2024 .profile
bandit19@bandit:~$ ./bandit20-do id
uid=11019(bandit19) gid=11019(bandit19) euid=11020(bandit20) groups=11019(bandit19)
```

Lúc này ta thấy có sự xuất hiện của `euid(Effective User ID)`, là do file SUID đó đang chạy với quyền của user `bandit20` thay vì là của user `bandit19`

Và cuối cùng là sử dụng nó để lấy password thôi

```sh
bandit19@bandit:~$ ./bandit20-do ls /etc/bandit_pass
bandit0  bandit10  bandit12  bandit14  bandit16  bandit18  bandit2   bandit21  bandit23  bandit25  bandit27  bandit29  bandit30  bandit32  bandit4  bandit6  bandit8
bandit1  bandit11  bandit13  bandit15  bandit17  bandit19  bandit20  bandit22  bandit24  bandit26  bandit28  bandit3   bandit31  bandit33  bandit5  bandit7  bandit9
bandit19@bandit:~$ ./bandit20-do cat /etc/bandit_pass/bandit20
0qXahG8ZjOVMN9Ghs7iOWsCfZyXOUbYO
```

# Level 20 → Level 21

## Goal

There is a setuid binary in the homedirectory that does the following: it makes a connection to localhost on the port you specify as a commandline argument. It then reads a line of text from the connection and compares it to the password in the previous level (bandit20). If the password is correct, it will transmit the password for the next level (bandit21).

NOTE: Try connecting to your own network daemon to see if it works as you think

## Solution

```sh
bandit20@bandit:~$ ls
suconnect
bandit20@bandit:~$ ./suconnect
Usage: ./suconnect <portnumber>
This program will connect to the given port on localhost using TCP. If it receives the correct password from the other side, the next password is transmitted back.
```

Đối với level này ta cần phải tạo một connection nghe ở một cổng nào đó, và bên cạnh đó ta cần phải gửi mật khẩu của ta vào port này trước khi chạy file SUID, để làm được điều đó ta sẽ sử dụng `nc` để mở một connect listen các connect tới nó và sử dụng `echo -n` để khi có connect nào tới nó sẻ gửi password đó (`-n` để loại bỏ đi newline trong password (nếu có))

```sh
bandit20@bandit:~$ echo -n '0qXahG8ZjOVMN9Ghs7iOWsCfZyXOUbYO' | nc -lp 4444 &
[1] 3619266
bandit20@bandit:~$ ./suconnect 4444
Read: 0qXahG8ZjOVMN9Ghs7iOWsCfZyXOUbYO
Password matches, sending next password
EeoULMCra2q0dSkYj561DX7s1CpBuOBt
[1]+  Done                    echo -n '0qXahG8ZjOVMN9Ghs7iOWsCfZyXOUbYO' | nc -lp 4444
```

# Level 21 → Level 22

## Goal

A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.

## Solution

`cronjobs` là một chương trình dùng để quản lý lịch trình chạy một số proccess trong `Linux`. Và để xem được các `config` đã có trong `cron` ta có thể xem ở `/etc/cron.d`

```sh
bandit21@bandit:~$ ls -la /etc/cron.d
total 44
drwxr-xr-x   2 root root  4096 Sep 19 07:10 .
drwxr-xr-x 121 root root 12288 Sep 20 18:37 ..
-rw-r--r--   1 root root   120 Sep 19 07:08 cronjob_bandit22
-rw-r--r--   1 root root   122 Sep 19 07:08 cronjob_bandit23
-rw-r--r--   1 root root   120 Sep 19 07:08 cronjob_bandit24
-rw-r--r--   1 root root   201 Apr  8  2024 e2scrub_all
-rwx------   1 root root    52 Sep 19 07:10 otw-tmp-dir
-rw-r--r--   1 root root   102 Mar 31  2024 .placeholder
-rw-r--r--   1 root root   396 Jan  9  2024 sysstat
bandit21@bandit:~$ cat /etc/cron.d/cronjob_bandit22
@reboot bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
* * * * * bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
```

Ở đây mình chỉ chú ý vào `cronjob_bandit22`, đọc nó thì ta có thể biết được nó chạy file `/usr/bin/cronjob_bandit22.sh`, với 5 sao là thể hiện cho việc nó sẽ chạy file đó mỗi phút và mỗi ngày

```sh
bandit21@bandit:~$ cat /usr/bin/cronjob_bandit22.sh
#!/bin/bash
chmod 644 /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
cat /etc/bandit_pass/bandit22 > /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
bandit21@bandit:~$ cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
tRae0UfB9v0UzbCdn9cY0gQnds9GF58Q
```

Sau đó mình phân tích sâu bên trong file đó xem nó thực thi những gì thì ta tháy nó cấp quyền `rw-` của file `/tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv` cho group và other. Sau đó đọc và lưu dữ liệu vào `/tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv` và với quyền `rw-` ta hoàn toàn có thể đọc file đó và lấy password

# Level 22 → Level 23

## Goal

A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.

NOTE: Looking at shell scripts written by other people is a very useful skill. The script for this level is intentionally made easy to read. If you are having problems understanding what it does, try executing it to see the debug information it prints.

## Solution

Như level trên và mình sẽ không giải thích nhiều ở đây

```sh
bandit22@bandit:~$ ls -la /etc/cron.d
total 44
drwxr-xr-x   2 root root  4096 Sep 19 07:10 .
drwxr-xr-x 121 root root 12288 Sep 20 18:37 ..
-rw-r--r--   1 root root   120 Sep 19 07:08 cronjob_bandit22
-rw-r--r--   1 root root   122 Sep 19 07:08 cronjob_bandit23
-rw-r--r--   1 root root   120 Sep 19 07:08 cronjob_bandit24
-rw-r--r--   1 root root   201 Apr  8  2024 e2scrub_all
-rwx------   1 root root    52 Sep 19 07:10 otw-tmp-dir
-rw-r--r--   1 root root   102 Mar 31  2024 .placeholder
-rw-r--r--   1 root root   396 Jan  9  2024 sysstat
bandit22@bandit:~$ cat /etc/cron.d//etc/cron.d
cat: /etc/cron.d//etc/cron.d: No such file or directory
bandit22@bandit:~$ cat /etc/cron.d/cronjob_bandit23
@reboot bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
* * * * * bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
bandit22@bandit:~$ cat /usr/bin/cronjob_bandit23.sh
#!/bin/bash

myname=$(whoami)
mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)

echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"

cat /etc/bandit_pass/$myname > /tmp/$mytarget
bandit22@bandit:~$ echo I am user bandit23 | md5sum | cut -d ' ' -f 1
8ca319486bfbbc3663ea0fbe81326349
bandit22@bandit:~$ cat /tmp/8ca319486bfbbc3663ea0fbe81326349
0Zf11ioIjMVN551jX3CmStKLYqjk54Ga
```

# Level 23 → Level 24

## Goal

A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.

NOTE: This level requires you to create your own first shell-script. This is a very big step and you should be proud of yourself when you beat this level!

NOTE 2: Keep in mind that your shell script is removed once executed, so you may want to keep a copy around…

## Solution

Các bước cũng khá giống như các level trước nên mình sẽ không giải thích nhiều ở đây:

```sh
bandit23@bandit:~$ ls
bandit23@bandit:~$ ls -la /etc/cron.d
total 44
drwxr-xr-x   2 root root  4096 Sep 19 07:10 .
drwxr-xr-x 121 root root 12288 Sep 20 18:37 ..
-rw-r--r--   1 root root   120 Sep 19 07:08 cronjob_bandit22
-rw-r--r--   1 root root   122 Sep 19 07:08 cronjob_bandit23
-rw-r--r--   1 root root   120 Sep 19 07:08 cronjob_bandit24
-rw-r--r--   1 root root   201 Apr  8  2024 e2scrub_all
-rwx------   1 root root    52 Sep 19 07:10 otw-tmp-dir
-rw-r--r--   1 root root   102 Mar 31  2024 .placeholder
-rw-r--r--   1 root root   396 Jan  9  2024 sysstat
bandit23@bandit:~$ cat /etc/cron.d/cronjob_bandit24
@reboot bandit24 /usr/bin/cronjob_bandit24.sh &> /dev/null
* * * * * bandit24 /usr/bin/cronjob_bandit24.sh &> /dev/null
bandit23@bandit:~$ cat /usr/bin/cronjob_bandit24.sh
#!/bin/bash

myname=$(whoami)

cd /var/spool/$myname/foo
echo "Executing and deleting all scripts in /var/spool/$myname/foo:"
for i in * .*;
do
    if [ "$i" != "." -a "$i" != ".." ];
    then
        echo "Handling $i"
        owner="$(stat --format "%U" ./$i)"
        if [ "${owner}" = "bandit23" ]; then
            timeout -s 9 60 ./$i
        fi
        rm -f ./$i
    fi
done
```

Với đoạn `bash script` ta thấy được thì nó sẽ xoá các thư mục trong `/var/spool/bandit24/foo` vì lúc này nó chạy với quyền của user `bandit24`. Điều kiện `if` sẽ check mỗi file mà nó chạy qua có nằm trong thư mục đặc biệt như là `.` hay `..` không. Và điều kiện `if` thứ 2 nằm bên trong đó sẽ check xem file đó có phải của user `bandit23` hay không, và nếu có nó sẽ thực thi lệnh bên trong `if` đó và sau đó xoá file đó đi

Vì ta biết rằng mỗi file sẽ được thực thi với quyền của `bandit24` và khi thực thi xong trong 60s nó sẽ xoá tệp đó đi. Như vậy việc ta sẽ làm là viết một file bash script và đặt nó trong `/var/spool/bandit24/foo`

```sh
bandit23@bandit:~$ cd /tmp
bandit23@bandit:/tmp$ mktemp -d
/tmp/tmp.lLRyk9z2Ce
bandit23@bandit:/tmp$ cd /tmp/tmp.lLRyk9z2Ce
bandit23@bandit:/tmp/tmp.lLRyk9z2Ce$ chmod 777 /tmp/tmp.lLRyk9z2Ce
bandit23@bandit:/tmp/tmp.lLRyk9z2Ce$ touch script.sh
bandit23@bandit:/tmp/tmp.lLRyk9z2Ce$ chmod 777 script.sh
bandit23@bandit:/tmp/tmp.lLRyk9z2Ce$ vim script.sh
bandit23@bandit:/tmp/tmp.lLRyk9z2Ce$ touch password.txt
bandit23@bandit:/tmp/tmp.lLRyk9z2Ce$ chmod 777 password.txt
bandit23@bandit:/tmp/tmp.lLRyk9z2Ce$ cat script.sh
#!/usr/bin/sh
cat /etc/bandit_pass/bandit24 > /tmp/tmp.lLRyk9z2Ce/password.txt
bandit23@bandit:/tmp/tmp.lLRyk9z2Ce$ cp script.sh /var/spool/bandit24/foo/password_script.sh
bandit23@bandit:/tmp/tmp.lLRyk9z2Ce$ cat password.txt
gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8
```

# Level 24 -> Level 25

## Goal

A daemon is listening on port 30002 and will give you the password for bandit25 if given the password for bandit24 and a secret numeric 4-digit pincode. There is no way to retrieve the pincode except by going through all of the 10000 combinations, called brute-forcing.
You do not need to create new connections each time

## Solution

Theo như đề bài thì lần này ta cần phải viết một bash script để brute force các number và các number này mình nghĩ nó chạy từ 0000 -> 9999 và sau đây là cách giải của mình

```sh
bandit24@bandit:~$ cd /tmp
bandit24@bandit:/tmp$ mktemp -d
/tmp/tmp.OP4szua1PC
bandit24@bandit:/tmp$ cd /tmp/tmp.OP4szua1PC
bandit24@bandit:/tmp/tmp.OP4szua1PC$ chmod 777 /tmp/tmp.OP4szua1PC
bandit24@bandit:/tmp/tmp.OP4szua1PC$ touch brute.sh
bandit24@bandit:/tmp/tmp.OP4szua1PC$ chmod 777 brute.sh
bandit24@bandit:/tmp/tmp.OP4szua1PC$ nano brute.sh
bandit24@bandit:/tmp/tmp.OP4szua1PC$ cat brute.sh
#!/usr/bin/sh

for i in {0000..9999}

do
        echo gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8 $i >> output.txt
done

cat output.txt | nc localhost 30002 > result.txt
bandit24@bandit:/tmp/tmp.OP4szua1PC$ ./brute.sh
bandit24@bandit:/tmp/tmp.OP4szua1PC$ cat result.txt | grep "is"
The password of user bandit25 is iCi86ttT4KSNe1armKiwbQNmB3YJP3q4
```

Lưu ý sự khác biệt giữa:

- `>` là ghi đè dữ liệu
- `>>` là giữ lại dữ liệu cũ và thêm tiếp dữ liệu mới vào sau

# Level 25 -> Level 26

## Goal

Logging in to bandit26 from bandit25 should be fairly easy… The shell for user bandit26 is not /bin/bash, but something else. Find out what it is, how it works and how to break out of it.

NOTE: if you’re a Windows user and typically use Powershell to ssh into bandit: Powershell is known to cause issues with the intended solution to this level. You should use command prompt instead.

## Solution

Welp, vậy đầu tiên ta nên check xem shell mà `bandit26` đang dùng là gì:

```sh
bandit25@bandit:~$ ls
bandit26.sshkey
bandit25@bandit:~$ cat /etc/passwd | grep "bandit26"
bandit26:x:11026:11026:bandit level 26:/home/bandit26:/usr/bin/showtext
bandit25@bandit:~$ ls -la /usr/bin/showtext
-rwxr-xr-x 1 root root 58 Sep 19 07:08 /usr/bin/showtext
bandit25@bandit:~$ cat /usr/bin/showtext
#!/bin/sh

export TERM=linux

exec more ~/text.txt
exit 0
```

Như vậy nó, khi ta connect vào nó sẽ hiện lên cái gì đó trong `text.txt`, và mình đã thử connect vào:

```sh
alter ^ Sol in ~
$ subl ssh25.private
alter ^ Sol in ~
$ chmod 600 ssh25.private
alter ^ Sol in ~
$ ssh bandit26@bandit.labs.overthewire.org -p 2220 -i ssh25.private
                         _                     _ _ _
                        | |__   __ _ _ __   __| (_) |_
                        | '_ \ / _` | '_ \ / _` | | __|
                        | |_) | (_| | | | | (_| | | |_
                        |_.__/ \__,_|_| |_|\__,_|_|\__|


                      This is an OverTheWire game server.
            More information on http://www.overthewire.org/wargames


      ,----..            ,----,          .---.
     /   /   \         ,/   .`|         /. ./|
    /   .     :      ,`   .'  :     .--'.  ' ;
   .   /   ;.  \   ;    ;     /    /__./ \ : |
  .   ;   /  ` ; .'___,/    ,' .--'.  '   \' .
  ;   |  ; \ ; | |    :     | /___/ \ |    ' '
  |   :  | ; | ' ;    |.';  ; ;   \  \;      :
  .   |  ' ' ' : `----'  |  |  \   ;  `      |
  '   ;  \; /  |     '   :  ;   .   \    .\  ;
   \   \  ',  /      |   |  '    \   \   ' \ |
    ;   :    /       '   :  |     :   '  |--"
     \   \ .'        ;   |.'       \   \ ;
  www. `---` ver     '---' he       '---" ire.org


Welcome to OverTheWire!

If you find any problems, please report them to the #wargames channel on
discord or IRC.

--[ Playing the games ]--

  This machine might hold several wargames.
  If you are playing "somegame", then:

    * USERNAMES are somegame0, somegame1, ...
    * Most LEVELS are stored in /somegame/.
    * PASSWORDS for each level are stored in /etc/somegame_pass/.

  Write-access to homedirectories is disabled. It is advised to create a
  working directory with a hard-to-guess name in /tmp/.  You can use the
  command "mktemp -d" in order to generate a random and hard to guess
  directory in /tmp/.  Read-access to both /tmp/ is disabled and to /proc
  restricted so that users cannot snoop on eachother. Files and directories
  with easily guessable or short names will be periodically deleted! The /tmp
  directory is regularly wiped.
  Please play nice:

    * don't leave orphan processes running
    * don't leave exploit-files laying around
    * don't annoy other players
    * don't post passwords or spoilers
    * again, DONT POST SPOILERS!
      This includes writeups of your solution on your blog or website!

--[ Tips ]--

  This machine has a 64bit processor and many security-features enabled
  by default, although ASLR has been switched off.  The following
  compiler flags might be interesting:

    -m32                    compile for 32bit
    -fno-stack-protector    disable ProPolice
    -Wl,-z,norelro          disable relro

  In addition, the execstack tool can be used to flag the stack as
  executable on ELF binaries.

  Finally, network-access is limited for most levels by a local
  firewall.

--[ Tools ]--

 For your convenience we have installed a few useful tools which you can find
 in the following locations:

    * gef (https://github.com/hugsy/gef) in /opt/gef/
    * pwndbg (https://github.com/pwndbg/pwndbg) in /opt/pwndbg/
    * gdbinit (https://github.com/gdbinit/Gdbinit) in /opt/gdbinit/
    * pwntools (https://github.com/Gallopsled/pwntools)
    * radare2 (http://www.radare.org/)

--[ More information ]--

  For more information regarding individual wargames, visit
  http://www.overthewire.org/wargames/

  For support, questions or comments, contact us on discord or IRC.

  Enjoy your stay!

  _                     _ _ _   ___   __
 | |                   | (_) | |__ \ / /
 | |__   __ _ _ __   __| |_| |_   ) / /_
 | '_ \ / _` | '_ \ / _` | | __| / / '_ \
 | |_) | (_| | | | | (_| | | |_ / /| (_) |
 |_.__/ \__,_|_| |_|\__,_|_|\__|____\___/
Connection to bandit.labs.overthewire.org closed.
```

Vấn đề ở đây là nằm ở `more`, đoạn text nó show ra quá ngắn, nên `more` sẽ không vào `command` mode cho chúng ta. việc ta cần làm là trigger `more` để nó vào command mode cho ta, và từ đó sử dụng `v` để mở vim và sử dụng `:set shell=/bin/sh`.
Để làm được điều đó ta cần thu nhỏ terminal của ta lại và chạy `ssh`

![alt text](image-3.png)

Và như thế ta đã mở được shell

![alt text](image-4.png)

```sh
bandit26@bandit:~$ ls
bandit27-do  text.txt
bandit26@bandit:~$ cat text.txt
  _                     _ _ _   ___   __
 | |                   | (_) | |__ \ / /
 | |__   __ _ _ __   __| |_| |_   ) / /_
 | '_ \ / _` | '_ \ / _` | | __| / / '_ \
 | |_) | (_| | | | | (_| | | |_ / /| (_) |
 |_.__/ \__,_|_| |_|\__,_|_|\__|____\___/
bandit26@bandit:~$ cat /etc/bandit\_pass/bandit26
s0773xxkk0MXfdqOfPRVr9L3jJBUOgCZ
```

Thật ra có khá nhiều cách, nhưng mình làm cách này để tiện cho level sau

# Level 26 -> Level 27

## Goal

Good job getting a shell! Now hurry and grab the password for bandit27!

## Solution

Việc có được shell rồi thì level này khá là đơn giản

```sh
bandit26@bandit:~$ ls
bandit27-do  text.txt
bandit26@bandit:~$ ./bandit27-do
Run a command as another user.
  Example: ./bandit27-do id
bandit26@bandit:~$ ./bandit27-do id
uid=11026(bandit26) gid=11026(bandit26) euid=11027(bandit27) groups=11026(bandit26)
bandit26@bandit:~$ ./bandit27-do cat /etc/bandit_pass/bandit27
upsNCc7vzaRDx6oZC6GiR6ERwe1MowGB
```

Lưu ý rằng ta phải làm nhanh vì shell này sẽ close ngay sau đó

# Level 27 -> Level 28

## Goal

There is a git repository at ssh://bandit27-git@localhost/home/bandit27-git/repo via the port 2220. The password for the user bandit27-git is the same as for the user bandit27.

Clone the repository and find the password for the next level.

## Solution

Để tìm hiểu về các lệnh của `git` thì ta có thể đọc ở [đây](https://education.github.com/git-cheat-sheet-education.pdf)

```sh
bandit27@bandit:~$ ls
bandit27@bandit:~$ cd /tmp/
bandit27@bandit:/tmp$ mktemp -d
/tmp/tmp.6qWVuT7KqO
bandit27@bandit:/tmp$ cd /tmp/tmp.6qWVuT7KqO
bandit27@bandit:/tmp/tmp.6qWVuT7KqO$ chmod 777 /tmp/tmp.6qWVuT7KqO
bandit27@bandit:/tmp/tmp.6qWVuT7KqO$ git init
hint: Using 'master' as the name for the initial branch. This default branch name
hint: is subject to change. To configure the initial branch name to use in all
hint: of your new repositories, which will suppress this warning, call:
hint:
hint:   git config --global init.defaultBranch <name>
hint:
hint: Names commonly chosen instead of 'master' are 'main', 'trunk' and
hint: 'development'. The just-created branch can be renamed via this command:
hint:
hint:   git branch -m <name>
Initialized empty Git repository in /tmp/tmp.6qWVuT7KqO/.git/
bandit27@bandit:/tmp/tmp.6qWVuT7KqO$ git clone ssh://bandit27-git@localhost:2220/home/bandit27-git/repo
Cloning into 'repo'...
The authenticity of host '[localhost]:2220 ([127.0.0.1]:2220)' can't be established.
ED25519 key fingerprint is SHA256:C2ihUBV7ihnV1wUXRb4RrEcLfXC5CXlhmAAM/urerLY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Could not create directory '/home/bandit27/.ssh' (Permission denied).
Failed to add the host to the list of known hosts (/home/bandit27/.ssh/known_hosts).
                         _                     _ _ _
                        | |__   __ _ _ __   __| (_) |_
                        | '_ \ / _` | '_ \ / _` | | __|
                        | |_) | (_| | | | | (_| | | |_
                        |_.__/ \__,_|_| |_|\__,_|_|\__|


                      This is an OverTheWire game server.
            More information on http://www.overthewire.org/wargames

bandit27-git@localhost's password:
Permission denied, please try again.
bandit27-git@localhost's password:
remote: Enumerating objects: 3, done.
remote: Counting objects: 100% (3/3), done.
remote: Compressing objects: 100% (2/2), done.
Receiving objects: 100% (3/3), 285 bytes | 285.00 KiB/s, done.
remote: Total 3 (delta 0), reused 0 (delta 0), pack-reused 0
bandit27@bandit:/tmp/tmp.6qWVuT7KqO$ ls
repo
bandit27@bandit:/tmp/tmp.6qWVuT7KqO$ cd repo/
bandit27@bandit:/tmp/tmp.6qWVuT7KqO/repo$ ls
README
bandit27@bandit:/tmp/tmp.6qWVuT7KqO/repo$ cat README
The password to the next level is: Yz9IpL0sBcCeuG7m9uQFt8ZNpS4HZRcN
```

# Level 28 -> Level 29

## Goal

There is a git repository at via the port 2220. The password for the user bandit28-git is the same as for the user bandit28.

Clone the repository and find the password for the next level.

## Solution

Level này cũng vậy, cũng là xoay quanh dùng các câu lệnh `git`

```sh
bandit28@bandit:/tmp/tmp.Cbob1wfcwg$ git clone ssh://bandit28-git@localhost:2220/home/bandit28-git/repo
Cloning into 'repo'...
The authenticity of host '[localhost]:2220 ([127.0.0.1]:2220)' can't be established.
ED25519 key fingerprint is SHA256:C2ihUBV7ihnV1wUXRb4RrEcLfXC5CXlhmAAM/urerLY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Could not create directory '/home/bandit28/.ssh' (Permission denied).
Failed to add the host to the list of known hosts (/home/bandit28/.ssh/known_hosts).
                         _                     _ _ _
                        | |__   __ _ _ __   __| (_) |_
                        | '_ \ / _` | '_ \ / _` | | __|
                        | |_) | (_| | | | | (_| | | |_
                        |_.__/ \__,_|_| |_|\__,_|_|\__|


                      This is an OverTheWire game server.
            More information on http://www.overthewire.org/wargames

bandit28-git@localhost's password:
remote: Enumerating objects: 9, done.
remote: Counting objects: 100% (9/9), done.
remote: Compressing objects: 100% (6/6), done.
remote: Total 9 (delta 2), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (9/9), done.
Resolving deltas: 100% (2/2), done.
bandit28@bandit:/tmp/tmp.Cbob1wfcwg$ cd repo
bandit28@bandit:/tmp/tmp.Cbob1wfcwg/repo$ ls
README.md
bandit28@bandit:/tmp/tmp.Cbob1wfcwg/repo$ cat README.md
# Bandit Notes
Some notes for level29 of bandit.

## credentials

- username: bandit29
- password: xxxxxxxxxx
```

Ở đây `file` đã có dấu hiệu thay đổi nên ta sẽ sử dụng `git log` để kiểm tra xem những thay đổi đó là gì

```sh
bandit28@bandit:/tmp/tmp.Cbob1wfcwg/repo$ git log
commit 817e303aa6c2b207ea043c7bba1bb7575dc4ea73 (HEAD -> master, origin/master, origin/HEAD)
Author: Morla Porla <morla@overthewire.org>
Date:   Thu Sep 19 07:08:39 2024 +0000

    fix info leak

commit 3621de89d8eac9d3b64302bfb2dc67e9a566decd
Author: Morla Porla <morla@overthewire.org>
Date:   Thu Sep 19 07:08:39 2024 +0000

    add missing data

commit 0622b73250502618babac3d174724bb303c32182
Author: Ben Dover <noone@overthewire.org>
Date:   Thu Sep 19 07:08:39 2024 +0000

    initial commit of README.md
```

Và ta thấy commit đầu là `fix info leak` có thể đây ám chỉ `password` nên ta sẽ sử dụng `git show` để xem `commit` đó

```sh
bandit28@bandit:/tmp/tmp.Cbob1wfcwg/repo$ git show 817e303aa6c2b207ea043c7bba1bb7575dc4ea73
commit 817e303aa6c2b207ea043c7bba1bb7575dc4ea73 (HEAD -> master, origin/master, origin/HEAD)
Author: Morla Porla <morla@overthewire.org>
Date:   Thu Sep 19 07:08:39 2024 +0000

    fix info leak

diff --git a/README.md b/README.md
index d4e3b74..5c6457b 100644
--- a/README.md
+++ b/README.md
@@ -4,5 +4,5 @@ Some notes for level29 of bandit.
 ## credentials

 - username: bandit29
-- password: 4pT1t5DENaYuqnqvadYs1oE4QLCdjmJ7
+- password: xxxxxxxxxx
```

# Level 29 → Level 30

## Goal

There is a git repository at ssh://bandit29-git@localhost/home/bandit29-git/repo via the port 2220. The password for the user bandit29-git is the same as for the user bandit29.

Clone the repository and find the password for the next level.

## Solution

Các bước đầu thì tương đối giống như các level trước đã làm

```sh
bandit29@bandit:/tmp/tmp.EPCgEEg3Xd$ git clone ssh://bandit29-git@localhost:2220/home/bandit29-git/repo
Cloning into 'repo'...
The authenticity of host '[localhost]:2220 ([127.0.0.1]:2220)' can't be established.
ED25519 key fingerprint is SHA256:C2ihUBV7ihnV1wUXRb4RrEcLfXC5CXlhmAAM/urerLY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Could not create directory '/home/bandit29/.ssh' (Permission denied).
Failed to add the host to the list of known hosts (/home/bandit29/.ssh/known_hosts).
                         _                     _ _ _
                        | |__   __ _ _ __   __| (_) |_
                        | '_ \ / _` | '_ \ / _` | | __|
                        | |_) | (_| | | | | (_| | | |_
                        |_.__/ \__,_|_| |_|\__,_|_|\__|


                      This is an OverTheWire game server.
            More information on http://www.overthewire.org/wargames

bandit29-git@localhost's password:
remote: Enumerating objects: 16, done.
remote: Counting objects: 100% (16/16), done.
remote: Compressing objects: 100% (11/11), done.
remote: Total 16 (delta 2), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (16/16), done.
Resolving deltas: 100% (2/2), done.
bandit29@bandit:/tmp/tmp.EPCgEEg3Xd$ ls
repo
bandit29@bandit:/tmp/tmp.EPCgEEg3Xd$ cd repo/
bandit29@bandit:/tmp/tmp.EPCgEEg3Xd/repo$ ls
README.md
bandit29@bandit:/tmp/tmp.EPCgEEg3Xd/repo$ cat README.md
# Bandit Notes
Some notes for bandit30 of bandit.

## credentials

- username: bandit30
- password: <no passwords in production!>
```

Ta thấy `<no passwords in production!>`, và sau khi mình kiểm tra bằng `git log` xem có thay đổi gì không thì vẫn không thấy gì đặc biệt

```sh
bandit29@bandit:/tmp/tmp.EPCgEEg3Xd/repo$ git log
commit 6ac7796430c0f39290a0e29a4d32e5126544b022 (HEAD -> master, origin/master, origin/HEAD)
Author: Ben Dover <noone@overthewire.org>
Date:   Thu Sep 19 07:08:41 2024 +0000

    fix username

commit e65a928cca4db1863b478cf5e93d1d5b1c1bd6b2
Author: Ben Dover <noone@overthewire.org>
Date:   Thu Sep 19 07:08:41 2024 +0000

    initial commit of README.md
```

Điều này còn có thể là do `repo` này có nhiều `branch` và mỗi `branch` này hoạt động riêng biệt nên ta không thể sử dụng `git log` để check như thông thường được. Vì thế ta cần dùng `git branch -a` để kiểm tra cách `branch` hiện có

```sh
bandit29@bandit:/tmp/tmp.EPCgEEg3Xd/repo$ git branch -a
* master
  remotes/origin/HEAD -> origin/master
  remotes/origin/dev
  remotes/origin/master
  remotes/origin/sploits-dev
```

Và việc còn lại là check từng `branch`

```sh
bandit29@bandit:/tmp/tmp.EPCgEEg3Xd/repo$ git checkout dev
branch 'dev' set up to track 'origin/dev'.
Switched to a new branch 'dev'
bandit29@bandit:/tmp/tmp.EPCgEEg3Xd/repo$ cat README.md
# Bandit Notes
Some notes for bandit30 of bandit.

## credentials

- username: bandit30
- password: qp30ex3VLz5MDG1n91YowTv4Q8l7CDZL
```

Trong lúc viết write up này thì mình nhận ra, ngay từ lúc mình đọc file `README` ở `main` thì nó đã có gợi ý cho `branch` của nó ở đâu rồi. Đó là `production` vì nếu nó không ở `production` thì có thể nó ở `development` <(")

# Level 30 → Level 31

## Goal

There is a git repository at ssh://bandit30-git@localhost/home/bandit30-git/repo via the port 2220. The password for the user bandit30-git is the same as for the user bandit30.

Clone the repository and find the password for the next level.

## Solution

Các bước đầu là giống nhau nên mình sẽ skip qua, và đi vô bước tiếp theo luôn

```sh
bandit30@bandit:/tmp/tmp.Gb4d3q3m7f/repo$ cat README.md
just an epmty file... muahaha
bandit30@bandit:/tmp/tmp.Gb4d3q3m7f/repo$ git log
commit acfc3c67816fc778c4aeb5893299451ca6d65a78 (HEAD -> master, origin/master, origin/HEAD)
Author: Ben Dover <noone@overthewire.org>
Date:   Thu Sep 19 07:08:44 2024 +0000

    initial commit of README.md
```

Search mạng thì mình biết được còn có thêm một lệnh đó là `git tag`

![alt text](image-5.png)

Vậy ta sẽ sử dụng nó để xem có gì thú vị

```sh
bandit30@bandit:/tmp/tmp.Gb4d3q3m7f/repo$ git tag
secret
bandit30@bandit:/tmp/tmp.Gb4d3q3m7f/repo$ git show secret
fb5S2xb7bRyFmAvQYQGEqsbhVyJqhnDy
```

và thế là ta đã có được flag

# Level 31 → Level 32

## Goal

There is a git repository at ssh://bandit31-git@localhost/home/bandit31-git/repo via the port 2220. The password for the user bandit31-git is the same as for the user bandit31.

Clone the repository and find the password for the next level.

## Solution

Các bước đầu giống nhau nên mình sẽ làm nhanh

```sh
bandit31@bandit:/tmp/tmp.yDkHHp3WFD/repo$ cat README.md
This time your task is to push a file to the remote repository.

Details:
    File name: key.txt
    Content: 'May I come in?'
    Branch: master
bandit31@bandit:/tmp/tmp.yDkHHp3WFD/repo$ cat .gitignore
*.txt
```

Như vậy ta thấy `.gitignore` là một file dùng để hạn chế các extention mà ta có thể `add` lên repo, nhưng trong trường hợp ta vẫn muốn add, thì ta sẽ sử dụng flag `-f` để ép nó phải add bằng mọi cách

```sh
bandit31@bandit:/tmp/tmp.yDkHHp3WFD/repo$ git add -f key.txt
bandit31@bandit:/tmp/tmp.yDkHHp3WFD/repo$ git commit -m 'test'
[master a093ff4] test
 1 file changed, 1 insertion(+)
 create mode 100644 key.txt
bandit31@bandit:/tmp/tmp.yDkHHp3WFD/repo$ git push -u origin master
The authenticity of host '[localhost]:2220 ([127.0.0.1]:2220)' can't be established.
ED25519 key fingerprint is SHA256:C2ihUBV7ihnV1wUXRb4RrEcLfXC5CXlhmAAM/urerLY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Could not create directory '/home/bandit31/.ssh' (Permission denied).
Failed to add the host to the list of known hosts (/home/bandit31/.ssh/known_hosts).
                         _                     _ _ _
                        | |__   __ _ _ __   __| (_) |_
                        | '_ \ / _` | '_ \ / _` | | __|
                        | |_) | (_| | | | | (_| | | |_
                        |_.__/ \__,_|_| |_|\__,_|_|\__|


                      This is an OverTheWire game server.
            More information on http://www.overthewire.org/wargames

bandit31-git@localhost's password:
Enumerating objects: 4, done.
Counting objects: 100% (4/4), done.
Delta compression using up to 2 threads
Compressing objects: 100% (2/2), done.
Writing objects: 100% (3/3), 318 bytes | 318.00 KiB/s, done.
Total 3 (delta 0), reused 0 (delta 0), pack-reused 0
remote: ### Attempting to validate files... ####
remote:
remote: .oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.
remote:
remote: Well done! Here is the password for the next level:
remote: 3O9RfhqyAlVBEZpVb6LYStshZoqoSx5K
remote:
remote: .oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.
remote:
To ssh://localhost:2220/home/bandit31-git/repo
 ! [remote rejected] master -> master (pre-receive hook declined)
error: failed to push some refs to 'ssh://localhost:2220/home/bandit31-git/repo'
```

# Level 32 -> Level 33

## Goal

After all this git stuff, it’s time for another escape. Good luck!

## Solution

```sh
WELCOME TO THE UPPERCASE SHELL
>> ls
sh: 1: LS: Permission denied
>> clear
sh: 1: CLEAR: Permission denied
>> LS
sh: 1: LS: Permission denied
```

Như ta thấy mọi command ta nhập vào đều bị `uppercase` đều này làm cho nó không thể nhận dạng được. Ở trong linux có một khái niệm gọi là `Environment Variable`. Bạn có thể đọc thêm ở [đây](https://www.geeksforgeeks.org/environment-variables-in-linux-unix/) để biết rõ hơn về nó

Như vậy ở đây sau khi mình research trên mạng (kèm theo đọc một số write up cho level này) thì mình thấy họ dùng `$0`. Mình tìm hiểu thêm thì thấy được rằng

![alt text](image-6.png)

Tức là nó là một biến đặc biệt biểu hiện cho tiến trình đăng chạy nó ví dụ mình sẽ tạo một file `test.sh`:

```sh
alter ^ Sol in ~
$ nano test.sh
alter ^ Sol in ~
$ chmod +x test.sh
alter ^ Sol in ~
$ cat test.sh
#!/usr/bin/sh

echo $0
alter ^ Sol in ~
$ ./test.sh
./test.sh
```

Như ta thấy nó sẽ in ra `./test.sh` là tiếng trình đã chạy nó, tương tự như vậy nếu ta sử dụng `echo $0` trên `terminal` thì sẽ như thế nào?

```sh
alter ^ Sol in ~
$ echo $0
-zsh
```

Ta sẽ thấy nó in ra `-zsh` tức là `shell` hiện tại mà máy mình đang dùng. Và khi ta sử dụng `$0` thì đơn giản là nó sẽ spawn `shell` cho mình

```sh
>> $0
$ ls
uppershell
$ cat /etc/bandit_pass/bandit33
tQdtbs5D5i2vJwkO8mEyYEyTL8izoeJ0
```
