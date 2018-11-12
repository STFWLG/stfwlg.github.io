---
layout: post
title: "[reversing.kr] ransomware 풀이"
date: 2018-08-09 14:00
categories: "[Rev]reversing.kr"
tags: "N0N4M3D"
---

# ransomware - [120pt]

![main](/pic/reversing_kr/ransomware/main.png)

문제 파일과 `readme.txt`의 내용입니다. `readme.txt`의 내용을 보고 `file`이라는 이름의 파일을 복호화하는 것이 문제이며 이 파일은 EXE 실행파일이라는 것을 알 수 있어요. `run.exe`를 실행해보면

![run_exe](/pic/reversing_kr/ransomware/run_exe.png)

위 사진과 같이 실행돼요. 어떤 나쁜놈이 파일을 암호화 시켜놓고 돈을 보내야 복호화 Key값을 준다네요. 5천억 달러를 달라는 거 보니깐 걍 안풀어주겠다는 심보네요(~~ㄹㅇ 나쁜넘~~). 저놈은 복구해 줄 생각이 전혀 없어보이니 직접 Key값을 찾아서 복구해봅시다.

## 1. 파일 분석
### 1-1. main 함수 찾기

![FIRST](/pic/reversing_kr/ransomware/FIRST.png)

디버깅 툴을 이용해서 EP로 가봤어요. 첫 부분 딱 보니깐 패킹되어있는 파일이네요! OEP를 찾고 트레이싱하면서 프로그램이 실행되는 부분의 함수를 찾았어요. `Step Into`해서 그 함수 안으로 들어가봤어요.

##### 그런데

![a](/pic/reversing_kr/ransomware/a.png)

{: refdef: style="text-align: center;"}
![what](/pic/reversing_kr/ransomware/what.jpg)
{: refdef}

<center>무엇?</center>

순간 졸라 당황했었어요. 정신차리고 올리디버거의 `all intermodular calls` 기능을 이용해서 함수들을 살펴봤어요

![intermodular_calls](/pic/reversing_kr/ransomware/intermodular_calls.png)

좀전에 `run.exe`를 실행해봤을 때 문자열을 출력하고 받고 출력해주는 순서로 프로그램이 실행이 되었어요. 함수들을 보니 BP 잡은 곳이 딱 그 부분이겠구나 했어요. 쨋튼 BP 잡고 f9로 실행해보니 예상한대로네요.

### 1-2. 루프문 분석

`main` 함수도 찾았으니 밑으로 내려가면서 쭉 분석해봤어요. 분석결과 저는 중요해보이는 두 개의 루프를 찾았어요!

#### 첫번째 루프

![loop1](/pic/reversing_kr/ransomware/loop1.png)

이게 제가 찾은 첫번째 루프문이에요. 하나하나씩 내려가면서 분석해보니 `file` 파일을 EOF일 때 까지 1바이트씩 받아와서 메모리에 적재시키는 루프문이였어요.

#### 두번째 루프

![loop2](/pic/reversing_kr/ransomware/loop2.png)

이 루프문은 메모리에 적재된 바이너리를 1바이트씩 두번의 XOR 연산을 통해 복호화 시켜주는 루프문이에요

![hex_view](/pic/reversing_kr/ransomware/hex_view.png)

![exchange_pe](/pic/reversing_kr/ransomware/exchange_pe.png)

위 사진이 `file` 파일을 헥스뷰어로 본 사진이고, 아래가 루프를 한 번 돈 후 메모리에 적재된 `file` 파일의 바이너리 값 입니다. 1바이트가 두 번의 XOR 연산으로 인해 값이 변경됐다는 것을 알 수 있어요. 두 번의 XOR 연산은 다음과 같이 진행됩니다.

>#### 바이너리 1byte ^ Key 1byte ^ 0xFF == 복호화 값

이 식을 변형해보면

>#### 바이너리 1byte ^ 0xFF ^ 복호화 값 == Key 1byte

라는 식이 만들어질 수 있어요. 

## 2. FLAG 구하기

`readme.txt`의 힌트를 보면 `file` 파일은 exe 파일이라고 하니 복호화 값은 정상적인 exe 파일의 처음 헤더 일부와 같을꺼에요. 따라서 정상적인 아무 exe 파일을 헥스뷰어로 열어 앞부분을 복사해 다음과 같이 코드를 짰어요

```python
real_pe = [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xB8]

FILE_pe = [0xDE, 0xC0, 0x1B, 0x8C, 0x8C, 0x93, 0x9E, 0x86, 0x98, 0x97, 0x9A, 0x8C, 0x73, 0x6C, 0x9A, 0x8B, 0x34]

for i in range(0, 17):
	real_num = FILE_pe[i] ^ real_pe[i] ^ 0xff
	print real_num
```

결과는

![expy](/pic/reversing_kr/ransomware/expy.png)

이렇게 나왔어요. 13번 주기로 반복하는 것 같아요! 따라서 Key 값은 13자리이며 이를 문자로 바꿔봤어요

```python
real_pe = [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xB8]

FILE_pe = [0xDE, 0xC0, 0x1B, 0x8C, 0x8C, 0x93, 0x9E, 0x86, 0x98, 0x97, 0x9A, 0x8C, 0x73, 0x6C, 0x9A, 0x8B, 0x34]

print '(',
for i in range(0, 13):
	real_num = FILE_pe[i] ^ real_pe[i] ^ 0xff
	print (chr(real_num)),
	
print ') IS REAL KEY!!!'
```

![KEY](/pic/reversing_kr/ransomware/KEY.png)

Key 값이 출력이 되었어요. 이건 아직 flag가 아닌 그냥 복호화 코드에요. `run.exe`에서 이 문자열을 넣고 실행시키고난 후 `file`파일의 확장자를 exe로 변경해 실행시켜보면

![flag](/pic/reversing_kr/ransomware/flag.png)

문제 답이 나와요!!!
