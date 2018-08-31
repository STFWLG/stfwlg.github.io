---
layout: post
title: "[pwnable.kr] blukat 풀이"
date: 2018-08-31 13:43
categories: "[Pwn]pwnable.kr"
tags: "#UnKN0wn"
---
>## blukat - [3pt]
### Sometimes, pwnable is strange...
### hint: if this challenge is hard, you are a skilled player.<br><br>
### ssh blukat@pwnable.kr -p2222 (pw: guest)

---

힌트를 보면 pwnable에 숙련된 사람은 이 문제가 어려울 수가 있다네요.

~~그럼 나한텐 엄청 쉽겠...~~

일단 문제 소스부터 한번 봅시다

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
char flag[100];
char password[100];
char* key = "3\rG[S/%\x1c\x1d#0?\rIS\x0f\x1c\x1d\x18;,4\x1b\x00\x1bp;5\x0b\x1b\x08\x45+";
void calc_flag(char* s){
	int i;
	for(i=0; i<strlen(s); i++){
		flag[i] = s[i] ^ key[i];
	}
	printf("%s\n", flag);
}
int main(){
	FILE* fp = fopen("/home/blukat/password", "r");
	fgets(password, 100, fp);
	char buf[100];
	printf("guess the password!\n");
	fgets(buf, 128, stdin);
	if(!strcmp(password, buf)){
		printf("congrats! here is your flag: ");
		calc_flag(password);
	}
	else{
		printf("wrong guess!\n");
		exit(0);
	}
	return 0;
}
```

소스를 보면 password 파일에서 100 바이트만큼 읽어서 `password`에 저장합니다

그리고 `buf`에 128 바이트만큼 입력받고, 이 두 값이 같으면 `flag`를 출력해주는 프로그램이네요

이 `password` 값을 알아내기위해 gdb-peda를 이용해 fgets로 `password` 값을 받아오는

부분에 BP를 걸고 실행시켜봤어요

![gdb_peda](/pic/pwnable_kr/blukat/gdb_peda_blukat.png)

RAX 레지스터에 `password`에서 받아온 문자열이 있네요. 저 문자열은 권한없을 때 나오는 문장인데?

`id`와 `ls -l` 명령어로 권한을 확인해보니 `blukat_pwn` 그룹 권한에 읽기 권한이 있는데

저런 문장이 나와요. 훼이크인가 보네요! blukat 실행시키고 문자열 넣으니 flag가 나왔어요

![flag_blukat](/pic/pwnable_kr/blukat/flag_blukat.png)


