---
layout: post
title: "hctf writeup"
date: 2014-11-10 23:15:57 -0700
comments: true
categories: binary
---
author: anhkgg

### 丘比龙的最爱

传说，丘比龙是丘比特的弟弟，丘比龙是一只小爱神，虽然有两只翅膀，但因为吃多了，导致身体太胖，所以飞不起来~那么问题来了?!丘比龙吃什么食物吃多了变胖了
百度之：甜甜圈

<!--more-->
### nvshen

猫流大大发现一个女神，你能告诉我女神的名字么（名字即是flag）http://107.189.158.112/0aab9b20410fdd880c53922048023266/nvshen.zip
打开大量数据，感觉是base64，解密了前一部分数据看到PNG, IHDR字符，应该就是png图片了，然后python写了段脚本：

    import base64
    f1 = open(“nvshen.txt”, “r”)
    f2 = open(“nvshen.png”, “wb”)
    while 1:
    buf = f1.read(12)
    if not buf:
    break;
    \#print buf, base64.decodestring(buf)
    f2.write(base64.decodestring(buf))
    f1.close()
    f2.close()
    
得到一张女神照片，纠结了会，google图片之，找到女神名字“爱新觉罗·启星”，被中间的点坑了几次，然后flag是“爱新觉罗启星”， 出题人原来喜欢她啊
![ss](/upload/0751f444dc849c083ee0f0826e8f567e.jpg)

### babyCrack

107.189.158.112/d55757a7ccf958399789e18e1d8199de/babyCrack.zip
PEID查了下，是.net，马上祭出神奇.net reflector， 结果工具过期，重新下了个注册机，搞定，几个函数，翻了下，看到flag：hctf{bAByCtsvlmE!}

    private void button1_Click(object sender, EventArgs e)
    {
    bool flag = false;
    Config.user = this.textBox1.Text;
    string user = Config.user;
    string str2 = “hctf{bABy_CtsvlmE_!}”;
    if (str2.CompareTo(user) == 0)
    {
    flag = true;
    }
    if (flag)
    {
    MessageBox.Show(“good !!!”);
    }
    }

### stego_final

图片隐写题，Stegsolve各种通道翻了一下，看到张二维码，用手机一扫，识别不了，背影有些黑点，又不会图片处理，ps一番，终于找到flag：flag{hctf_3xF$235#^3}

### wzwzDingDing

被坑的最惨的一道题，是个64位驱动，代码真不多，只有30多个函数，翻了一个遍，流程分析清楚，最后有个字符串提示 “OK!YOU ARE REALLY GOOD!Also, there is a } left!”

就是说代码执行到这，应该会得到flag，然后这个是在IRP_MJ_DEVICE_CONTROL函数中，对应多个ctl code，分别是：
0x88102004，0x88102008, 0x8810200C, 0x88102014, 0x88102010，以及都不符和一个ctl code，每个ctl code对应分支都会对偏移0x48E0的一个标志进行操作，最后得到0xFFFFFF执行提示字符串的分支。

下面是触发的ring3代码：

    HANDLE hDev = CreateFileA(DRV_SYM, GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hDev == INVALID_HANDLE_VALUE)
    {
    printf(“[-] open dev error %d\n”, GetLastError());
    return 0;
    }
    printf(“[+] open dev success!\n”);
    char buf[20] = “^lejAJ]O”;
    DWORD dwReturn = 0;
    if(! DeviceIoControl(hDev, 0x88102004, buf, strlen(buf), buf, strlen(buf), &dwReturn, NULL))
    {
    printf(“[-] dev control error %d\n”, GetLastError());
    return 0;
    }
    char buf1[20] = “MNIII”;
    if(! DeviceIoControl(hDev, 0x88102004, buf1, strlen(buf1), buf1, strlen(buf1), &dwReturn, NULL))
    {
    printf(“[-] dev control error %d\n”, GetLastError());
    return 0;
    }
    if(! DeviceIoControl(hDev, 0x88102008, NULL, 0, NULL, 0, &dwReturn, NULL))
    {
    printf(“[-] dev control error %d\n”, GetLastError());
    return 0;
    }
    //8810200C
    if(! DeviceIoControl(hDev, 0x8810200C, NULL, 0, NULL, 0, &dwReturn, NULL))
    {
    printf(“[-] dev control error %d\n”, GetLastError());
    return 0;
    }
    if(! DeviceIoControl(hDev, 0x88102014, NULL, 0, NULL, 0, &dwReturn, NULL))
    {
    printf(“[-] dev control error %d\n”, GetLastError());
    return 0;
    }
    //88102010
    if(! DeviceIoControl(hDev, 0x88102010, NULL, 0, NULL, 0, &dwReturn, NULL))
    {
    printf(“[-] dev control error %d\n”, GetLastError());
    return 0;
    }

最后就进入了提示字符分支，结果在这里 text:0000000000012361 call [rsp+0C8h+ShellCode]，就崩了，被坑了好久，这里需要结合题目提示flag: HCTF{‘intput’.encode(‘hex’)}
就是需要修复那段shellcode，让其正确执行，然后顺利执行到提示字符串位置，分支中还有代码提示需要修复的代码字节位置，然后就是根据一个堆栈平衡就能修复（开始明显看不懂题意啊，坑）
修复前代码：

    fffff880`02f85d90 l5b
    wzwzDingDing+0x2d90:
    fffff880`02f85d90 （10） 5152 adc byte ptr [rcx+52h],dl =>(50 //push rax push rcx
    fffff880`02f85d93 53 push rbx
    fffff880`02f85d94 55 push rbp
    fffff880`02f85d95 56 push rsi
    fffff880`02f85d96 57 push rdi
    fffff880`02f85d97 （90） nop
    fffff880`02f85d98 （90） nop//push r8 (41 50
    fffff880`02f85d99 4151 push r9
    fffff880`02f85d9b 4152 push r10
    fffff880`02f85d9d 4153 push r11
    fffff880`02f85d9f 4154 push r12
    fffff880`02f85da1 4155 push r13
    fffff880`02f85da3 4156 push r14
    fffff880`02f85da5 4157 push r15
    fffff880`02f85da7 90 nop
    fffff880`02f85da8 （90） nop//(48 83 EC 28 sub rsp,28h
    fffff880`02f85da9 (90 nop
    fffff880`02f85daa (90 nop
    fffff880`02f85dab (90 nop
    fffff880`02f85dac 90 nop
    fffff880`02f85dad 48c7c600000000 mov rsi,0
    fffff880`02f85db4 488b040e mov rax,qword ptr [rsi+rcx]
    fffff880`02f85db8 4883f007 xor rax,7
    fffff880`02f85dbc 4889040e mov qword ptr [rsi+rcx],rax
    fffff880`02f85dc0 90 nop
    fffff880`02f85dc1 90 nop
    fffff880`02f85dc2 90 nop
    fffff880`02f85dc3 90 nop
    fffff880`02f85dc4 48ffc6 inc rsi
    fffff880`02f85dc7 4883fe0b cmp rsi,0Bh
    fffff880`02f85dcb 74e0 je wzwzDingDing+0x2dad (fffff880`02f85dad)
    fffff880`02f85dcd 90 nop
    fffff880`02f85dce 4883c428 add rsp,28h
    fffff880`02f85dd2 415f pop r15
    fffff880`02f85dd4 415e pop r14
    fffff880`02f85dd6 415d pop r13
    fffff880`02f85dd8 415c pop r12
    fffff880`02f85dda 415b pop r11
    fffff880`02f85ddc 415a pop r10
    fffff880`02f85dde 4159 pop r9
    fffff880`02f85de0 4158 pop r8
    fffff880`02f85de2 5f pop rdi
    fffff880`02f85de3 5e pop rsi
    fffff880`02f85de4 5d pop rbp
    fffff880`02f85de5 5b pop rbx
    fffff880`02f85de6 5a pop rdx
    fffff880`02f85de7 (90) nop //59 pop rcx
    fffff880`02f85de8 58 pop rax
    fffff880`02f85de9 (90) nop//ret C3
    fffff880`02f85dea 00cc add ah,cl
    
修复后代码：

    kd> u fffff880`02f85d90 l5b
    wzwzDingDing+0x2d90:
    fffff880`02f85d90 50 push rax
    fffff880`02f85d91 51 push rcx
    fffff880`02f85d92 52 push rdx
    fffff880`02f85d93 53 push rbx
    fffff880`02f85d94 55 push rbp
    fffff880`02f85d95 56 push rsi
    fffff880`02f85d96 57 push rdi
    fffff880`02f85d97 4150 push r8
    fffff880`02f85d99 4151 push r9
    fffff880`02f85d9b 4152 push r10
    fffff880`02f85d9d 4153 push r11
    fffff880`02f85d9f 4154 push r12
    fffff880`02f85da1 4155 push r13
    fffff880`02f85da3 4156 push r14
    fffff880`02f85da5 4157 push r15
    fffff880`02f85da7 90 nop
    fffff880`02f85da8 4883ec28 sub rsp,28h
    fffff880`02f85dac 90 nop
    fffff880`02f85dad 48c7c600000000 mov rsi,0
    fffff880`02f85db4 488b040e mov rax,qword ptr [rsi+rcx]
    fffff880`02f85db8 4883f007 xor rax,7
    fffff880`02f85dbc 4889040e mov qword ptr [rsi+rcx],rax
    fffff880`02f85dc0 90 nop
    fffff880`02f85dc1 90 nop
    fffff880`02f85dc2 90 nop
    fffff880`02f85dc3 90 nop
    fffff880`02f85dc4 48ffc6 inc rsi
    fffff880`02f85dc7 4883fe0b cmp rsi,0Bh
    fffff880`02f85dcb 74e0 je wzwzDingDing+0x2dad (fffff880`02f85dad)
    fffff880`02f85dcd 90 nop
    fffff880`02f85dce 4883c428 add rsp,28h
    fffff880`02f85dd2 415f pop r15
    fffff880`02f85dd4 415e pop r14
    fffff880`02f85dd6 415d pop r13
    fffff880`02f85dd8 415c pop r12
    fffff880`02f85dda 415b pop r11
    fffff880`02f85ddc 415a pop r10
    fffff880`02f85dde 4159 pop r9
    fffff880`02f85de0 4158 pop r8
    fffff880`02f85de2 5f pop rdi
    fffff880`02f85de3 5e pop rsi
    fffff880`02f85de4 5d pop rbp
    fffff880`02f85de5 5b pop rbx
    fffff880`02f85de6 5a pop rdx
    fffff880`02f85de7 59 pop rcx
    fffff880`02f85de8 58 pop rax
    fffff880`02f85de9 c3 ret
    fffff880`02f85dea 00cc add ah,cl

然后flag：HCTF{5041504883ec2859c3}，注意大小写啊

### 其他

就这么多了，经验太少，就各路大牛路过指导