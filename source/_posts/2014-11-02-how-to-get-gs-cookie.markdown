---
layout: post
title: "How to get GS cookie"
date: 2014-11-02 23:12:09 -0700
comments: true
categories: binary
---

author:anhkgg

### Stack cookie

Stack cookies (/GS Switch cookie)，windows防止栈溢出的一种机制，[详见](http://www.pediy.com/kssd/pediy12/102719/724039/39112.pdf)。

栈中的 cookie/GS保护

/GS 编译选项会在函数的开头和结尾添加代码来阻止对典型的栈溢出漏洞（字符串缓冲区）的利用。
当应用程序启动时，程序的 cookie（4 字节（dword），无符号整型）被计算出来（伪随机数）并保存在
加载模块的.data 节中,在函数的开头这个 cookie 被拷贝到栈中，位于 EBP 和返回地址的正前方（位于返
回地址和局部变量的中间）。
[buffer][cookie][saved EBP][saved EIP]
在函数的结尾处，程序会把这个 cookie 和保存在.data 节中的 cookie 进行比较。
如果不相等，就说明进程栈被破坏，进程必须被终止。
<!--more-->

栈中的 cookie/GS绕过方法
挫败这种栈溢出保护机制的最直接的方法是检索/猜测/计算出 cookie 值（这样就可以用相同的 cookie
覆盖栈中的 cookie），这个 cookie 有时候（很少）是一个静态值…但即使如此，它也可能包含一些不利
的字符而导致不能使用它。

### 如何通过PE来获取GS cookie的值

在PE的DataDirectory中，第10序号的是一个叫做LoadConfig的东西，保存了映像的配置数据，里面就有GS cookie，来看看这个数据结构
IMAGE_LOAD_CONFIG_DIRECTORY32

    typedef struct {
    DWORD Size;
    DWORD TimeDateStamp;
    WORD MajorVersion;
    WORD MinorVersion;
    DWORD GlobalFlagsClear;
    DWORD GlobalFlagsSet;
    DWORD CriticalSectionDefaultTimeout;
    DWORD DeCommitFreeBlockThreshold;
    DWORD DeCommitTotalFreeThreshold;
    DWORD LockPrefixTable; // VA
    DWORD MaximumAllocationSize;
    DWORD VirtualMemoryThreshold;
    DWORD ProcessHeapFlags;
    DWORD ProcessAffinityMask;
    WORD CSDVersion;
    WORD Reserved1;
    DWORD EditList; // VA
    DWORD SecurityCookie; // VA
    DWORD SEHandlerTable; // VA
    DWORD SEHandlerCount;
    } IMAGE_LOAD_CONFIG_DIRECTORY32, *PIMAGE_LOAD_CONFIG_DIRECTORY32;
    
    SecurityCookie
    A pointer to a cookie that is used by Visual C++ or GS implementation.

所以，可以通过解析pe的方式，获取到SecurityCookie，进而绕过cookie/GS保护，这只是我的想法，也没测试过，是在分析某个sys的时间想到的，下面贴出获取Cookie的代码


    unsigned int __stdcall myGetGSSecureCookie(PVOID ImageBase, ULONG Size)
    {
    ULONG v2; // edi@1
    PVOID v3; // esi@1
    PVOID v4; // eax@2
    unsigned int result; // eax@7
    v3 = ImageBase;
    v2 = Size;
    if ( (signed int)myGetValidNtHeader(1, (unsigned int)ImageBase, Size, (int)&ImageBase) < 0//myGetValidNtHeader获取nt头地址
    || (v4 = RtlImageDirectoryEntryToData(v3, 1u, 0xAu, &Size), !v4)// 通过加载配置目录信息找到SecureCookie
    || !Size
    || Size != 0x40 && Size != *(_DWORD *)v4
    || *(_DWORD *)v4 < 0x48u
    || (result = *((_DWORD *)v4 + 15), result <= (unsigned int)v3)// loadcofig->SecurityCookie
    // A pointer to a cookie that is used by Visual C++ or GS implementation.
    || result >= (unsigned int)(v3 + v2 – 4) )
    result = 0;
    return result;
    }
其他

没来得及查资料，是否有完整的绕过方法，这只是自己突然分析到这，想到的，不对之处，敬请见谅。