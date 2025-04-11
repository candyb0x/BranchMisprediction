```bash
git clone https://github.com/Eugnis/spectre-attack
```

Spectre V1 漏洞复现，理解代码实现的原理；计划根据 if 分支预测进行下一步的分支预测的编写；

Spectre V1 是基于已知敏感信息地址进行的信息泄漏，通过敏感信息的地址与 array1 数组基址的偏移进行预测执行越界访问敏感信息，使用访问到的敏感信息作为索引去访问 array2 数组，然后根据缓存的访问时间测信道了解到相关的越界访问敏感信息所对应的字节码，通过字节码可以知道访问到的字节的内容；

![img](https://cdn.nlark.com/yuque/0/2025/png/34580676/1743669032765-d16347ac-128d-42b7-930c-95bb217caa21.png)

# 参考链接

1. https://github.com/speed47/spectre-meltdown-checker
2. https://github.com/Eugnis/spectre-attack