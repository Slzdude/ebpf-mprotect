# mprotect monitor

通过eBPF技术监控`mprotect`的调用和参数

目前想到的就是可以辅助逆向脱壳

## Requirements

在Ubuntu 20.10进行的开发， 理论上无兼容问题，如果有运行不了的环境，可以提Issues

只需要bcc即可运行

```shell
sudo apt-get install bpfcc-tools python3-bpfcc linux-headers-$(uname -r) 
```

## Result

执行以下命令开始运行：

`sudo python mprotect.py`

如果运行正常就可以得到以下的结果

```
pid     ppid    uid     comm    start           len     prot
54782   18542   1000    sh      0x7f945bd25000  1810432 0
54782   18542   1000    sh      0x7f945bedf000  12288   1
54782   18542   1000    sh      0x563650119000  8192    1
54782   18542   1000    sh      0x7f945bf21000  4096    1
54784   54782   1000    grep    0x7f87a7645000  1810432 0
54784   54782   1000    grep    0x7f87a77ff000  12288   1
54784   54782   1000    grep    0x7f87a7619000  4096    1
54784   54782   1000    grep    0x7f87a780d000  4096    1
54784   54782   1000    grep    0x7f87a7880000  4096    1
54784   54782   1000    grep    0x55f81da93000  4096    1
54784   54782   1000    grep    0x7f87a78ba000  4096    1
54783   54782   1000    ls      0x7f8da278f000  1810432 0
```

可以编译`test.c`进行测试，它是从`https://man7.org/linux/man-pages/man2/mprotect.2.html`上提取的一个简单的测试程序。
