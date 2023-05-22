# 简介

本项目主要为How2heap提供了一份中文翻译，尽可能的做到尊重原文，便于读者理解。

如果有帮到各位师傅，还请动动手点个Star吧！如果发现本文有任何谬误或对本文有任何建议，欢迎提交commit。

正在施工中。。。



# 堆利用教程

这个仓库用于学习各种堆利用技术。我们使用Ubuntu的Libc版本作为黄金标准。每种技术都经过验证的，可以在相应的Ubuntu版本上正常工作。您可以运行“apt source libc6”来下载您在基于Debian的操作系统上使用的Libc的源代码。您还可以单击:arrow_forward:使用gdb在浏览器中调试技术。

我们在黑客会议期间想出了这个想法，并实现了以下技术：

| 文件                                                         | :arrow_forward:                                              | 技术概括                                                     | Glibc-版本  | 补丁(patch)                                                  | 相关的CTF挑战                                                |
| ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ | ----------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| [first_fit.c](first_fit.c)                                   |                                                              | 展示glibc malloc使用first-fit算法的方式。                    |             |                                                              |                                                              |
| [calc_tcache_idx.c](calc_tcache_idx.c)                       |                                                              | 展示glibc的tcache索引计算方式。                              |             |                                                              |                                                              |
| [fastbin_dup.c](glibc_2.35/fastbin_dup.c)                    | <a href="https://wargames.ret2.systems/level/how2heap_fastbin_dup_2.34" title="Debug Technique In Browser">:arrow_forward:</a> | 通过利用 fastbin 的 freelist 来诱骗 malloc 返回已分配的堆指针。 | 最新        |                                                              |                                                              |
| [fastbin_dup_into_stack.c](glibc_2.35/fastbin_dup_into_stack.c) | <a href="https://wargames.ret2.systems/level/how2heap_fastbin_dup_into_stack_2.23" title="Debug Technique In Browser">:arrow_forward:</a> | 通过利用 fastbin 的 freelist 来诱骗 malloc 返回几乎任意的指针。 | 最新        |                                                              | [9447-search-engine](https://github.com/ctfs/write-ups-2015/tree/master/9447-ctf-2015/exploitation/search-engine), [0ctf 2017-babyheap](http://uaf.io/exploitation/2017/03/19/0ctf-Quals-2017-BabyHeap2017.html) |
| [fastbin_dup_consolidate.c](glibc_2.35/fastbin_dup_consolidate.c) | <a href="https://wargames.ret2.systems/level/how2heap_fastbin_dup_consolidate_2.23" title="Debug Technique In Browser">:arrow_forward:</a> | 通过将指针放在 fast bin freelist 和 unsorted bin freelist 中来诱骗 malloc 返回已分配的堆指针。 | 最新        |                                                              | [Hitcon 2016 SleepyHolder](https://github.com/mehQQ/public_writeup/tree/master/hitcon2016/SleepyHolder) |
| [unsafe_unlink.c](glibc_2.35/unsafe_unlink.c)                | <a href="https://wargames.ret2.systems/level/how2heap_unsafe_unlink_2.34" title="Debug Technique In Browser">:arrow_forward:</a> | 利用损坏的块进行自由攻击，能够进行任意地址写入。             | 最新        |                                                              | [HITCON CTF 2014-stkof](http://acez.re/ctf-writeup-hitcon-ctf-2014-stkof-or-modern-heap-overflow/), [Insomni'hack 2017-Wheel of Robots](https://gist.github.com/niklasb/074428333b817d2ecb63f7926074427a) |
| [house_of_spirit.c](glibc_2.35/house_of_spirit.c)            | <a href="https://wargames.ret2.systems/level/how2heap_house_of_spirit_2.23" title="Debug Technique In Browser">:arrow_forward:</a> | free 一个伪造的 fastbin chunk 使 malloc 返回一个几乎任意的指针。 | 最新        |                                                              | [hack.lu CTF 2014-OREO](https://github.com/ctfs/write-ups-2014/tree/master/hack-lu-ctf-2014/oreo) |
| [poison_null_byte.c](glibc_2.35/poison_null_byte.c)          | <a href="https://wargames.ret2.systems/level/how2heap_poison_null_byte_2.34" title="Debug Technique In Browser">:arrow_forward:</a> | 利用单个空字节溢出。                                         | 最新        |                                                              | [PlaidCTF 2015-plaiddb](https://github.com/ctfs/write-ups-2015/tree/master/plaidctf-2015/pwnable/plaiddb), [BalsnCTF 2019-PlainNote](https://gist.github.com/st424204/6b5c007cfa2b62ed3fd2ef30f6533e94?fbclid=IwAR3n0h1WeL21MY6cQ_C51wbXimdts53G3FklVIHw2iQSgtgGo0kR3Lt-1Ek) |
| [house_of_lore.c](glibc_2.35/house_of_lore.c)                | <a href="https://wargames.ret2.systems/level/how2heap_house_of_lore_2.34" title="Debug Technique In Browser">:arrow_forward:</a> | 通过利用 small bin freelist 来诱骗 malloc 返回几乎任意的指针。 | 最新        |                                                              |                                                              |
| [overlapping_chunks.c](glibc_2.27/overlapping_chunks.c)      | <a href="https://wargames.ret2.systems/level/how2heap_overlapping_chunks_2.34" title="Debug Technique In Browser">:arrow_forward:</a> | 利用 unsorted bin 中释放的区块大小的覆盖，以使新的分配与现有区块重叠 | < 2.29      | [补丁](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=b90ddd08f6dd688e651df9ee89ca3a69ff88cd0c) | [hack.lu CTF 2015-bookstore](https://github.com/ctfs/write-ups-2015/tree/master/hack-lu-ctf-2015/exploiting/bookstore), [Nuit du Hack 2016-night-deamonic-heap](https://github.com/ctfs/write-ups-2016/tree/master/nuitduhack-quals-2016/exploit-me/night-deamonic-heap-400) |
| [overlapping_chunks_2.c](glibc_2.23/overlapping_chunks_2.c)  | <a href="https://wargames.ret2.systems/level/how2heap_overlapping_chunks_2_2.23" title="Debug Technique In Browser">:arrow_forward:</a> | 覆盖正在使用的区块大小，使新的分配与现有区块重叠             | < 2.29      | [补丁](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=b90ddd08f6dd688e651df9ee89ca3a69ff88cd0c) |                                                              |
| [mmap_overlapping_chunks.c](glibc_2.35/mmap_overlapping_chunks.c) |                                                              | 利用正在使用的 mmap 区块，使新的分配与当前 mmap 区块重叠     | 最新        |                                                              |                                                              |
| [house_of_force.c](glibc_2.27/house_of_force.c)              | <a href="https://wargames.ret2.systems/level/how2heap_house_of_force_2.27" title="Debug Technique In Browser">:arrow_forward:</a> | 利用 top chunk （Wilderness）header 来让 malloc 返回几乎任意的指针 | < 2.29      | [补丁](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=30a17d8c95fbfb15c52d1115803b63aaa73a285c) | [Boston Key Party 2016-cookbook](https://github.com/ctfs/write-ups-2016/tree/master/boston-key-party-2016/pwn/cookbook-6), [BCTF 2016-bcloud](https://github.com/ctfs/write-ups-2016/tree/master/bctf-2016/exploit/bcloud-200) |
| [unsorted_bin_into_stack.c](glibc_2.27/unsorted_bin_into_stack.c) | <a href="https://wargames.ret2.systems/level/how2heap_unsorted_bin_into_stack_2.27" title="Debug Technique In Browser">:arrow_forward:</a> | 覆盖 unsorted bin freelist 上的已被释放的堆块来返回几乎任意的指针。 | < 2.29      | [补丁](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=b90ddd08f6dd688e651df9ee89ca3a69ff88cd0c) |                                                              |
| [unsorted_bin_attack.c](glibc_2.27/unsorted_bin_attack.c)    | <a href="https://wargames.ret2.systems/level/how2heap_unsorted_bin_attack_2.27" title="Debug Technique In Browser">:arrow_forward:</a> | 覆盖 unsorted bin freelist 上的已被释放的堆块将一个较大的值写入任意地址 | < 2.29      | [补丁](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=b90ddd08f6dd688e651df9ee89ca3a69ff88cd0c) | [0ctf 2016-zerostorage](https://github.com/ctfs/write-ups-2016/tree/master/0ctf-2016/exploit/zerostorage-6) |
| [large_bin_attack.c](glibc_2.35/large_bin_attack.c)          | <a href="https://wargames.ret2.systems/level/how2heap_large_bin_attack_2.34" title="Debug Technique In Browser">:arrow_forward:</a> | 覆盖 large bin freelist 上的已被释放的堆块将一个较大的值写入任意地址 | 最新        |                                                              | [0ctf 2018-heapstorm2](https://dangokyo.me/2018/04/07/0ctf-2018-pwn-heapstorm2-write-up/) |
| [house_of_einherjar.c](glibc_2.35/house_of_einherjar.c)      | <a href="https://wargames.ret2.systems/level/how2heap_house_of_einherjar_2.34" title="Debug Technique In Browser">:arrow_forward:</a> | 利用单个空字节溢出诱骗 malloc 返回受控指针                   | 最新        |                                                              | [Seccon 2016-tinypad](https://gist.github.com/hhc0null/4424a2a19a60c7f44e543e32190aaabf) |
| [house_of_orange.c](glibc_2.23/house_of_orange.c)            | <a href="https://wargames.ret2.systems/level/how2heap_house_of_orange_2.23" title="Debug Technique In Browser">:arrow_forward:</a> | 利用 top chunk（Wilderness）来进行任意代码执行               | < 2.26      | [补丁](https://sourceware.org/git/?p=glibc.git;a=blobdiff;f=stdlib/abort.c;h=117a507ff88d862445551f2c07abb6e45a716b75;hp=19882f3e3dc1ab830431506329c94dcf1d7cc252;hb=91e7cf982d0104f0e71770f5ae8e3faf352dea9f;hpb=0c25125780083cbba22ed627756548efe282d1a0) | [Hitcon 2016 houseoforange](https://github.com/ctfs/write-ups-2016/tree/master/hitcon-ctf-2016/pwn/house-of-orange-500) |
| [house_of_roman.c](glibc_2.23/house_of_roman.c)              | <a href="https://wargames.ret2.systems/level/how2heap_house_of_roman_2.23" title="Debug Technique In Browser">:arrow_forward:</a> | 一种无泄漏技术，以通过伪造的fastbins，unsorted bin和相对覆盖来实现远程代码执行。 | < 2.29      | [补丁](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=b90ddd08f6dd688e651df9ee89ca3a69ff88cd0c) |                                                              |
| [tcache_poisoning.c](glibc_2.35/tcache_poisoning.c)          | <a href="https://wargames.ret2.systems/level/how2heap_tcache_poisoning_2.34" title="Debug Technique In Browser">:arrow_forward:</a> | 通过利用 tcache freelist 来诱骗 malloc 返回完全任意的指针。（glibc版本至少要在2.32以上并且同时需要对堆泄漏进行利用） | > 2.25      | [补丁](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=a1a486d70ebcc47a686ff5846875eacad0940e41) |                                                              |
| [tcache_house_of_spirit.c](glibc_2.35/tcache_house_of_spirit.c) | <a href="https://wargames.ret2.systems/level/how2heap_tcache_house_of_spirit_2.34" title="Debug Technique In Browser">:arrow_forward:</a> | 释放一个伪造的块，让 malloc 返回一个几乎任意的指针。         | > 2.25      |                                                              |                                                              |
| [house_of_botcake.c](glibc_2.35/house_of_botcake.c)          | <a href="https://wargames.ret2.systems/level/how2heap_house_of_botcake_2.34" title="Debug Technique In Browser">:arrow_forward:</a> | 绕过tcache的双重释放检查机制。Make `tcache_dup` great again! | > 2.25      |                                                              |                                                              |
| [tcache_stashing_unlink_attack.c](glibc_2.35/tcache_stashing_unlink_attack.c) | <a href="https://wargames.ret2.systems/level/how2heap_tcache_stashing_unlink_attack_2.34" title="Debug Technique In Browser">:arrow_forward:</a> | 覆盖 small bin freelist 上的已被释放的块来诱骗 malloc 返回任意指针，并在 calloc 的帮助下将一个较大的值写入任意地址。 | > 2.25      |                                                              | [Hitcon 2019 one punch man](https://github.com/xmzyshypnc/xz_files/tree/master/hitcon2019_one_punch_man) |
| [fastbin_reverse_into_tcache.c](glibc_2.35/fastbin_reverse_into_tcache.c) | <a href="https://wargames.ret2.systems/level/how2heap_fastbin_reverse_into_tcache_2.34" title="Debug Technique In Browser">:arrow_forward:</a> | 覆盖 fastbin 中已被释放的块将一个较大的值写入任意地址。      | > 2.25      |                                                              |                                                              |
| [house_of_mind_fastbin.c](glibc_2.35/house_of_mind_fastbin.c) | <a href="https://wargames.ret2.systems/level/how2heap_house_of_mind_fastbin_2.34" title="Debug Technique In Browser">:arrow_forward:</a> | 利用arena处理的单字节覆盖将一个较大的值（堆指针）写入任意地址 | 最新        |                                                              |                                                              |
| [house_of_storm.c](glibc_2.27/house_of_storm.c)              | <a href="https://wargames.ret2.systems/level/how2heap_house_of_storm_2.27" title="Debug Technique In Browser">:arrow_forward:</a> | 利用对 large bin 和unsorted bin 的 use-after-free 漏洞以从 malloc 返回任意的块 | < 2.29      |                                                              |                                                              |
| [house_of_gods.c](glibc_2.24/house_of_gods.c)                | <a href="https://wargames.ret2.systems/level/how2heap_house_of_gods_2.24" title="Debug Technique In Browser">:arrow_forward:</a> | 一种在 8 次分配以内劫持线程arena的技术                       | < 2.27      |                                                              |                                                              |
| [decrypt_safe_linking.c](glibc_2.35/decrypt_safe_linking.c)  | <a href="https://wargames.ret2.systems/level/how2heap_decrypt_safe_linking_2.34" title="Debug Technique In Browser">:arrow_forward:</a> | 解密链表中的poisoned value来恢复实际指针                     | >= 2.32     |                                                              |                                                              |
| [tcache_dup.c](obsolete/glibc_2.27/tcache_dup.c)(已废弃)     |                                                              | 利用 tcache freelist 诱骗 malloc 返回已分配的堆指针。        | 2.26 - 2.28 | [补丁](https://sourceware.org/git/?p=glibc.git;a=commit;h=bcdaad21d4635931d1bd3b54a7894276925d081d) |                                                              |

# 用法

获取仓库

```bash
git clone https://github.com/ffreeez/how2heap_zh
cd ./how2heap_zh
git submodule update --init --recursive
```

在根目录下直接make即可

```bash
$ cd ./how2heap_zh
$ make
```

使用glibc_run.sh来执行可执行文件，可以更方便的替换glibc
在使用这个脚本之前，需要安装`patchelf`，并且要在`glibc-all-in-one`项目中更新可下载的列表

```bash
$ sudo apt install patchelf
```

```bash
$ cd ./how2heap_zh/glibc-all-in-one
$ chmod +x ./*
$ ./update_list
```

执行`update_list`时，可能会提示`-bash: ./update_list: /usr/bin/python: bad interpreter: No such file or directory`
，在文本编辑器中把`update_list`文件中的第一行`#!/usr/bin/python`改为`#!/usr/bin/python3`即可

```
[用法] ./glibc_run.sh <glibc版本号> <可执行文件> [-h] [-i686] [-u] [-r] [-gdb | -r2 | -p]
-i686 -使用32位的libc
-u 在glibc-all-in-one中更新libc列表
-r 在glibc-all-in-one中下载libc
-gdb -在gdb中执行目标文件
-r2 -在radare2中执行目标文件
-p -只在可执行文件中修改interpreter和rpath来指向对应的glibc并且不执行

eg: ./glibc_run.sh 2.23 ./first_fit
```


Gnu Libc 正在不断发展，上面的几种技术已经允许在 malloc/free 逻辑中引入一致性检查。
因此，这些检查会定期破坏某些技术，并需要进行调整以绕过它们（如果可能）。
我们通过为每个需要调整的 Glibc 版本保留相同技术的多个版本来解决此问题。
项目结构为`glibc_<version>/技术名称.c`

# 堆利用工具

这里有一些广为流传的堆利用工具，具体内容暂不做翻译（懒懒。

## shadow

jemalloc exploitation framework: https://github.com/CENSUS/shadow

## libheap

Examine the glibc heap in gdb: https://github.com/cloudburst/libheap

## heap-viewer

Examine the glibc heap in IDA Pro: https://github.com/danigargu/heap-viewer

## heapinspect

A Python based heap playground with good visualization for educational purposes: https://github.com/matrix1001/heapinspect

## Forkever

Debugger that lets you set "checkpoints" as well as view and edit the heap using a hexeditor: https://github.com/haxkor/forkever

## Malloc Playground

The `malloc_playground.c` file given is the source for a program that prompts the user for commands to allocate and free memory interactively.

## Pwngdb

Examine the glibc heap in gdb: https://github.com/scwuaptx/Pwngdb

## heaptrace

Helps you visualize heap operations by replacing addresses with symbols: https://github.com/Arinerron/heaptrace

## Heap Search

Search for applicable heap exploitation techniques based on primitive requirements: https://kissprogramming.com/heap/heap-search

# Other resources

Some good heap exploitation resources, roughly in order of their publication, are:

- glibc in-depth tutorial (https://heap-exploitation.dhavalkapil.com/) - book and exploit samples
- ptmalloc fanzine, a set of resources and examples related to meta-data attacks on ptmalloc (http://tukan.farm/2016/07/26/ptmalloc-fanzine/)
- A malloc diagram, from libheap (https://raw.githubusercontent.com/cloudburst/libheap/master/heap.png)
- Glibc Adventures: The Forgotten Chunk (https://go.contextis.com/rs/140-OCV-459/images/Glibc_Adventures-The_Forgotten_Chunks.pdf) - advanced heap exploitation
- Pseudomonarchia jemallocum (http://www.phrack.org/issues/68/10.html)
- The House Of Lore: Reloaded (http://phrack.org/issues/67/8.html)
- Malloc Des-Maleficarum (http://phrack.org/issues/66/10.html) - some malloc exploitation techniques
- Yet another free() exploitation technique (http://phrack.org/issues/66/6.html)
- Understanding the heap by breaking it (https://www.blackhat.com/presentations/bh-usa-07/Ferguson/Whitepaper/bh-usa-07-ferguson-WP.pdf) - explains heap implementation and a couple exploits
- The use of set_head to defeat the wilderness (http://phrack.org/issues/64/9.html)
- The Malloc Maleficarum (http://seclists.org/bugtraq/2005/Oct/118)
- OS X heap exploitation techniques (http://phrack.org/issues/63/5.html)
- Exploiting The Wilderness (http://seclists.org/vuln-dev/2004/Feb/25)
- Advanced Doug lea's malloc exploits (http://phrack.org/issues/61/6.html)
- GDB Enhanced Features (GEF) Heap Exploration Tools (https://gef.readthedocs.io/en/master/commands/heap/)
- Painless intro to the Linux userland heap (https://sensepost.com/blog/2017/painless-intro-to-the-linux-userland-heap/)
- Heap exploitation techniques that work on glibc-2.31 (https://github.com/StarCross-Tech/heap_exploit_2.31)
- Overview of GLIBC heap exploitation techniques (https://0x434b.dev/overview-of-glibc-heap-exploitation-techniques/)

# Hardening

There are a couple of "hardening" measures embedded in glibc, like `export MALLOC_CHECK_=1` (enables some checks), `export MALLOC_PERTURB_=1` (data is overwritten), `export MALLOC_MMAP_THRESHOLD_=1` (always use mmap()), ...

More info: [mcheck()](http://www.gnu.org/software/libc/manual/html_node/Heap-Consistency-Checking.html), [mallopt()](http://www.gnu.org/software/libc/manual/html_node/Malloc-Tunable-Parameters.html).

There's also some tracing support as [mtrace()](http://manpages.ubuntu.com/mtrace), [malloc_stats()](http://manpages.ubuntu.com/malloc_stats), [malloc_info()](http://manpages.ubuntu.com/malloc_info), [memusage](http://manpages.ubuntu.com/memusage), and in other functions in this family.
