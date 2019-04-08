---
title: MISC一些总结
date: 2019-04-08 19:19:50
tags: Misc
---


### 信息收集
------
#### 社会工程学

从广义上来说，社会工程学是一种通过对“人性”的心理弱点、本能反应、好奇心、信任、贪婪等心理陷阱进行诸如欺骗、伤害等危害手段取得自身利益的手法，它并不能等同于一般的欺骗手法，社会工程学尤其复杂，即使自认为最警惕最小心的人，一样会被高明的社会工程学手段损害利益。
<!--more-->
利用种种人之常情, 例如你想进入一个有门禁的小区大门, 当然, 作为一个黑客你可以采用电影里面复制门禁卡的手法进入, 但是最简单的方法是找准时机跟随一个住户进入, 这时你甚至可以在对方掏卡之前假装掏一下, 然后理所当然的跟着提前掏出卡的他进入。

这些人之常情, 好心, 必要的时候都是可以利用的安全漏洞, **安全体系中最大的漏洞往往是人**。

>推荐相关影片《我是谁（who an I）》《猫鼠游戏》  



#### GOOGLE HACK

  在我们平时使用搜索引擎的过程中，通常是将需要搜索的关键字输入搜索引擎，然后就开始了漫长的信息提取过程。其实Google对于搜索的关键字提供了多种语法，合理使用这些语法，将使我们得到的搜索结果更加精确。当然，Google允许用户使用这些语法的目的是为了获得更加精确的结果，但是黑客却可以利用这些语法构造出特殊的关键字，使搜索的结果中绝大部分都是存在漏洞的网站。 

当然，这也与很多网站配置不当或者未限制抓取导致敏感信息泄露有关

撒大网捞鱼

详细可以自己了解

>https://www.cnblogs.com/xudong0520/p/5797828.html



### 数字取证

------



#### 流量分析

1. 普通网络流量分析
    >主要采用工具：wireshark等

    HTTP协议 | HTTPS协议 | FTP协议 | DNS协议

    + `HTTP`(`Hyper Text Transfer Protocol` ，也称为超文本传输协议) 是一种用于分布式、协作式和超媒体信息系统的应用层协议。 `HTTP` 是万维网的数据通信的基础。

        HTTP协议分析一般需要寻找到攻击者所用的攻击payload
    
    + `FTP` ( `File Transfer Protocol` ，即文件传输协议) 是 `TCP/IP` 协议组中的协议之一。 `FTP` 协议包括两个组成部分，其一为 `FTP` 服务器，其二为 `FTP` 客户端。其中 `FTP` 服务器用来存储文件，用户可以使用 `FTP` 客户端通过 `FTP` 协议访问位于 `FTP` 服务器上的资源。在开发网站的时候，通常利用 `FTP` 协议把网页或程序传到 `Web` 服务器上。此外，由于 `FTP` 传输效率非常高，在网络上传输大的文件时，一般也采用该协议。

        默认情况下 `FTP` 协议使用 `TCP` 端口中的 `20` 和 `21` 这两个端口，其中 `20` 用于传输数据， `21` 用于传输控制信息。但是，是否使用 `20` 作为传输数据的端口与 `FTP` 使用的传输模式有关，如果采用主动模式，那么数据传输端口就是 `20` ；如果采用被动模式，则具体最终使用哪个端口要服务器端和客户端协商决定。

        FTP协议一般需要提取出传输文件并进行进一步操作

    + `DNS` 通常为 `UDP` 协议, 报文格式
        
        ```
        +-------------------------------+
        | 报文头                         |
        +-------------------------------+
        | 问题 (向服务器提出的查询部分)    |
        +-------------------------------+
        | 回答 (服务器回复的资源记录)      |
        +-------------------------------+
        | 授权 (权威的资源记录)           |
        +-------------------------------+
        | 格外的 (格外的资源记录)         |
        +-------------------------------+
        ```
        
        查询包只有头部和问题两个部分， `DNS` 收到查询包后，根据查询到的信息追加回答信息、授权机构、额外资源记录，并且修改了包头的相关标识再返回给客户端。
    
        每个 `question` 部分
    
        ```
        0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                                               |
        /                     QNAME                     /
        /                                               /
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                     QTYPE                     |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                     QCLASS                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        ```
    
        - `QNAME` ：为查询的域名，是可变长的，编码格式为：将域名用. 号划分为多个部分，每个部分前面加上一个字节表示该部分的长度，最后加一个 `0` 字节表示结束
        - `QTYPE` ：占 `16` 位，表示查询类型，共有 `16` 种，常用值有：`1` ( `A` 记录，请求主机 `IP` 地址)、`2` ( `NS` ，请求授权 `DNS` 服务器)、`5` ( `CNAME` 别名查询）
    
        DNS协议也可用于DNS隧道隐写

        参考资料：
        > https://ctf-wiki.github.io/ctf-wiki/misc/traffic/protocols/DNS/
        >​ https://blog.csdn.net/lepton126/article/details/54583313

    例题：(取自DDCTF2018)

    流量包文件：
    https://pan.baidu.com/s/1bEEgrE4mxkLpEBHxE66m5g

    分析流量包，可以发现有大量SMTP协议内容，及邮件内容，导出可得到多个eml文件。
    考虑到eml文件与mht文件格式相似，直接改后缀为mht查看，可以发现，在某个eml文件中有密钥的图像，
    识别得到密钥，对流量包中的TLS协议内容进行解密，可以得到包含flag的文件。
   

2. 鼠标流量分析

    鼠标流量包的特征是每一个数据包的数据区有四个字节，第一个字节代表按键，当取
    0x00 时，代表没有按键、为 0x01 时，代表按左键，为 0x02 时，代表当前按键为右键。第二个字节可以看成是一个 signed byte 类型，其最高位为符号位，当这个值为正时，代表鼠标水平右移多少像素，为负时，代表水平左移多少像素。第三个字节与第二字节类似，代表垂直上下移动的偏移。
   
    鼠标发送给PC的数据每次4个字节 
    BYTE1 | BYTE2 |  BYTE3 | BYTE4 
    定义分别是：
    ```
    BYTE1 -- 
           |--bit7:   1   表示   Y   坐标的变化量超出－256   ~   255的范围,0表示没有溢出  
           |--bit6:   1   表示   X   坐标的变化量超出－256   ~   255的范围，0表示没有溢出  
           |--bit5:   Y   坐标变化的符号位，1表示负数，即鼠标向下移动  
           |--bit4:   X   坐标变化的符号位，1表示负数，即鼠标向左移动  
           |--bit3:     恒为1  
           |--bit2:     1表示中键按下  
           |--bit1:     1表示右键按下  
           |--bit0:     1表示左键按下  
    BYTE2 -- X坐标变化量，与byte的bit4组成9位符号数,负数表示向左移，正数表右移。用补码表示变化量  
    BYTE3 -- Y坐标变化量，与byte的bit5组成9位符号数，负数表示向下移，正数表上移。用补码表示变化量 
    BYTE4 -- 滚轮变化。
    ```

   

3. 键盘流量分析

    键盘流量包：
   ```
    BYTE1 -- 
    ​       |--bit0: Left Control是否按下，按下为1 
    ​       |--bit1: Left Shift 是否按下，按下为1 
    ​       |--bit2: Left Alt 是否按下，按下为1
    ​       |--bit3: Left GUI 是否按下，按下为1 
    ​       |--bit4: Right Control是否按下，按下为1 
    ​       |--bit5: Right Shift 是否按下，按下为1 
    ​       |--bit6: Right Alt 是否按下，按下为1 
    ​       |--bit7: Right GUI 是否按下，按下为1 
    BYTE2 -- 暂不清楚，有的地方说是保留位 
    BYTE3~BYTE8 -- 这六个为普通按键（具体对应关系自行百度）
    ```

    >例题：详见 https://github.com/MiGoooo/HCTF2018_misc_dpl

4. 蓝牙流量分析

5. 投影仪流量分析*

#### 内存分析

内存中一半存有程序运行时的数据，可以存留有多种不同类型的数据结构，例如程序打开的文件，程序本身的可执行文件(PE,elf等)，系统运行所留存的全局数据(注册表，用户权限，系统信息等等)等，
而且不同的系统间内存结构不同。
在内存取证时一般使用`volatility`来进行分析。([官网页面](https://www.volatilityfoundation.org/))

此处以一道题目为例。(题目取自护网杯)
> 内存dump文件: 链接: https://pan.baidu.com/s/1IdhDQAv02nAz0H211BoVgA 提取码: axgp

首先，由于无法得知，内存所属的系统，利用工具对此dump文件进行分析，使用如下指令，获取镜像文件的信息。
```bash
volatility -f easy_dump.img imageinfo
```
可以得到如下结果:
```
Volatility Foundation Volatility Framework 2.6
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_23418
                     AS Layer1 : FileAddressSpace (easy_dump.img)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0x3ec36a6L
          Number of Processors : 0
     Image Type (Service Pack) : -
             KUSER_SHARED_DATA : 0xfffff78000000000L
```
可以看到，这是一个windows7/2008的内存镜像。

接下来可以分析此文件中到底都包含什么，接下来分析内存中运行的进程，使用如下指令列举进程信息。
```bash
volatility -f esay_dump.img --profile=Win7SP1x64 psscan
```
可得到如下结果:
```
Volatility Foundation Volatility Framework 2.6
Offset(P)          Name                PID   PPID PDB                Time created                   Time exited
------------------ ---------------- ------ ------ ------------------ ------------------------------ ------------------------------
0x00000000230f4166 VGAuthService.     1680    500 0x0000000007845000 2018-10-02 13:21:08 UTC+0000
0x000000002313dfa6 SearchIndexer.     2308    500 0x0000000006faf000 2018-10-02 13:21:13 UTC+0000
0x0000000023188bf6 vmtoolsd.exe       1704    500 0x0000000015204000 2018-10-02 13:21:08 UTC+0000
(中间省略部分无用信息)
0x000000002533c166 notepad.exe        2872   1244 0x0000000008151000 2018-10-02 13:26:51 UTC+0000
0x000000002539d166 audiodg.exe        1008    768 0x000000000bef1000 2018-10-02 14:23:21 UTC+0000
0x00000000253ee896 DumpIt.exe          140   1244 0x000000000042b000 2018-10-02 14:25:38 UTC+0000
0x00000000255d2166 System                4      0 0x0000000000187000 2018-10-02 13:21:03 UTC+0000
```
可以看到存在一个叫做`DumpIt.exe`程序，作为一道题目，这显然是需要分析的目标。

单独提取这个程序所对应的内存，使用指令如下:(提取PID为140的进程对应内存，提取至当前目录)
```bash
volatility -f esay_dump.img --profile=Win7SP1x64 memdump -p 140 -D ./
```

在当前目录下，得到`140.dmp`文件，直接分析此段镜像中可能存在的文件。
```bash
binwalk 140.dmp
```
发现文件中存在一个zip，其中包含文件`message.img`。

> 关于`volatility`的更多指令，参阅其[官方文档](https://github.com/volatilityfoundation/volatility/wiki)
> 关于`binwalk`工具的使用，参阅其[官方文档](https://github.com/ReFirmLabs/binwalk/wiki)
> `binwalk`类似工具还包括`foremost`等，但对于文件的直接2进制分析，**请不要过分依赖于某一个工具**。

> 推荐相关内存取证教程: [CTF内存取证入坑指南！稳！](https://www.freebuf.com/column/152545.html)

#### 磁盘文件分析

磁盘文件只要考虑到两部分，包括标准的磁盘分区部分，以及每个磁盘的文件系统组成。

+ 磁盘分区主要包含两种方式:`MBR`、`GPT`。

    + `MBR`为旧的格式标准，与`BIOS`标准相结合，只要包含一个最多有四条记录的分区表，因此，在此模式下的磁盘至多只有4个启动分区。
    + `GPT`为更新的格式，为了兼容`MBR`的标准，防止被不支持`GPT`的工具错误覆盖，因此`GPT`的头部带有一个被称之为`PMBR`的`MBR`结构，
        将整个`GPT`所覆盖的区域视作一个被保护的`MBR`分区。`GPT`分区主要与`EFI`启动格式有关，可以支持更多的主分区(启动分区)。

+ 磁盘的文件系统因不同的系统而异，常见的文件系统一般如下：
    + FAT12/16/32，为DOS/windows的经典文件系统，结构简单，缺少日志结构保护。
    + NTFS，为windows的现代文件系统，包含读写日志等结构以保护硬盘数据的完整性。
    + ext2/3/4，为linux内核所使用的文件系统，其中ext2不包含日志，而ext3/4包含日志。
    + swap等，为linux的功能性文件系统。

对于磁盘镜像文件，由于其体积过大，一般也采用工具进行分析。

此处以例题做说明。(接续内存分析的例题)

在前述题目得到`message.img`文件后，利用`foremost`分析可以得知，`message.img`为一个ext2的磁盘镜像文件。

此处利用`testdisk`工具进行分析。
```bash
testdisk message.img
```
对镜像文件进行检索可以发现，存在`hint.txt`及被放入回收站的`.message.swp`

可利用`testdisk`工具直接将文件拷贝/恢复到外面。

(后续题解与磁盘文件分析无关，详见https://blog.csdn.net/weixin_40709439/article/details/83144569)

> `testdisk`为交互式工具，可直接参看其文字说明，官网如下:
> https://www.cgsecurity.org/wiki/TestDisk
> 其他磁盘镜像工具: [Autopsy & TSK](http://www.sleuthkit.org/)


#### 压缩包破解

`ZIP` 文件主要由三部分构成，分别为

| 压缩源文件数据区                                | 核心目录          | 目录结束                        |
| ----------------------------------------------- | ----------------- | ------------------------------- |
| local file header + file data + data descriptor | central directory | end of central directory record |

-  压缩源文件数据区中每一个压缩的源文件或目录都是一条记录，其中

    - `local file header` ：文件头用于标识该文件的开始，记录了该压缩文件的信息，这里的文件头标识由固定值 `50 4B 03 04` 开头，也是 `ZIP` 的文件头的重要标志
    - `file data` ：文件数据记录了相应压缩文件的数据
    - `data descriptor` ：数据描述符用于标识该文件压缩结束，该结构只有在相应的 `local file header` 中通用标记字段的第 `3 bit` 设为 `1` 时才会出现，紧接在压缩文件源数据后

- `Central directory` 核心目录

    - 记录了压缩文件的目录信息，在这个数据区中每一条纪录对应在压缩源文件数据区中的一条数据。

    | Offset | Bytes | Description                                          | 译                                       |
    | ------ | ----- | ---------------------------------------------------- | ---------------------------------------- |
    | 0      | 4     | Central directory file header signature = 0x02014b50 | 核心目录文件 header 标识 =（0x02014b50） |
    | 4      | 2     | Version made by                                      | 压缩所用的 pkware 版本                   |
    | 6      | 2     | Version needed to extract (minimum)                  | 解压所需 pkware 的最低版本               |
    | 8      | 2     | General purpose bit flag                             | 通用位标记伪加密                         |
    | 10     | 2     | Compression method                                   | 压缩方法                                 |
    | 12     | 2     | File last modification time                          | 文件最后修改时间                         |
    | 14     | 2     | File last modification date                          | 文件最后修改日期                         |
    | 16     | 4     | CRC-32                                               | CRC-32 校验码                            |
    | 20     | 4     | Compressed size                                      | 压缩后的大小                             |
    | 24     | 4     | Uncompressed size                                    | 未压缩的大小                             |
    | 28     | 2     | File name length (n)                                 | 文件名长度                               |
    | 30     | 2     | Extra field length (m)                               | 扩展域长度                               |
    | 32     | 2     | File comment length (k)                              | 文件注释长度                             |
    | 34     | 2     | Disk number where file starts                        | 文件开始位置的磁盘编号                   |
    | 36     | 2     | Internal file attributes                             | 内部文件属性                             |
    | 38     | 4     | External file attributes                             | 外部文件属性                             |
    | 42     | 4     | relative offset of local header                      | 本地文件头的相对位移                     |
    | 46     | n     | File name                                            | 目录文件名                               |
    | 46+n   | m     | Extra field                                          | 扩展域                                   |
    | 46+n+m | k     | File comment                                         | 文件注释内容                             |

 - `End of central directory record(EOCD)` 目录结束标识

 - 目录结束标识存在于整个归档包的结尾，用于标记压缩的目录数据的结束。每个压缩文件必须有且只有一个 `EOCD` 记录。

   

   

`RAR` 文件主要由标记块，压缩文件头块，文件头块，结尾块组成。

   其每一块大致分为以下几个字段：

   | 名称       | 大小 | 描述                  |
   | ---------- | ---- | --------------------- |
   | HEAD_CRC   | 2    | 全部块或块部分的 CRC  |
   | HEAD_TYPE  | 1    | 块类型                |
   | HEAD_FLAGS | 2    | 阻止标志              |
   | HEAD_SIZE  | 2    | 块大小                |
   | ADD_SIZE   | 4    | 可选字段 - 添加块大小 |

   Rar 压缩包的文件头为 `0x 52 61 72 21 1A 07 00`。

   紧跟着文件头（0x526172211A0700）的是标记块（MARK_HEAD），其后还有文件头（File Header）。

   | 名称          | 大小            | 描述                                                         |
   | ------------- | --------------- | ------------------------------------------------------------ |
   | HEAD_CRC      | 2               | CRC of fields from HEAD_TYPE to FILEATTR and file name       |
   | HEAD_TYPE     | 1               | Header Type: 0x74                                            |
   | HEAD_FLAGS    | 2               | Bit Flags (Please see ‘Bit Flags for File in Archive’ table for all possibilities)（伪加密） |
   | HEAD_SIZE     | 2               | File header full size including file name and comments       |
   | PACK_SIZE     | 4               | Compressed file size                                         |
   | UNP_SIZE      | 4               | Uncompressed file size                                       |
   | HOST_OS       | 1               | Operating system used for archiving (See the ‘Operating System Indicators’ table for the flags used) |
   | FILE_CRC      | 4               | File CRC                                                     |
   | FTIME         | 4               | Date and time in standard MS DOS format                      |
   | UNP_VER       | 1               | RAR version needed to extract file (Version number is encoded as 10 * Major version + minor version.) |
   | METHOD        | 1               | Packing method (Please see ‘Packing Method’ table for all possibilities |
   | NAME_SIZE     | 2               | File name size                                               |
   | ATTR          | 4               | File attributes                                              |
   | HIGH_PACK_SIZ | 4               | High 4 bytes of 64-bit value of compressed file size. Optional value, presents only if bit 0x100 in HEAD_FLAGS is set. |
   | HIGH_UNP_SIZE | 4               | High 4 bytes of 64-bit value of uncompressed file size. Optional value, presents only if bit 0x100 in HEAD_FLAGS is set. |
   | FILE_NAME     | NAME_SIZE bytes | File name - string of NAME_SIZE bytes size                   |
   | SALT          | 8               | present if (HEAD_FLAGS & 0x400) != 0                         |
   | EXT_TIME      | variable size   | present if (HEAD_FLAGS & 0x1000) != 0                        |

   每个 RAR 文件的结尾快（Terminator）都是固定的。

   | Field Name | Size (bytes) | Possibilities       |
   | ---------- | ------------ | ------------------- |
   | HEAD_CRC   | 2            | Always 0x3DC4       |
   | HEAD_TYPE  | 1            | Header type: 0x7b   |
   | HEAD_FLAGS | 2            | Always 0x4000       |
   | HEAD_SIZE  | 2            | Block size = 0x0007 |

 

 攻击方式：伪加密破解、已知明文攻击、爆破、CRC32攻击

   > `伪加密`是在ZIP文件的核心目录区中，将通用标记位的两个字节做修改
   >
   > 是一个未加密的文件伪装成已经加密的文件，解压时需要输入密码，因为源文件本没有加密，自然什么密码都不对 
   >
   > 无加密
   >
   > 压缩源文件数据区的全局加密应当为`00 00` 
   >  且压缩源文件目录区的全局方式位标记应当为`00 00`
   >
   > 假加密
   >
   > 压缩源文件数据区的全局加密应当为`00 00` 
   >  且压缩源文件目录区的全局方式位标记应当为`09 00`
   >
   > 真加密
   >
   > 压缩源文件数据区的全局加密应当为`09 00` 
   >  且压缩源文件目录区的全局方式位标记应当为`09 00`
   >
   > ![这里写图片描述](https://img-blog.csdn.net/20170801022644776?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQva2Fqd2Vi/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70/gravity/SouthEast)

   > `爆破`暴力破解顾名思义，就是逐个尝试选定集合中可以组成的所有密码，知道遇到正确密码
   >
   > 而字典攻击的效率比爆破稍高，因为字典中存储了常用的密码，因此就避免了爆破时把时间浪费在脸滚键盘类的密码上，平时可以收集相应的字典，同时实际运用时也可以根据具体收集的信息来构造字典

   > `已知明文攻击`是一种较为高效的攻击手段，大致原理是当你不知道一个zip的密码，但是你有zip中的一个已知文件（文件大小要大于12Byte）或者已经通过其他手段知道zip加密文件中的某些内容时，因为同一个zip压缩包里的所有文件都是使用同一个加密密钥来加密的，所以可以用已知文件来找加密密钥，利用密钥来解锁其他加密文件

   > `CRC32攻击`CRC本身是“冗余校验码”的意思，CRC32则表示会产生一个32bit（8位十六进制数）的校验值。在产生CRC32时，源数据块的每一位都参与了运算，因此即使数据块中只有一位发生改变也会得到不同的CRC32值，利用这个原理我们可以直接爆破出加密文件的内容, 也就是构造文件, 当构造出来的文件的CRC与原文件的CRC相同的时候, 就意味着这两个文件是相同的

#### 固件分析





### 隐写分析

------



#### 图片隐写

图像文件有多种复杂的格式，可以用于各种涉及到元数据、信息丢失和无损压缩、校验、隐写或可视化数据编码的分析解密，都是 Misc 中的一个很重要的出题方向。涉及到的知识点很多（包括基本的文件格式，常见的隐写手法及隐写用的软件），有的地方也需要去进行深入的理解。

1. JPG

   - PEG 是有损压缩格式，将像素信息用 JPEG 保存成文件再读取出来，其中某些像素值会有少许变化。在保存时有个质量参数可在 0 至 100 之间选择，参数越大图片就越保真，但图片的体积也就越大。一般情况下选择 70 或 80 就足够了
   -  JPEG 没有透明度信息
   
   JPG 基本数据结构为两大类型：「段」和经过压缩编码的图像数据。
   
   | 名 称   | 字节数 | 数据 | 说明                                         |
   | ------- | ------ | ---- | -------------------------------------------- |
   | 段 标识 | 1      | FF   | 每个新段的开始标识                           |
   | 段类型  | 1      |      | 类型编码（称作标记码）                       |
   | 段长 度 | 2      |      | 包括段内容和段长度本身, 不包括段标识和段类型 |
   | 段内容  | 2      |      | ≤65533 字节                                  |
   
   - 有些段没有长度描述也没有内容，只有段标识和段类型。文件头和文件尾均属于这种段。
   - 段与段之间无论有多少 `FF` 都是合法的，这些 `FF` 称为「填充字节」，必须被忽略掉。
   
   一些常见的段类型
   
   ![img](https://ctf-wiki.github.io/ctf-wiki/misc/picture/figure/jpgformat.png)
   
   `0xffd8` 和 `0xffd9`为 JPG 文件的开始结束的标志。

2. PNG

    对于一个 PNG 文件来说，其文件头总是由位固定的字节来描述的，剩余的部分由 3 个以上的 PNG 的数据块（Chunk）按照特定的顺序组成。
    
    文件头 `89 50 4E 47 0D 0A 1A 0A` + 数据块 + 数据块 + 数据块……
    
    ### 数据块 CHUNk
    
    PNG 定义了两种类型的数据块，一种是称为关键数据块（critical  chunk），这是标准的数据块，另一种叫做辅助数据块（ancillary chunks），这是可选的数据块。关键数据块定义了 4  个标准数据块，每个 PNG 文件都必须包含它们，PNG 读写软件也都必须要支持这些数据块。
    
    | 数据块符号 | 数据块名称             | 多数据块 | 可选否 | 位置限制               |
    | ---------- | ---------------------- | -------- | ------ | ---------------------- |
    | IHDR       | 文件头数据块           | 否       | 否     | 第一块                 |
    | cHRM       | 基色和白色点数据块     | 否       | 是     | 在 PLTE 和 IDAT 之前   |
    | gAMA       | 图像γ数据块            | 否       | 是     | 在 PLTE 和 IDAT 之前   |
    | sBIT       | 样本有效位数据块       | 否       | 是     | 在 PLTE 和 IDAT 之前   |
    | PLTE       | 调色板数据块           | 否       | 是     | 在 IDAT 之前           |
    | bKGD       | 背景颜色数据块         | 否       | 是     | 在 PLTE 之后 IDAT 之前 |
    | hIST       | 图像直方图数据块       | 否       | 是     | 在 PLTE 之后 IDAT 之前 |
    | tRNS       | 图像透明数据块         | 否       | 是     | 在 PLTE 之后 IDAT 之前 |
    | oFFs       | (专用公共数据块）      | 否       | 是     | 在 IDAT 之前           |
    | pHYs       | 物理像素尺寸数据块     | 否       | 是     | 在 IDAT 之前           |
    | sCAL       | (专用公共数据块）      | 否       | 是     | 在 IDAT 之前           |
    | IDAT       | 图像数据块             | 是       | 否     | 与其他 IDAT 连续       |
    | tIME       | 图像最后修改时间数据块 | 否       | 是     | 无限制                 |
    | tEXt       | 文本信息数据块         | 是       | 是     | 无限制                 |
    | zTXt       | 压缩文本数据块         | 是       | 是     | 无限制                 |
    | fRAc       | (专用公共数据块）      | 是       | 是     | 无限制                 |
    | gIFg       | (专用公共数据块）      | 是       | 是     | 无限制                 |
    | gIFt       | (专用公共数据块）      | 是       | 是     | 无限制                 |
    | gIFx       | (专用公共数据块）      | 是       | 是     | 无限制                 |
    | IEND       | 图像结束数据           | 否       | 否     | 最后一个数据块         |
    
    对于每个数据块都有着统一的数据结构，每个数据块由 4 个部分组成
    
    | 名称                            | 字节数   | 说明                                                 |
    | ------------------------------- | -------- | ---------------------------------------------------- |
    | Length（长度）                  | 4 字节   | 指定数据块中数据域的长度，其长度不超过（231－1）字节 |
    | Chunk Type Code（数据块类型码） | 4 字节   | 数据块类型码由 ASCII 字母（A - Z 和 a - z）组成      |
    | Chunk Data（数据块数据）        | 可变长度 | 存储按照 Chunk Type Code 指定的数据                  |
    | CRC（循环冗余检测）             | 4 字节   | 存储用来检测是否有错误的循环冗余码                   |
    
    CRC（Cyclic Redundancy Check）域中的值是对 Chunk Type Code 域和 Chunk Data 域中的数据进行计算得到的。
    
    ### IHDR
    
    文件头数据块 IHDR（Header Chunk）：它包含有 PNG 文件中存储的图像数据的基本信息，由 13 字节组成，并要作为第一个数据块出现在 PNG 数据流中，而且一个 PNG 数据流中只能有一个文件头数据块
    
    其中我们关注的是前 8 字节的内容
    
    | 域的名称 | 字节数  | 说明                   |
    | -------- | ------- | ---------------------- |
    | Width    | 4 bytes | 图像宽度，以像素为单位 |
    | Height   | 4 bytes | 图像高度，以像素为单位 |
    
    我们经常会去更改一张图片的高度或者宽度使得一张图片显示不完整从而达到隐藏信息的目的。
    
    ### PLTE
    
    调色板数据块 PLTE（palette chunk）：它包含有与索引彩色图像（indexed-color image）相关的彩色变换数据，它仅与索引彩色图像有关，而且要放在图像数据块（image data chunk）之前。真彩色的 PNG 数据流也可以有调色板数据块，目的是便于非真彩色显示程序用它来量化图像数据，从而显示该图像。
    
    ### IDAT
    
    图像数据块 IDAT（image data chunk）：它存储实际的数据，在数据流中可包含多个连续顺序的图像数据块。
    
    - 储存图像像数数据
    - 在数据流中可包含多个连续顺序的图像数据块
    - 采用 LZ77 算法的派生算法进行压缩
    - 可以用 zlib 解压缩
    
    值得注意的是，IDAT 块只有当上一个块充满时，才会继续一个新的块。
    
    利用 `python zlib` 解压多余 IDAT 块的内容，此时注意剔除 长度、数据块类型及末尾的 CRC 校验值。
    
    ### IEND
    
    图像结束数据 IEND（image trailer chunk）：它用来标记 PNG 文件或者数据流已经结束，并且必须要放在文件的尾部。
    

    
     ```
     00 00 00 00 49 45 4E 44 AE 42 60 82
     ```
    
    IEND 数据块的长度总是 `00 00 00 00`，数据标识总是 IEND `49 45 4E 44`，因此，CRC 码也总是 `AE 42 60 82`。
    
    ### 其余辅助数据块
    
    - 背景颜色数据块 bKGD（background color）
    - 基色和白色度数据块 cHRM（primary chromaticities and white point），所谓白色度是指当 `R＝G＝B＝最大值` 时在显示器上产生的白色度
    - 图像 γ 数据块 gAMA（image gamma）
    - 图像直方图数据块 hIST（image histogram）
    - 物理像素尺寸数据块 pHYs（physical pixel dimensions）
    - 样本有效位数据块 sBIT（significant bits）
    - 文本信息数据块 tEXt（textual data）
    - 图像最后修改时间数据块 tIME （image last-modification time）
    - 图像透明数据块 tRNS （transparency）
    - 压缩文本数据块 zTXt （compressed textual data）
    

    
    ## LSB
    
    LSB 全称 Least Significant Bit，最低有效位。PNG 文件中的图像像数一般是由 RGB 三原色（红绿蓝）组成，每一种颜色占用 8 位，取值范围为 `0x00` 至 `0xFF`，即有 256 种颜色，一共包含了 256 的 3 次方的颜色，即 16777216 种颜色。
    
    而人类的眼睛可以区分约 1000 万种不同的颜色，意味着人类的眼睛无法区分余下的颜色大约有 6777216 种。
    
    LSB 隐写就是修改 RGB 颜色分量的最低二进制位（LSB），每个颜色会有 8 bit，LSB 隐写就是修改了像数中的最低的 1 bit，而人类的眼睛不会注意到这前后的变化，每个像素可以携带 3 比特的信息。

3. GIF

    一个 GIF 文件的结构可分为

    - 文件头（File Header）
      - GIF 文件署名（Signature）
      - 版本号（Version）
    - GIF 数据流（GIF Data Stream）
      - 控制标识符
      - 图象块（Image Block）
      - 其他的一些扩展块
    - 文件终结器（Trailer）

    ### 文件头 

    GIF 署名（Signature）和版本号（Version）。GIF 署名用来确认一个文件是否是 GIF 格式的文件，这一部分由三个字符组成：`GIF`；文件版本号也是由三个字节组成，可以为 `87a` 或 `89a`。

    ### 逻辑屏幕标识符（Logical Screen Descriptor）

    Logical Screen Descriptor（逻辑屏幕描述符）紧跟在 header 后面。这个块告诉  decoder（解码器）图片需要占用的空间。它的大小固定为 7 个字节，以 canvas width（画布宽度）和 canvas  height（画布高度）开始。

    ### 全局颜色列表（Global Color Table）

    GIF 格式可以拥有 global color table，或用于针对每个子图片集，提供 local color table。每个 color table 由一个 RGB（就像通常我们见到的（255，0，0）红色 那种）列表组成。

    ### 图像标识符（Image Descriptor）

    一个 GIF 文件一般包含多个图片。之前的图片渲染模式一般是将多个图片绘制到一个大的（virtual canvas）虚拟画布上，而现在一般将这些图片集用于实现动画。

    每个 image 都以一个 image descriptor block（图像描述块）作为开头，这个块固定为 10 字节。

    ![img](https://ctf-wiki.github.io/ctf-wiki/misc/picture/figure/imagesdescription.png)

    ### 图像数据（Image Data）

    终于到了图片数据实际存储的地方。Image Data 是由一系列的输出编码（output codes）构成，它们告诉 decoder（解码器）需要绘制在画布上的每个颜色信息。这些编码以字节码的形式组织在这个块中。

    ### 文件终结器（Trailer）

    该块为一个单字段块，用来指示该数据流的结束。取固定值 0x3b.

    

    由于 GIF 的动态特性，由一帧帧的图片构成，所以每一帧的图片，多帧图片间的结合，都成了隐藏信息的一种载体。

    或者是在上百帧中隐藏一帧带信息的图片, 或者是重复帧构成某种编码, 或者是设置播放速度极其慢 ,让人误以为静态图 , 或是通过每一帧持续时长的不同构成编码

    对于需要分离的 GIF 文件, 可以使用`convert`命令将其每一帧分割开来

   

4. BMP

   `bmp`是Windows操作系统中的标准图像文件格式, 它采用位映射存储格式，除了图像深度可选以外，不采用其他任何压缩，因此，BMP文件所占用的空间很大。BMP文件的图像深度可选lbit、4bit、8bit及24bit。BMP文件存储数据时，图像的扫描方式是按从左到右、从下到上的顺序。
   
   典型的BMP图像文件由四部分组成：
   
   1：位图文件头( 14字节 )
   
   它包含BMP文件的类型、文件大小和位图起始位置等信息；
   
   ```
   bfType 位图文件的类型，必须为BM(1-2字节）
   bfSize 位图文件的大小，以字节为单位（3-6字节，低位在前）
   bfReserved1 位图文件保留字，必须为0(7-8字节）
   bfReserved2 位图文件保留字，必须为0(9-10字节）
   bfOffBits 位图数据的起始位置，以相对于位图（11-14字节，低位在前)
   ```
   
   2：位图信息头( 40字节 ) 
   
   它包含有BMP图像的宽、高、压缩方法，以及定义颜色等信息；
   
   ```
   biSize 本结构所占用字节数（15-18字节）
   biWidth 位图的宽度，以像素为单位（19-22字节）
   biHeight 位图的高度，以像素为单位（23-26字节）
   biPlanes 目标设备的级别，必须为1(27-28字节）
   biBitCount 每个像素所需的位数，必须是1（双色），（29-30字节）
   //4(16色），8(256色）16(高彩色)或24（真彩色）之一
   biCompression 位图压缩类型，必须是0（不压缩），（31-34字节）
   //1(BI_RLE8压缩类型）或2(BI_RLE4压缩类型）之一
   biSizeImage 位图的大小(其中包含了为了补齐行数是4的倍数而添加的空字节)，以字节为单位（35-38字节）
   biXPelsPerMeter 位图水平分辨率，每米像素数（39-42字节）
   biYPelsPerMeter 位图垂直分辨率，每米像素数（43-46字节)
   biClrUsed 位图实际使用的颜色表中的颜色数（47-50字节）
   biClrImportant 位图显示过程中重要的颜色数（51-54字节）
   ```
   
   3：调色板
   
   这个部分是可选的，有些位图需要调色板，有些位图，比如真彩色图（24位的BMP）就不需要调色板；
   
   ```
   rgbBlue 蓝色的亮度（值范围为0-255)(1字节)
   rgbGreen 绿色的亮度（值范围为0-255)(1字节)
   rgbRed 红色的亮度（值范围为0-255)(1字节)
   rgbReserved 保留，必须为0(1字节)
   ```
   
   4：位图数据，位图数据记录了位图的每一个像素值，记录顺序是在扫描行内是从左到右，扫描行之间是从下到上。这部分的内容根据BMP位图使用的位数不同而不同，在24位图中直接使用RGB，而其他的小于24位的使用调色板中颜色索引值。位图的一个像素值所占的字节数：
   
   当biBitCount=1时，8个像素占1个字节；
   
   当biBitCount=4时，2个像素占1个字节；
   
   当biBitCount=8时，1个像素占1个字节；
   
   当biBitCount=24时，1个像素占3个字节,按顺序分别为B,G,R；

   

#### 音频隐写

1. 频谱

   > 音频中的频谱隐写是将字符串隐藏在频谱中，此类音频通常会有一个较明显的特征，听起来是一段杂音或者比较刺耳。
   >
   > 

   

2. 波形

   > 通常来说，波形方向的题，在观察到异常后，使用相关软件（Audacity, Adobe Audition 等）观察波形规律，将波形进一步转化为 01 字符串等
   >
   > 一些较复杂的可能会先对音频进行一系列的处理，如滤波等

   

3. LSB

   > 类似于图片隐写中的 LSB 隐写，音频中也有对应的 LSB 隐写。主要可以使用 [Silenteye](http://silenteye.v1kings.io/) 工具

3. 无线电编码
   

#### 视频隐写

1. MSU stego
2. TCStego

#### 文档隐写

1. word
2. pdf
3. openXML

#### 流量包隐写

1. 附件
2. 协议
3. 字符串拆分

#### 交换数据流隐写(NTFS)

> NTFS交换数据流（alternate data streams，简称ADS）是NTFS磁盘格式的一个特性，在NTFS文件系统下，每个文件都可以存在多个数据流，就是说除了主文件流之外还可以有许多非主文件流寄宿在主文件流中。它使用资源派生来维持与文件相关的信息，虽然我们无法看到数据流文件，但是它却是真实存在于我们的系统中的。创建一个数据交换流文件的方法很简单，命令为"宿主文件:准备与宿主文件关联的数据流文件"。
>
> 流文件不能直接通过网络传输，也不能使用WinRAR进行普通压缩后传输，那样会丢失信息，必须在压缩时选择高级选项里的“保存文件流数据“才行
>
> 制作好的流文件大小跟用来隐藏原文件的那个文件是一样的，但压缩后的文件还是包括了隐藏文件的大小，这说明NTFS文件流仍然会占用磁盘空间，这是判断文件是否包含流文件的重要方法，对比解压后的文件大小和压缩包的大小，如果前者小于后者那就说明这个压缩包里有猫腻
>
> 流文件必须要在NTFS分区下才能运行，一旦放到其他的文件系统分区中，即使再放回来，也会造成NTFS数据流的丢失

#### HTML隐写

> `snow`是Mattehew Kwan开发的软件，它可以在ASCII文本的末行隐藏数据，并且可以通过插入制表位和空格使嵌入的数据在浏览器中不可见。Snow支持ICE（Information Concealment Engine）加密。最初是为DOS开发的，现在已经成为开源的。

### vmdk隐写

dsfok-bools