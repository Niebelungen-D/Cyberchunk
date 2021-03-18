# Heap

> 在程序运行过程中，堆可以提供动态分配的内存，允许程序申请大小未知的内存。堆其实就是程序虚拟地址空间的一块连续的线性区域，它由低地址向高地址方向增长。我们一般称管理堆的那部分程序为堆管理器。

## 堆的操作

### malloc

```c
/*
  malloc(size_t n)
  Returns a pointer to a newly allocated chunk of at least n bytes, or null
  if no space is available. Additionally, on failure, errno is
  set to ENOMEM on ANSI C systems.
  If n is zero, malloc returns a minumum-sized chunk. (The minimum
  size is 16 bytes on most 32bit systems, and 24 or 32 bytes on 64bit
  systems.)  On most systems, size_t is an unsigned type, so calls
  with negative arguments are interpreted as requests for huge amounts
  of space, which will often fail. The maximum supported value of n
  differs across systems, but is in all cases less than the maximum
  representable value of a size_t.
*/
```

- malloc 函数返回对应大小字节的内存块的指针
- 当 n=0 时，返回当前系统允许的堆的最小内存块。
- 当 n 为负数时，由于在大多数系统上，**size_t 是无符号数（这一点非常重要）**，所以程序就会申请很大的内存空间，但通常来说都会失败，因为系统没有那么多的内存可以分配

### free

```c
/*
      free(void* p)
      Releases the chunk of memory pointed to by p, that had been previously
      allocated using malloc or a related routine such as realloc.
      It has no effect if p is null. It can have arbitrary (i.e., bad!)
      effects if p has already been freed.
      Unless disabled (using mallopt), freeing very large spaces will
      when possible, automatically trigger operations that give
      back unused memory to the system, thus reducing program footprint.
    */
```

- 释放由 p 所指向的内存块。这个内存块有可能是通过 malloc 函数得到的，也有可能是通过相关的函数 realloc 得到的。
- **当 p 为空指针时，函数不执行任何操作。**
- 当 p 已经被释放之后，再次释放会出现乱七八糟的效果: `double free`。
- 除了被禁用 (mallopt) 的情况下，当释放很大的内存空间时，程序会将这些内存空间还给系统，以便于减小程序所使用的内存空间

## 内存分配背后的系统调用

![](G:\CTF\writeup\图片\内存分配的系统调用.png)

### (s)brk

sbrk()是库函数，brk()是系统调用，都是改变brk的值来扩展收缩堆。

start_brk是进程动态分配的起始地址（heap的起始地址），brk 是堆当前最后的地址。

初始时，堆的起始地址 [start_brk](http://elixir.free-electrons.com/linux/v3.8/source/include/linux/mm_types.h#L365) 以及堆的当前末尾 [brk](http://elixir.free-electrons.com/linux/v3.8/source/include/linux/mm_types.h#L365) 指向同一地址。根据是否开启ASLR，两者的具体位置会有所不同:

- 不开启 ASLR 保护时，start_brk 以及 brk 会指向 data/bss 段的结尾。
- 开启 ASLR 保护时，start_brk 以及 brk 也会指向同一位置，只是这个位置是在 data/bss 段结尾后的随机偏移处。

### mmap

malloc 会使用 mmap来创建独立的匿名映射段。匿名映射的目的主要是可以申请以0填充的内存，并且这块内存仅被调用进程所使用。

mmap 是一种内存映射方法，将一个文件或其他对象映射到进程的地址空间，实现文件磁盘地址和进程虚拟地址一一对应的关系。内核空间对这块区域的改变也直接反应到用户空间，实现不同进程的文件共享。

默认情况下，**malloc函数分配内存，如果请求内存大于128K（可由M_MMAP_THRESHOLD选项调节），并且没有任何arena有足够的空间时，那就不是去改变brk的值了，而是利用mmap系统调用，从堆和栈的中间分配一块虚拟内存。**

因为使用brk调用的内存无法单独释放，例如，brk申请了A,B两块内存，必须要B释放后A才能释放。而mmap申请的内存可以单独释放。

munmap用来释放mmap申请的内存。

> brk和mmap的内存申请方式都与中断有关，其中涉及虚拟内存的分页机制，具体理解待补充。。。

### arena

**虽然程序可能只是向操作系统申请很小的内存，但是为了方便，操作系统会把很大的内存分配给程序。这样的话，就避免了多次内核态与用户态的切换，提高了程序的效率。**我们称这一块连续的内存区域为 arena。此外，我们称由主线程申请的内存为 main_arena。后续的申请的内存会一直从这个 arena 中获取，直到空间不足。当 arena 空间不足时，它可以通过增加brk的方式来增加堆的空间。类似地，arena 也可以通过减小 brk 来缩小自己的空间。

内存分配区，可以理解为堆管理器所持有的内存池

- 操作系统 --> 堆管理器 --> 用户

- 物理内存 --> arena  --> 可用内存

堆管理器与用户的内存交易发生于arena中，可以理解为堆管理器向操作系统批发来的有冗余的内存库存

对于不同系统，arena数量的[约束](https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/arena.c#L847)如下：

```c
For 32 bit systems:
     Number of arena = 2 * number of cores+1.
For 64 bit systems:
     Number of arena = 8 * number of cores+1.
```

#### 多Arena的管理

假设有如下情境：一台只含有一个处理器核心的PC机安装有32位操作系统，其上运行了一个多线程应用程序，共含有4个线程——主线程和三个用户线程。显然线程个数大于系统能维护的最大arena个数（2*核心数 + 1= 3），那么此时glibc malloc就需要确保这4个线程能够正确地共享这3个arena，那么它是如何实现的呢？

当主线程首次调用malloc的时候，glibc malloc会直接为它分配一个main arena，而不需要任何附加条件。

当用户线程1和用户线程2首次调用malloc的时候，glibc malloc会分别为每个用户线程创建一个新的thread arena。此时，各个线程与arena是一一对应的。但是，当用户线程3调用malloc的时候，就出现问题了。因为此时glibc malloc能维护的arena个数已经达到上限，无法再为线程3分配新的arena了，那么就需要重复使用已经分配好的3个arena中的一个(main arena, arena 1或者arena 2)。那么该选择哪个arena进行重复利用呢？

1)首先，glibc malloc循环遍历所有可用的arenas，在遍历的过程中，它会尝试lock该arena。如果成功lock(该arena当前对应的线程并未使用堆内存则表示可lock)，比如将main arena成功lock住，那么就将main arena返回给用户，即表示该arena被线程3共享使用。

2)而如果没能找到可用的arena，那么就将线程3的malloc操作阻塞，直到有可用的arena为止。

3)现在，如果线程3再次调用malloc的话，glibc malloc就会先尝试使用最近访问的arena(此时为main arena)。如果此时main arena可用的话，就直接使用，否则就将线程3阻塞，直到main arena再次可用为止。

这样线程3与主线程就共享main arena了。至于其他更复杂的情况，以此类推。

## 堆的相关数据结构

与堆相应的数据结构主要分为

- 宏观结构，包含堆的宏观信息，可以通过这些数据结构索引堆的基本信息。

- 微观结构，用于具体处理堆的分配与回收中的内存块。

  **chunk**是堆管理器管理内存的基本单位，malloc()返回的指针指向一个chunk的数据区域。

### malloc_chunk

```c
/*
  This struct declaration is misleading (but accurate and necessary).
  It declares a "view" into memory allowing access to necessary
  fields at known offsets from a given base. See explanation below.
*/
struct malloc_chunk {

  INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};
```

 INTERNAL_SIZE_T用于内部记录chunk的大小，与size_t大小相同，两者都是无符号整数。一般来说，size_t 在 64 位中是 64 位无符号整数，32 位中是 32 位无符号整数。

- **prev_size**, 如果该 chunk 的**物理相邻的前一地址chunk（两个指针的地址差值为前一chunk大小）**是空闲的话，那该字段记录的是前一个 chunk 的大小(包括 chunk 头)。否则，该字段可以用来存储物理相邻的前一个chunk 的数据。**这里的前一 chunk 指的是较低地址的 chunk** 。
- size，该 chunk 的大小，大小必须是 2 * SIZE_SZ 的整数倍。如果申请的内存大小不是 2 * SIZE_SZ 的整数倍，会被转换满足大小的最小的 2 * SIZE_SZ 的倍数。32 位系统中，SIZE_SZ 是 4；64 位系统中，SIZE_SZ 是 8。 该字段的低三个比特位对 chunk 的大小没有影响，它们从高到低分别表示
  - A: NON_MAIN_ARENA，记录当前 chunk 是否不属于主线程，1表示不属于，0表示属于。
  - M: IS_MAPPED，记录当前 chunk 是否是由 mmap 分配的。
  - P: PREV_INUSE，记录前一个 chunk 块是否被分配。一般来说，堆中第一个被分配的内存块的 size 字段的P位都会被设置为1，以便于防止访问前面的非法内存。当一个 chunk 的 size 的 P 位为 0 时，我们能通过 prev_size 字段来获取上一个 chunk 的大小以及地址。这也方便进行空闲chunk之间的合并。
- fd，bk。 chunk 处于分配状态时，从 fd 字段开始是用户的数据。chunk 空闲时，会被添加到对应的空闲管理链表中，其字段的含义如下
  - fd 指向下一个（非物理相邻）空闲的 chunk
  - bk 指向上一个（非物理相邻）空闲的 chunk
- fd_nextsize， bk_nextsize，也是只有 chunk 空闲的时候才使用，不过其用于较大的 chunk（large chunk）。
  - fd_nextsize 指向前一个与当前 chunk 大小不同的第一个空闲块，不包含 bin 的头指针。
  - bk_nextsize 指向后一个与当前 chunk 大小不同的第一个空闲块，不包含 bin 的头指针。
  - 一般空闲的 large chunk 在 fd 的遍历顺序中，按照由大到小的顺序排列。**这样做可以避免在寻找合适chunk 时挨个遍历。**

一个已经分配的 chunk 的样子如下。**我们称前两个字段称为 chunk header，后面的部分称为 user data。每次 malloc 申请得到的内存指针，其实指向 user data 的起始处。**

当一个 chunk 处于使用状态时，它的下一个 chunk 的 prev_size 域无效，所以下一个 chunk 的该部分也可以被当前chunk使用。**这就是chunk中的空间复用。**

**malloc_chunk(Allocated chunk)**

```reStructuredText
chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Size of previous chunk, if unallocated (P clear)  |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Size of chunk, in bytes                     |A|M|P|
  mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             User data starts here...                          .
        .                                                               .
        .             (malloc_usable_size() bytes)                      .
next    .                                                               |
chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             (size of chunk, but used for application data)    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Size of next chunk, in bytes                |A|0|1|
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**free chunk**

```reStructuredText
chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Size of previous chunk, if unallocated (P clear)  |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
`head:' |             Size of chunk, in bytes                     |A|0|P|
  mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Forward pointer to next chunk in list             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Back pointer to previous chunk in list            |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Unused space (may be 0 bytes long)                .
        .                                                               .
 next   .                                                               |
chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
`foot:' |             Size of chunk, in bytes                           |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Size of next chunk, in bytes                |A|0|0|
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**一般情况下**，物理相邻的两个空闲 chunk 会被合并为一个 chunk 。堆管理器会通过 prev_size 字段以及 size 字段合并两个物理相邻的空闲 chunk 块。

### chunk

用户最小申请的内存大小必须是 2 * SIZE_SZ 的最小整数倍。(32位系统下为8字节，64系统位下为16字节)

**字节对齐**

系统会检查用户申请的内存大小是否是 2 * SIZE_SZ 的整数倍，如果不是系统会自动进行补齐。保证所有的chunk都2 * SIZE_SZ对齐。

### bin

用户释放掉的 chunk 不会马上归还给系统，ptmalloc 会统一管理 heap 和 mmap 映射区域中的空闲的chunk。当用户再一次请求分配内存时，ptmalloc 分配器会试图在空闲的chunk中挑选一块合适的给用户。

bin根据chunk的大小进行分类，采用链表的方式进行管理，数组元素为相应大小chunk链表的表头：

1. Fast bin
2. Unsorted bin
3. Small bin
4. Large bin

fast bin的维护：

```c
typedef struct malloc_chunk *mfastbinptr;

mfastbinptr fastbinsY[]; // Array of pointers to chunks
```

 small bins，large bins，unsorted bin 来说，Ptmalloc 将它们维护在同一个数组中：

```c
typedef struct malloc_chunk* mchunkptr;

mchunkptr bins[]; // Array of pointers to chunks
```

#### fast bin

有10个fast bin。每个fast bin都包含一个单向链表，每个bin包含的chunk的相同。采用**LIFO**进行管理，这10个bin中chunk的大小为：6、24、32、40、48、56、64、72、80和88（包含chunk head）。

**fastbin 范围的 chunk 的 inuse 始终被置为 1。因此它们不会和其它被释放的 chunk 合并。**

![](G:\CTF\blog\picture\fastbin.png)

#### unsorted bin

bins[1], unsorted bin 只有一个链表，可以视为空闲 chunk 回归其所属 bin 之前的缓冲区。

unsorted bin 中的空闲 chunk 处于乱序状态，主要有两个来源：

- 当一个较大的 chunk 被分割成两半后，如果剩下的部分大于 MINSIZE，就会被放到 unsorted bin 中。
- 释放一个不属于 fast bin 的 chunk，并且该 chunk 不和 top chunk 紧邻时，该 chunk 会被首先放到 unsorted bin 中。关于 top chunk 的解释，请参考下面的介绍。

此外，Unsorted Bin 在使用的过程中，采用的遍历顺序是 FIFO 。

![](G:\CTF\blog\picture\unsortedbin.png)

#### small bins

有62个small bins，bins[2]~bins[63]。每个bin包含一个双向循环列表，管理16、24、32、40、···、504Bytes的free chunk，采用的遍历顺序是 FIFO 。

![](G:\CTF\blog\picture\smallbin.png)

fast bin 中的 chunk 是有可能被放到 small bin 中去。

#### large bins

有63个large bins，bins[64]~bins[126。每个bin包含一个双向循环列表，管理大于504Bytes的free chunk。

large bins 中一共包括 63 个 bin，每个 bin 中的 chunk 的大小不一致，而是处于一定区间范围内。此外，这 63 个 bin 被分成了 6 组，每组 bin 中的 chunk 大小之间的公差一致，具体如下：

|  组  | 数量 |  公差   |
| :--: | :--: | :-----: |
|  1   |  32  |   64B   |
|  2   |  16  |  512B   |
|  3   |  8   |  4096B  |
|  4   |  4   | 32768B  |
|  5   |  2   | 262144B |
|  6   |  1   | 不限制  |

![](G:\CTF\blog\picture\largebins.png)

#### Top chunk

程序第一次进行 malloc 的时候，heap 会被分为两块，一块给用户，剩下的那块就是 top chunk。其实，所谓的top chunk 就是处于当前堆的物理地址最高的 chunk。这个 chunk 不属于任何一个 bin，它的作用在于当所有的bin 都无法满足用户请求的大小时，如果其大小不小于指定的大小，就进行分配，并将剩下的部分作为新的 top chunk。否则，就对heap进行扩展后再进行分配。在main arena中通过sbrk扩展heap，而在thread arena中通过mmap分配新的heap。

需要注意的是，top chunk 的 prev_inuse 比特位始终为1，否则其前面的chunk就会被合并到top chunk中。

#### last remainer chunk

在用户使用 malloc 请求分配内存时，ptmalloc2 找到的 chunk 可能并不和申请的内存大小一致，这时候就将分割之后的剩余部分称之为 last remainder chunk ，unsort bin 也会存这一块。top chunk 分割剩下的部分不会作为last remainer。

### heap_info

程序刚开始执行时，每个线程是没有 heap 区域的。当其申请内存时，就需要一个结构来记录对应的信息，而heap_info 的作用就是这个。而且当该heap的资源被使用完后，就必须得再次申请内存了。此外，一般申请的heap 是不连续的，因此需要记录不同heap之间的链接结构。

**该数据结构是专门为从 Memory Mapping Segment 处申请的内存准备的，即为非主线程准备的。**

主线程可以通过 sbrk() 函数扩展 program break location 获得（直到触及Memory Mapping Segment），只有一个heap，没有 heap_info 数据结构

因为一个**thread arena**（注意：不包含**main thread**）可以包含多个heaps，所以为了便于管理，就给每个heap分配一个heap header。那么在什么情况下一个thread arena会包含多个heaps呢?在当前heap不够用的时候，malloc会通过系统调用mmap申请新的堆空间，新的堆空间会被添加到当前thread arena中，便于管理。

### malloc_state

该结构用于管理堆，记录每个 arena 当前申请的内存的具体状态，比如说是否有空闲chunk，有什么大小的空闲chunk 等等。无论是 thread arena 还是 main arena，它们都只有一个 malloc state 结构。由于 thread 的 arena 可能有多个，malloc state结构会在最新申请的arena中。

**注意，main arena 的 malloc_state 并不是 heap segment 的一部分，而是一个全局变量，存储在 libc.so 的数据段。**

```c
struct malloc_state {
    /* Serialize access.  */
    __libc_lock_define(, mutex);

    /* Flags (formerly in max_fast).  */
    int flags;

    /* Fastbins */
    mfastbinptr fastbinsY[ NFASTBINS ];

    /* Base of the topmost chunk -- not otherwise kept in a bin */
    mchunkptr top;

    /* The remainder from the most recent split of a small request */
    mchunkptr last_remainder;

    /* Normal bins packed as described above */
    mchunkptr bins[ NBINS * 2 - 2 ];

    /* Bitmap of bins, help to speed up the process of determinating if a given bin is definitely empty.*/
    unsigned int binmap[ BINMAPSIZE ];

    /* Linked list, points to the next arena */
    struct malloc_state *next;

    /* Linked list for free arenas.  Access to this field is serialized
       by free_list_lock in arena.c.  */
    struct malloc_state *next_free;

    /* Number of threads attached to this arena.  0 if the arena is on
       the free list.  Access to this field is serialized by
       free_list_lock in arena.c.  */
    INTERNAL_SIZE_T attached_threads;

    /* Memory allocated from the system in this arena.  */
    INTERNAL_SIZE_T system_mem;
    INTERNAL_SIZE_T max_system_mem;
};
```

### heap segment与arena关系

下图是只有一个heap segment的main arena和thread arena的内存分布图：

![](G:\CTF\blog\picture\oneheap.png)

下图是一个thread arena中含有多个heap segments的情况：

![](G:\CTF\blog\picture\multiheap.png)

从上图可以看出，thread arena只含有一个malloc_state(即arena header)，却有两个heap_info(即heap header)。由于两个heap segments是通过mmap分配的内存，两者在内存布局上并不相邻而是分属于不同的内存区间，所以为了便于管理，libc malloc将第二个heap_info结构体的prev成员指向了第一个heap_info结构体的起始位置（即ar_ptr成员），而第一个heap_info结构体的ar_ptr成员指向了malloc_state，这样就构成了一个单链表，方便后续管理。

## 堆的实现

### unlink

unlink 用来将一个双向链表（只存储空闲的 chunk）中的一个元素取出来，可能在以下地方使用

- malloc
  - 从恰好大小合适的 large bin 中获取 chunk。
    - **这里需要注意的是 fastbin 与 small bin 就没有使用 unlink，这就是为什么漏洞会经常出现在它们这里的原因。**
    - 依次遍历处理 unsorted bin 时也没有使用 unlink 的。
  - 从比请求的 chunk 所在的 bin 大的 bin 中取 chunk。
- Free
  - 后向合并，合并物理相邻低地址空闲 chunk。
  - 前向合并，合并物理相邻高地址空闲 chunk（除了 top chunk）。
- malloc_consolidate
  - 后向合并，合并物理相邻低地址空闲 chunk。
  - 前向合并，合并物理相邻高地址空闲 chunk（除了 top chunk）。
- realloc
  - 前向扩展，合并物理相邻高地址空闲 chunk（除了top chunk）。

![](G:\CTF\blog\picture\unlink_smallbin_intro.png)

要取出的chunk并没有被改变，只是改变了其相邻chunk的指向。

- libc 地址
  - P 位于双向链表头部，bk 泄漏
  - P 位于双向链表尾部，fd 泄漏
  - 双向链表只包含一个空闲 chunk 时，P 位于双向链表中，fd 和 bk 均可以泄漏
- 泄漏堆地址，双向链表包含多个空闲 chunk
  - P 位于双向链表头部，fd 泄漏
  - P 位于双向链表中，fd 和 bk 均可以泄漏
  - P 位于双向链表尾部，bk 泄漏

**注意**

- 这里的头部指的是 bin 的 fd 指向的 chunk，即双向链表中最新加入的 chunk。
- 这里的尾部指的是 bin 的 bk 指向的 chunk，即双向链表中最先加入的 chunk。
- **堆的第一个 chunk 所记录的 prev_inuse 位默认为1。**

## 申请内存块

### __libc_malloc

这里需要注意的是，**用户申请的字节一旦进入申请内存函数中就变成了无符号整数**。

_libc_malloc寻找arena试图进行内存分配，并调用 _int_malloc 函数去申请对应的内存，分配失败就寻找下一个arena再次申请。

###  _int_malloc 

_int_malloc 是内存分配的核心函数，其核心思路有如下

1. 它根据用户申请的**内存块大小**以及**相应大小 chunk 通常使用的频度**（fastbin chunk, small chunk, large chunk），依次实现了不同的分配方法。
2. 它由小到大依次检查不同的 bin 中是否有相应的空闲块可以满足用户请求的内存。
3. 当所有的空闲 chunk 都无法满足时，它会考虑 top chunk。
4. 当 top chunk 也无法满足时，堆分配器才会进行内存块申请。

#### arena

```c
    /* There are no usable arenas.  Fall back to sysmalloc to get a chunk from
       mmap.  */
    if (__glibc_unlikely(av == NULL)) {
        void *p = sysmalloc(nb, av);
        if (p != NULL) alloc_perturb(p, bytes);
        return p;
    }
```

#### fast bin

如果申请的 chunk 的大小位于 fastbin 范围内，**需要注意的是这里比较的是无符号整数**。**此外，是从 fastbin 的头结点开始取 chunk**。

```c
    /*
       If the size qualifies as a fastbin, first check corresponding bin.
       This code is safe to execute even if av is not yet initialized, so we
       can try it without checking, which saves some time on this fast path.
     */

    if ((unsigned long) (nb) <= (unsigned long) (get_max_fast())) {
        // 得到对应的fastbin的下标
        idx             = fastbin_index(nb);
        // 得到对应的fastbin的头指针
        mfastbinptr *fb = &fastbin(av, idx);
        mchunkptr    pp = *fb;
        // 利用fd遍历对应的bin内是否有空闲的chunk块，
        do {
            victim = pp;
            if (victim == NULL) break;
        } while ((pp = catomic_compare_and_exchange_val_acq(fb, victim->fd,
                                                            victim)) != victim);
        // 存在可以利用的chunk
        if (victim != 0) {
            // 检查取到的 chunk 大小是否与相应的 fastbin 索引一致。
            // 根据取得的 victim ，利用 chunksize 计算其大小。
            // 利用fastbin_index 计算 chunk 的索引。
            if (__builtin_expect(fastbin_index(chunksize(victim)) != idx, 0)) {
                errstr = "malloc(): memory corruption (fast)";
            errout:
                malloc_printerr(check_action, errstr, chunk2mem(victim), av);
                return NULL;
            }
            // 细致的检查。。只有在 DEBUG 的时候有用
            check_remalloced_chunk(av, victim, nb);
            // 将获取的到chunk转换为mem模式
            void *p = chunk2mem(victim);
            // 如果设置了perturb_type, 则将获取到的chunk初始化为 perturb_type ^ 0xff
            alloc_perturb(p, bytes);
            return p;
        }
    }
```

#### small bin

如果获取的内存块的范围处于 small bin 的范围，那么执行如下流程

```c
    /*
       If a small request, check regular bin.  Since these "smallbins"
       hold one size each, no searching within bins is necessary.
       (For a large request, we need to wait until unsorted chunks are
       processed to find best fit. But for small ones, fits are exact
       anyway, so we can check now, which is faster.)
     */

    if (in_smallbin_range(nb)) {
        // 获取 small bin 的索引
        idx = smallbin_index(nb);
        // 获取对应 small bin 中的 chunk 指针
        bin = bin_at(av, idx);
        // 先执行 victim = last(bin)，获取 small bin 的最后一个 chunk
        // 如果 victim = bin ，那说明该 bin 为空。
        // 如果不相等，那么会有两种情况
        if ((victim = last(bin)) != bin) {
            // 第一种情况，small bin 还没有初始化。
            if (victim == 0) /* initialization check */
                // 执行初始化，将 fast bins 中的 chunk 进行合并
                malloc_consolidate(av);
            // 第二种情况，small bin 中存在空闲的 chunk
            else {
                // 获取 small bin 中倒数第二个 chunk 。
                bck = victim->bk;
                // 检查 bck->fd 是不是 victim，防止伪造
                if (__glibc_unlikely(bck->fd != victim)) {
                    errstr = "malloc(): smallbin double linked list corrupted";
                    goto errout;
                }
                // 设置 victim 对应的 inuse 位
                set_inuse_bit_at_offset(victim, nb);
                // 修改 small bin 链表，将 small bin 的最后一个 chunk 取出来
                bin->bk = bck;
                bck->fd = bin;
                // 如果不是 main_arena，设置对应的标志
                if (av != &main_arena) set_non_main_arena(victim);
                // 细致的检查，非调试状态没有作用
                check_malloced_chunk(av, victim, nb);
                // 将申请到的 chunk 转化为对应的 mem 状态
                void *p = chunk2mem(victim);
                // 如果设置了 perturb_type , 则将获取到的chunk初始化为 perturb_type ^ 0xff
                alloc_perturb(p, bytes);
                return p;
            }
        }
    }
```

#### large bin

**当 fast bin、small bin 中的 chunk 都不能满足用户请求 chunk 大小时**，就会考虑是不是 large bin。但是，其实在 large bin 中并没有直接去扫描对应 bin 中的chunk，而是先利用 malloc_consolidate（合并函数） 函数处理 fast bin 中的chunk，将有可能能够合并的 chunk 先进行合并后放到 unsorted bin 中，不能够合并的就直接放到 unsorted bin 中，然后再在下面的大循环中进行相应的处理。

**为什么不直接从相应的 bin 中取出 large chunk 呢？这是ptmalloc 的机制，它会在分配 large chunk 之前对堆中碎片 chunk 进行合并，以便减少堆中的碎片。**

```c
    /*
       If this is a large request, consolidate fastbins before continuing.
       While it might look excessive to kill all fastbins before
       even seeing if there is space available, this avoids
       fragmentation problems normally associated with fastbins.
       Also, in practice, programs tend to have runs of either small or
       large requests, but less often mixtures, so consolidation is not
       invoked all that often in most programs. And the programs that
       it is called frequently in otherwise tend to fragment.
     */

    else {
        // 获取large bin的下标。
        idx = largebin_index(nb);
        // 如果存在fastbin的话，会处理 fastbin 
        if (have_fastchunks(av)) malloc_consolidate(av);
    }
```

#### 大循环

**如果程序执行到了这里，那么说明 与 chunk 大小正好一致的 bin (fast bin， small bin) 中没有 chunk可以直接满足需求 ，但是large chunk 则是在这个大循环中处理**。

该部分是一个大循环，这是为了尝试重新分配 small bin chunk，这是因为我们虽然会首先使用 large bin，top chunk 来尝试满足用户的请求，但是如果没有满足的话，由于我们在上面没有分配成功 small bin，我们并没有对fast bin 中的 chunk 进行合并，所以这里会进行 fast bin chunk 的合并，进而使用一个大循环来尝试再次分配small bin chunk。

先考虑 unsorted bin，再考虑 last remainder ，但是对于 small bin chunk 的请求会有所例外。

在上一步中我们已经将有可能能够合并的 chunk 先进行合并后放到 unsorted bin 中了，这一步我们会遍历unsorted bin，然后将合并后的chunk放到对应的bin（small bin和large bin）中。如果从 unsorted bin 中取出来的 chunk 大小正好合适，就直接使用。这样的操作会循环10000次后退出。

#### large bin

如果请求的 chunk 在 large chunk 范围内，就在对应的 bin 中从小到大进行扫描，找到第一个合适的。

```c
        /*
           If a large request, scan through the chunks of current bin in
           sorted order to find smallest that fits.  Use the skip list for this.
         */
        if (!in_smallbin_range(nb)) {
            bin = bin_at(av, idx);
            /* skip scan if empty or largest chunk is too small */
            // 如果对应的 bin 为空或者其中的chunk最大的也很小，那就跳过
            // first(bin)=bin->fd 表示当前链表中最大的chunk
            if ((victim = first(bin)) != bin &&
                (unsigned long) chunksize_nomask(victim) >=
                    (unsigned long) (nb)) {
                // 反向遍历链表，直到找到第一个不小于所需chunk大小的chunk
                victim = victim->bk_nextsize;
                while (((unsigned long) (size = chunksize(victim)) <
                        (unsigned long) (nb)))
                    victim = victim->bk_nextsize;

                /* Avoid removing the first entry for a size so that the skip
                   list does not have to be rerouted.  */
                // 如果最终取到的chunk不是该bin中的最后一个chunk，并且该chunk与其前面的chunk
                // 的大小相同，那么我们就取其前面的chunk，这样可以避免调整bk_nextsize,fd_nextsize
                //  链表。因为大小相同的chunk只有一个会被串在nextsize链上。
                if (victim != last(bin) &&
                    chunksize_nomask(victim) == chunksize_nomask(victim->fd))
                    victim = victim->fd;
                // 计算分配后剩余的大小
                remainder_size = size - nb;
                // 进行unlink
                unlink(av, victim, bck, fwd);

                /* Exhaust */
                // 剩下的大小不足以当做一个块
                // 很好奇接下来会怎么办？
                if (remainder_size < MINSIZE) {
                    set_inuse_bit_at_offset(victim, size);
                    if (av != &main_arena) set_non_main_arena(victim);
                }
                /* Split */
                //  剩下的大小还可以作为一个chunk，进行分割。
                else {
                    // 获取剩下那部分chunk的指针，称为remainder
                    remainder = chunk_at_offset(victim, nb);
                    /* We cannot assume the unsorted list is empty and therefore
                       have to perform a complete insert here.  */
                    // 插入unsorted bin中
                    bck = unsorted_chunks(av);
                    fwd = bck->fd;
                    // 判断 unsorted bin 是否被破坏。
                    if (__glibc_unlikely(fwd->bk != bck)) {
                        errstr = "malloc(): corrupted unsorted chunks";
                        goto errout;
                    }
                    remainder->bk = bck;
                    remainder->fd = fwd;
                    bck->fd       = remainder;
                    fwd->bk       = remainder;
                    // 如果不处于small bin范围内，就设置对应的字段
                    if (!in_smallbin_range(remainder_size)) {
                        remainder->fd_nextsize = NULL;
                        remainder->bk_nextsize = NULL;
                    }
                    // 设置分配的chunk的标记
                    set_head(victim,
                             nb | PREV_INUSE |
                                 (av != &main_arena ? NON_MAIN_ARENA : 0));

                    // 设置remainder的上一个chunk，即分配出去的chunk的使用状态
                    // 其余的不用管，直接从上面继承下来了
                    set_head(remainder, remainder_size | PREV_INUSE);
                    // 设置remainder的大小
                    set_foot(remainder, remainder_size);
                }
                // 检查
                check_malloced_chunk(av, victim, nb);
                // 转换为mem状态
                void *p = chunk2mem(victim);
                // 如果设置了perturb_type, 则将获取到的chunk初始化为 perturb_type ^ 0xff
                alloc_perturb(p, bytes);
                return p;
            }
        }
```

#### 寻找更大chunk

如果走到了这里，那说明对于用户所需的chunk，不能直接从其对应的合适的bin中获取chunk，所以我们需要来查找比当前 bin 更大的 fast bin ， small bin 或者 large bin。