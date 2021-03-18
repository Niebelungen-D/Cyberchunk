# Glibc-2.20-malloc源码分析

第一次看源码，都算不上分析只是写写自己的理解。不知如何入手，所以记录的内容难免凌乱缺少条理，还请见谅。
## 大小和对齐检查以及转换
### struct malloc_chunk
```c
struct malloc_chunk {
	
 INTERNAL_SIZE_T prev_size; /* Size of previous chunk (if free).  */
 INTERNAL_SIZE_T size; /* Size in bytes, including overhead. */
  
 struct malloc_chunk* fd; /* double links -- used only if free. */
 struct malloc_chunk* bk;

 /* Only used for large blocks: pointer to next larger size.  */
 struct malloc_chunk* fd_nextsize; /* double links -- used only if free. \*/
 struct malloc_chunk* bk_nextsize;
};
```
我省去了大部分的描述，只保留了结构图。
```c
/*
   malloc_chunk details:

    An allocated chunk looks like this:


    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of previous chunk, if allocated            | |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of chunk, in bytes                       |M|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             User data starts here...                          .
	    .                                                               .
	    .             (malloc_usable_size() bytes)                      .
	    .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of chunk                                     |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


    Free chunks are stored in circular doubly-linked lists, and look like this:

    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of previous chunk                            |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `head:' |             Size of chunk, in bytes                         |P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Forward pointer to next chunk in list             |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Back pointer to previous chunk in list            |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Unused space (may be 0 bytes long)                .
	    .                                                               .
	    .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `foot:' |             Size of chunk, in bytes                           |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
```

- **prev_size**：如果前一个chunk是空闲的，该域表示前一个chunk的大小，如果前一个chunk不空闲，该域无意义。**注意：这里的前一个指的是存储物理相邻地址较低的那一个chunk。**
- **size**：该 chunk 的大小，大小必须是 2 * SIZE_SZ 的整数倍。如果申请的内存大小不是 2 * SIZE_SZ 的整数倍，会被转换满足大小的最小的 2 * SIZE_SZ 的倍数。32 位系统中，SIZE_SZ 是 4；64 位系统中，SIZE_SZ 是 8。 该字段的低三个比特位对 chunk 的大小没有影响，它们从高到低分别表示：
  - A: NON_MAIN_ARENA，记录当前 chunk 是否不属于主线程（分配区/arena），1表示不属于，0表示属于。
  - M: IS_MAPPED，他表示当前chunk是从哪个内存区域获得的虚拟内存。M为1表示该chunk是从mmap映射区域分配的，否则是从heap区域分配的。
  - P: PREV_INUSE，记录前一个 chunk 块是否被分配。一般来说，堆中第一个被分配的内存块的 size 字段的P位都会被设置为1，以便于防止访问前面的非法内存。当一个 chunk 的 size 的 P 位为 0 时，我们能通过 prev_size 字段来获取上一个 chunk 的大小以及地址。这也方便进行空闲chunk之间的合并。
- **fd，bk**： chunk 处于分配状态时，从 fd 字段开始是用户的数据。chunk 空闲时，会被添加到对应的空闲管理链表中，其字段的含义如下
  - fd 指向下一个（非物理相邻）空闲的 chunk
  - bk 指向上一个（非物理相邻）空闲的 chunk
- **fd_nextsize， bk_nextsize**：也是只有 chunk 空闲的时候才使用，不过其用于较大的 chunk（large chunk）。
  - fd_nextsize指向下一个比当前chunk size小的第一个空闲chunk，不包含 bin 的头指针。
  - bk_nextszie指向上一个比当前chunk size大的第一个空闲chunk，不包含 bin 的头指针。
  - large bins中的空闲chunk是按照大小排序的。**这样做可以避免在寻找合适chunk 时挨个遍历。**
 
**注意：fd所指向的是从表头到表尾方向，bk则是反过来。这样理解下一个和上一个的含义。**
一个已经分配的 chunk 的样子如下。**我们称前两个字段称为 chunk header，后面的部分称为 user data。每次 malloc 申请得到的内存指针，其实指向 user data 的起始处。**
当一个 chunk 处于使用状态时，它的下一个 chunk 的 prev_size 域无效，所以下一个 chunk 的该部分也可以被当前chunk使用。**这就是chunk中的空间复用。**
```c
#define chunk2mem(p)   ((void*)((char*)(p) + 2*SIZE_SZ))
#define mem2chunk(mem) ((mchunkptr)((char*)(mem) - 2*SIZE_SZ))

/* The smallest possible chunk */
#define MIN_CHUNK_SIZE        (offsetof(struct malloc_chunk, fd_nextsize))

/* The smallest size we can malloc is an aligned minimal chunk */

#define MINSIZE  \
  (unsigned long)(((MIN_CHUNK_SIZE+MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK))

/* Check if m has acceptable alignment */

#define aligned_OK(m)  (((unsigned long)(m) & MALLOC_ALIGN_MASK) == 0)

#define misaligned_chunk(p) \
  ((uintptr_t)(MALLOC_ALIGNMENT == 2 * SIZE_SZ ? (p) : chunk2mem (p)) \
   & MALLOC_ALIGN_MASK)
```
每次`malloc`得到的是`mem`指针，真正指向整个chunk的是`chunk`指针，可以通过上面两个宏进行转换。
`MIN_CHUNK_SIZE `定义了最小chunk的至少要包含`fd`与`bk`指针。
`MINSIZE`定义了最小的分配的内存大小，是对`MIN_CHUNK_SIZE`进行了2*`SIZE_SZ`对齐，地址对齐后与`MIN_CHUNK_SIZE`的大小仍然是一样的。
宏`aligned_OK`和`misaligned_chunk(p)`用于校验地址是否是按2*`SIZE_SZ`对齐的。
```c
/*
   Check if a request is so large that it would wrap around zero when
   padded and aligned. To simplify some other code, the bound is made
   low enough so that adding MINSIZE will also not wrap around zero.
 */

#define REQUEST_OUT_OF_RANGE(req)                                 \
  ((unsigned long) (req) >=						      \
   (unsigned long) (INTERNAL_SIZE_T) (-2 * MINSIZE))

/* pad request bytes into a usable size -- internal version */

#define request2size(req)                                         \
  (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)  ?             \
   MINSIZE :                                                      \
   ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

/*  Same, except also perform argument check */

#define checked_request2size(req, sz)                             \
  if (REQUEST_OUT_OF_RANGE (req)) {					      \
      __set_errno (ENOMEM);						      \
      return 0;								      \
    }									      \
  (sz) = request2size (req);
```
用户申请的内存大小需要转化为真实chunk大小，在转换的时候加上了`SIZE_SZ`大小，这是因为chunk中的空间复用。所以实际一个使用中chunk size(64位下)的计算公式为`in_use_size = (req +16 -8) align to 8B`
最后，因为空闲的chunk和使用中的chunk使用的是同一块空间。所以肯定要取其中最大者作为实际的分配空间。即最终的分配空间`chunk_size = max(in_use_size, 32)`。
## 物理chunk操作
```c
/* size field is or'ed with PREV_INUSE when previous adjacent chunk in use */
#define PREV_INUSE 0x1

/* extract inuse bit of previous chunk */
#define prev_inuse(p)       ((p)->size & PREV_INUSE)


/* size field is or'ed with IS_MMAPPED if the chunk was obtained with mmap() */
#define IS_MMAPPED 0x2

/* check for mmap()'ed chunk */
#define chunk_is_mmapped(p) ((p)->size & IS_MMAPPED)


/* size field is or'ed with NON_MAIN_ARENA if the chunk was obtained
   from a non-main arena.  This is only set immediately before handing
   the chunk to the user, if necessary.  */
#define NON_MAIN_ARENA 0x4

/* check for chunk from non-main arena */
#define chunk_non_main_arena(p) ((p)->size & NON_MAIN_ARENA)
```
参考上一节
```c
/*
   Bits to mask off when extracting size

   Note: IS_MMAPPED is intentionally not masked off from size field in
   macros for which mmapped chunks should never be seen. This should
   cause helpful core dumps to occur if it is tried by accident by
   people extending or adapting this malloc.
 */
#define SIZE_BITS (PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)

/* Get size, ignoring use bits */
#define chunksize(p)         ((p)->size & ~(SIZE_BITS))


/* Ptr to next physical malloc_chunk. */
#define next_chunk(p) ((mchunkptr) (((char *) (p)) + ((p)->size & ~SIZE_BITS)))

/* Ptr to previous physical malloc_chunk */
#define prev_chunk(p) ((mchunkptr) (((char *) (p)) - ((p)->prev_size)))

/* Treat space at ptr + offset as a chunk */
#define chunk_at_offset(p, s)  ((mchunkptr) (((char *) (p)) + (s)))
```
如果前一个邻接chunk块空闲，那么当前chunk块结构体内的`prev_size`字段记录的是前一个邻接chunk块的大小。这就是由当前chunk指针获得前一个空闲chunk地址的依据。
如果前一个邻接chunk在使用中，则当前chunk的`prev_size`的空间被前一个chunk借用中，其中的值是前一个chunk的内存内容，对当前chunk没有任何意义。
字段`size`记录了本chunk的大小，无论下一个chunk是空闲状态或是被使用状态，都可以通过本chunk的地址加上本chunk的大小，得到下一个chunk的地址，由于size的低3个bit记录了控制信息，需要屏蔽掉这些控制信息，取出实际的size在进行计算下一个chunk地址，这是`next_chunk(p)`的实现原理。`prev_chunk`同理。
宏`chunksize(p)`用于获得chunk的实际大小，需要屏蔽掉size中的控制信息。
宏`chunk_at_offset(p, s)`将p+s的地址强制看作一个chunk。
```c
/* extract p's inuse bit */
#define inuse(p)							      \
  ((((mchunkptr) (((char *) (p)) + ((p)->size & ~SIZE_BITS)))->size) & PREV_INUSE)

/* set/clear chunk as being inuse without otherwise disturbing */
#define set_inuse(p)							      \
  ((mchunkptr) (((char *) (p)) + ((p)->size & ~SIZE_BITS)))->size |= PREV_INUSE

#define clear_inuse(p)							      \
  ((mchunkptr) (((char *) (p)) + ((p)->size & ~SIZE_BITS)))->size &= ~(PREV_INUSE)


/* check/set/clear inuse bits in known places */
#define inuse_bit_at_offset(p, s)					      \
  (((mchunkptr) (((char *) (p)) + (s)))->size & PREV_INUSE)

#define set_inuse_bit_at_offset(p, s)					      \
  (((mchunkptr) (((char *) (p)) + (s)))->size |= PREV_INUSE)

#define clear_inuse_bit_at_offset(p, s)					      \
  (((mchunkptr) (((char *) (p)) + (s)))->size &= ~(PREV_INUSE))


/* Set size at head, without disturbing its use bit */
#define set_head_size(p, s)  ((p)->size = (((p)->size & SIZE_BITS) | (s)))

/* Set size/use field */
#define set_head(p, s)       ((p)->size = (s))

/* Set size at footer (only when chunk is not in use) */
#define set_foot(p, s)       (((mchunkptr) ((char *) (p) + (s)))->prev_size = (s))
```
chunk头的检查与设置操作。
## 内部数据结构
```c
/*
   Bins

    An array of bin headers for free chunks. Each bin is doubly
    linked.  The bins are approximately proportionally (log) spaced.
    There are a lot of these bins (128). This may look excessive, but
    works very well in practice.  Most bins hold sizes that are
    unusual as malloc request sizes, but are more usual for fragments
    and consolidated sets of chunks, which is what these bins hold, so
    they can be found quickly.  All procedures maintain the invariant
    that no consolidated chunk physically borders another one, so each
    chunk in a list is known to be preceeded and followed by either
    inuse chunks or the ends of memory.

    Chunks in bins are kept in size order, with ties going to the
    approximately least recently used chunk. Ordering isn't needed
    for the small bins, which all contain the same-sized chunks, but
    facilitates best-fit allocation for larger chunks. These lists
    are just sequential. Keeping them in order almost never requires
    enough traversal to warrant using fancier ordered data
    structures.

    Chunks of the same size are linked with the most
    recently freed at the front, and allocations are taken from the
    back.  This results in LRU (FIFO) allocation order, which tends
    to give each chunk an equal opportunity to be consolidated with
    adjacent freed chunks, resulting in larger free chunks and less
    fragmentation.

    To simplify use in double-linked lists, each bin header acts
    as a malloc_chunk. This avoids special-casing for headers.
    But to conserve space and improve locality, we allocate
    only the fd/bk pointers of bins, and then use repositioning tricks
    to treat these as the fields of a malloc_chunk*.
 */
```
对于空闲块的管理ptmalloc使用了**bins**，根据size的大小将其放入不同类型的bin中，每种bin内部又分为不同的bin对空闲块进行更细化的管理。每个bin都是由双向链表进行组织维护，并且每个bin的头部都充当一个`malloc_chunk`结构体，在bins数组中只为每个bin预留了两个指针的内存空间用于存放bin的链表头的fb和bk指针。。
除了`small bin`外其余bin中的chunk都以大小顺序排列。
```c
typedef struct malloc_chunk *mbinptr;

/* addressing -- note that bin_at(0) does not exist */
#define bin_at(m, i) \
  (mbinptr) (((char *) &((m)->bins[((i) - 1) * 2]))			      \
             - offsetof (struct malloc_chunk, fd))

/* analog of ++bin */
#define next_bin(b)  ((mbinptr) ((char *) (b) + (sizeof (mchunkptr) << 1)))

/* Reminders about list directionality within bins */
#define first(b)     ((b)->fd)
#define last(b)      ((b)->bk)
```
`bin_at(m,i)`用来通过index来获取bin的链表头，m 指的是分配区，i 是索引。
宏`next_bin(b)`用于获得下一个bin的地址，根据前面的分析，我们知道只需要将当前bin的地址向后移动两个指针的长度就得到下一个bin的链表头地址。
bin采用双向链表，表头的fd指向的第一个可用chunk，bk指向链表中最后一个。`first(b)`和`last(b)`用来获取一个bin中第一和最后一个可用chunk。
### unlink
```c
/* Take a chunk off a bin list */
#define unlink(P, BK, FD) {                                            \
    FD = P->fd;								      \
    BK = P->bk;								      \
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))		      \
      malloc_printerr (check_action, "corrupted double-linked list", P);      \
    else {								      \
        FD->bk = BK;							      \
        BK->fd = FD;							      \
        if (!in_smallbin_range (P->size)				      \
            && __builtin_expect (P->fd_nextsize != NULL, 0)) {		      \
            assert (P->fd_nextsize->bk_nextsize == P);			      \
            assert (P->bk_nextsize->fd_nextsize == P);			      \
            if (FD->fd_nextsize == NULL) {				      \
                if (P->fd_nextsize == P)				      \
                  FD->fd_nextsize = FD->bk_nextsize = FD;		      \
                else {							      \
                    FD->fd_nextsize = P->fd_nextsize;			      \
                    FD->bk_nextsize = P->bk_nextsize;			      \
                    P->fd_nextsize->bk_nextsize = FD;			      \
                    P->bk_nextsize->fd_nextsize = FD;			      \
                  }							      \
              } else {							      \
                P->fd_nextsize->bk_nextsize = P->bk_nextsize;		      \
                P->bk_nextsize->fd_nextsize = P->fd_nextsize;		      \
              }								      \
          }								      \
      }									      \
}
```
经典`unlink`用来从链表中取出一个chunk。
**注意：large bins中的空闲chunk可能处于两个双向循环链表中，`unlink`时需要从两个链表中都删除。**
所以，从这里可以看出在`large bin`中chunk是用`fd_nextsize`和`bk_nextsize`来链接的。
### large bin&small bin
```c
/*
   Indexing

    Bins for sizes < 512 bytes contain chunks of all the same size, spaced
    8 bytes apart. Larger bins are approximately logarithmically spaced:

    64 bins of size       8
    32 bins of size      64
    16 bins of size     512
     8 bins of size    4096
     4 bins of size   32768
     2 bins of size  262144
     1 bin  of size what's left

    There is actually a little bit of slop in the numbers in bin_index
    for the sake of speed. This makes no difference elsewhere.

    The bins top out around 1MB because we expect to service large
    requests via mmap.

    Bin 0 does not exist.  Bin 1 is the unordered list; if that would be
    a valid chunk size the small bins are bumped up one.
 */
```
sizes小于512 bytes的chunk属于`small bin`的管理范围，表中列出了bin之间的公差，单位byte。bin 0不存在，bin 1是`unsorted bin`的链表头。
```c
#define NBINS             128
#define NSMALLBINS         64
#define SMALLBIN_WIDTH    MALLOC_ALIGNMENT
#define SMALLBIN_CORRECTION (MALLOC_ALIGNMENT > 2 * SIZE_SZ)
#define MIN_LARGE_SIZE    ((NSMALLBINS - SMALLBIN_CORRECTION) * SMALLBIN_WIDTH)

#define in_smallbin_range(sz)  \
  ((unsigned long) (sz) < (unsigned long) MIN_LARGE_SIZE)

#define smallbin_index(sz) \
  ((SMALLBIN_WIDTH == 16 ? (((unsigned) (sz)) >> 4) : (((unsigned) (sz)) >> 3))\
   + SMALLBIN_CORRECTION)

#define largebin_index_32(sz)                                                \
  (((((unsigned long) (sz)) >> 6) <= 38) ?  56 + (((unsigned long) (sz)) >> 6) :\
   ((((unsigned long) (sz)) >> 9) <= 20) ?  91 + (((unsigned long) (sz)) >> 9) :\
   ((((unsigned long) (sz)) >> 12) <= 10) ? 110 + (((unsigned long) (sz)) >> 12) :\
   ((((unsigned long) (sz)) >> 15) <= 4) ? 119 + (((unsigned long) (sz)) >> 15) :\
   ((((unsigned long) (sz)) >> 18) <= 2) ? 124 + (((unsigned long) (sz)) >> 18) :\
   126)

#define largebin_index_32_big(sz)                                            \
  (((((unsigned long) (sz)) >> 6) <= 45) ?  49 + (((unsigned long) (sz)) >> 6) :\
   ((((unsigned long) (sz)) >> 9) <= 20) ?  91 + (((unsigned long) (sz)) >> 9) :\
   ((((unsigned long) (sz)) >> 12) <= 10) ? 110 + (((unsigned long) (sz)) >> 12) :\
   ((((unsigned long) (sz)) >> 15) <= 4) ? 119 + (((unsigned long) (sz)) >> 15) :\
   ((((unsigned long) (sz)) >> 18) <= 2) ? 124 + (((unsigned long) (sz)) >> 18) :\
   126)

// XXX It remains to be seen whether it is good to keep the widths of
// XXX the buckets the same or whether it should be scaled by a factor
// XXX of two as well.
#define largebin_index_64(sz)                                                \
  (((((unsigned long) (sz)) >> 6) <= 48) ?  48 + (((unsigned long) (sz)) >> 6) :\
   ((((unsigned long) (sz)) >> 9) <= 20) ?  91 + (((unsigned long) (sz)) >> 9) :\
   ((((unsigned long) (sz)) >> 12) <= 10) ? 110 + (((unsigned long) (sz)) >> 12) :\
   ((((unsigned long) (sz)) >> 15) <= 4) ? 119 + (((unsigned long) (sz)) >> 15) :\
   ((((unsigned long) (sz)) >> 18) <= 2) ? 124 + (((unsigned long) (sz)) >> 18) :\
   126)

#define largebin_index(sz) \
  (SIZE_SZ == 8 ? largebin_index_64 (sz)                                     \
   : MALLOC_ALIGNMENT == 16 ? largebin_index_32_big (sz)                     \
   : largebin_index_32 (sz))

#define bin_index(sz) \
  ((in_smallbin_range (sz)) ? smallbin_index (sz) : largebin_index (sz))
 ```
所有的bin头可视为一个数组，总共有128bin，但是实际上因为bin 0和bin 127不存在，所以只有126个bin，bin 1为`unsorted bin`，bin 2-63为`small bin`，其余都是`large bin`。所以`small bin`为62个，`large bin`为63个。

### unsorted bin
```c
/*
   Unsorted chunks

    All remainders from chunk splits, as well as all returned chunks,
    are first placed in the "unsorted" bin. They are then placed
    in regular bins after malloc gives them ONE chance to be used before
    binning. So, basically, the unsorted_chunks list acts as a queue,
    with chunks being placed on it in free (and malloc_consolidate),
    and taken off (to be either used or placed in bins) in malloc.

    The NON_MAIN_ARENA flag is never set for unsorted chunks, so it
    does not have to be taken into account in size comparisons.
 */

/* The otherwise unindexable 1-bin is used to hold unsorted chunks. */
#define unsorted_chunks(M)          (bin_at (M, 1))
```
bin 1为`unsorted bin`的链表头，chunk分割后剩余的部分会首先被放入`unsorted bin`，并且不排序。若`unsorted bin`中的chunk不能满足用户的请求，那么就会将其中的chunk进行合并，然后分配到各自属于的bin中。所以`unsorted bin`扮演一个队列的角色。
### Top
```c
/*
   Top

    The top-most available chunk (i.e., the one bordering the end of
    available memory) is treated specially. It is never included in
    any bin, is used only if no other chunk is available, and is
    released back to the system if it is very large (see
    M_TRIM_THRESHOLD).  Because top initially
    points to its own bin with initial zero size, thus forcing
    extension on the first malloc request, we avoid having any special
    code in malloc to check whether it even exists yet. But we still
    need to do so when getting memory from system, so we make
    initial_top treat the bin as a legal but unusable chunk during the
    interval between initialization and the first call to
    sysmalloc. (This is somewhat delicate, since it relies on
    the 2 preceding words to be zero during this interval as well.)
 */

/* Conveniently, the unsorted bin can be used as dummy top on first call */
#define initial_top(M)              (unsorted_chunks (M))
```
`top chunk`是特殊的，它不属于任何bin，当任何bin都无法满足要求时才会对其进行操作。当它很大时会释放回操作系统。根据描述，为了不再添加特殊的代码来检查`top chunk`，所以将其初始化为一个合法的`unsorted bin`。
### binmap
```c
/*
   Binmap

    To help compensate for the large number of bins, a one-level index
    structure is used for bin-by-bin searching.  `binmap' is a
    bitvector recording whether bins are definitely empty so they can
    be skipped over during during traversals.  The bits are NOT always
    cleared as soon as bins are empty, but instead only
    when they are noticed to be empty during traversal in malloc.
 */

/* Conservatively use 32 bits per map word, even if on 64bit system */
#define BINMAPSHIFT      5
#define BITSPERMAP       (1U << BINMAPSHIFT)
#define BINMAPSIZE       (NBINS / BITSPERMAP)

#define idx2block(i)     ((i) >> BINMAPSHIFT)
#define idx2bit(i)       ((1U << ((i) & ((1U << BINMAPSHIFT) - 1))))

#define mark_bin(m, i)    ((m)->binmap[idx2block (i)] |= idx2bit (i))
#define unmark_bin(m, i)  ((m)->binmap[idx2block (i)] &= ~(idx2bit (i)))
#define get_binmap(m, i)  ((m)->binmap[idx2block (i)] & idx2bit (i))
```
`binmap`用来简化判断一个bin是否为空，`binmap`中的bit位是在malloc时进行设置的。
### fast bin
```c 
/*
   Fastbins

    An array of lists holding recently freed small chunks.  Fastbins
    are not doubly linked.  It is faster to single-link them, and
    since chunks are never removed from the middles of these lists,
    double linking is not necessary. Also, unlike regular bins, they
    are not even processed in FIFO order (they use faster LIFO) since
    ordering doesn't much matter in the transient contexts in which
    fastbins are normally used.

    Chunks in fastbins keep their inuse bit set, so they cannot
    be consolidated with other free chunks. malloc_consolidate
    releases all chunks in fastbins and consolidates them with
    other free chunks.
 */

typedef struct malloc_chunk *mfastbinptr;
#define fastbin(ar_ptr, idx) ((ar_ptr)->fastbinsY[idx])

/* offset 2 to use otherwise unindexable first 2 bins */
#define fastbin_index(sz) \
  ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
```
`fast bin`用来保存最近free的`small chunk`，对于SIZE_SZ为4B的平台，小于64B的chunk分配请求，对于SIZE_SZ为8B的平台，小于128B的chunk分配请求，会首先在`fast bin`中进行`best fit`。
`fast bin`使用单链表进行维护，即仅使用`fd`域，其可以视为LIFO的链栈。并且其`in_use`位不会被置零，保证其中的chunk不会被合并。
```c
/* The maximum fastbin request size we support */
#define MAX_FAST_SIZE     (80 * SIZE_SZ / 4)

#define NFASTBINS  (fastbin_index (request2size (MAX_FAST_SIZE)) + 1)
/*
   FASTBIN_CONSOLIDATION_THRESHOLD is the size of a chunk in free()
   that triggers automatic consolidation of possibly-surrounding
   fastbin chunks. This is a heuristic, so the exact value should not
   matter too much. It is defined at half the default trim threshold as a
   compromise heuristic to only attempt consolidation if it is likely
   to lead to trimming. However, it is not dynamically tunable, since
   consolidation reduces fragmentation surrounding large chunks even
   if trimming is not used.
 */

#define FASTBIN_CONSOLIDATION_THRESHOLD  (65536UL)
```
根据`SIZE_SZ`的不同大小，定义`MAX_FAST_SIZE`为80B或是160B，`fast bins`数组的大小`NFASTBINS`为10，即`fast bins`共有十个bin，公差为8B。
`FASTBIN_CONSOLIDATION_THRESHOLD`为64k，当每次释放的chunk与该chunk相邻的空闲chunk合并后的大小大于64k时，就认为内存碎片可能比较多了，就需要把`fast bins`中的所有chunk都进行合并，以减少内存碎片对系统的影响。

```c
#ifndef DEFAULT_MXFAST
#define DEFAULT_MXFAST     (64 * SIZE_SZ / 4)
#endif
/*
   Set value of max_fast.
   Use impossibly small value if 0.
   Precondition: there are no existing fastbin chunks.
   Setting the value clears fastchunk bit but preserves noncontiguous bit.
 */

#define set_max_fast(s) \
  global_max_fast = (((s) == 0)						      \
                     ? SMALLBIN_WIDTH : ((s + SIZE_SZ) & ~MALLOC_ALIGN_MASK))
#define get_max_fast() global_max_fast
```
`set_max_fast(s)`用来设置默认的`fast bins`中最大的chunk，在free时，大小小于默认值的chunk都会被加入到`fast bins`中。
## 内部状态表示与初始化
### malloc_state
```c
struct malloc_state
{
  /* Serialize access.  */
  mutex_t mutex;

  /* Flags (formerly in max_fast).  */
  int flags;

  /* Fastbins */
  mfastbinptr fastbinsY[NFASTBINS];

  /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr top;

  /* The remainder from the most recent split of a small request */
  mchunkptr last_remainder;

  /* Normal bins packed as described above */
  mchunkptr bins[NBINS * 2 - 2];

  /* Bitmap of bins */
  unsigned int binmap[BINMAPSIZE];

  /* Linked list */
  struct malloc_state *next;

  /* Linked list for free arenas.  */
  struct malloc_state *next_free;

  /* Memory allocated from the system in this arena.  */
  INTERNAL_SIZE_T system_mem;
  INTERNAL_SIZE_T max_system_mem;
};
```
ptmalloc使用`malloc_state`来管理分配区。`mutex`用于串行化访问，当有多个线程访问同一个分配区时，第一个获得这个`mutex`的线程将使用该分配区分配内存，分配完成后，释放该分配区的`mutex`，以便其它线程使用该分配区。可以理解为锁，当正在使用的线程加锁后，其他线程就无法访问，锁被释放后才可以。
`Flags`(之前记录在`max_fast`中)记录了分配区的一些标志：
```c
/*
   Since the lowest 2 bits in max_fast don't matter in size comparisons,
   they are used as flags.
 */

/*
   FASTCHUNKS_BIT held in max_fast indicates that there are probably
   some fastbin chunks. It is set true on entering a chunk into any
   fastbin, and cleared only in malloc_consolidate.

   The truth value is inverted so that have_fastchunks will be true
   upon startup (since statics are zero-filled), simplifying
   initialization checks.
 */

#define FASTCHUNKS_BIT        (1U)

#define have_fastchunks(M)     (((M)->flags & FASTCHUNKS_BIT) == 0)
#define clear_fastchunks(M)    catomic_or (&(M)->flags, FASTCHUNKS_BIT)
#define set_fastchunks(M)      catomic_and (&(M)->flags, ~FASTCHUNKS_BIT)

/*
   NONCONTIGUOUS_BIT indicates that MORECORE does not return contiguous
   regions.  Otherwise, contiguity is exploited in merging together,
   when possible, results from consecutive MORECORE calls.

   The initial value comes from MORECORE_CONTIGUOUS, but is
   changed dynamically if mmap is ever used as an sbrk substitute.
 */

#define NONCONTIGUOUS_BIT     (2U)

#define contiguous(M)          (((M)->flags & NONCONTIGUOUS_BIT) == 0)
#define noncontiguous(M)       (((M)->flags & NONCONTIGUOUS_BIT) != 0)
#define set_noncontiguous(M)   ((M)->flags |= NONCONTIGUOUS_BIT)
#define set_contiguous(M)      ((M)->flags &= ~NONCONTIGUOUS_BIT)
```
`max_fast`中的最后两位用作控制信息，bit0用来表示`fast bins`是否为空。如果bit0为0，表示分配区中有fast chunk，如果为1表示没有fast chunk，初始化完成后的`malloc_state`实例中，flags值为0，表示该分配区中有fast chunk，但实际上没有，试图从fast bins中分配chunk都会返回NULL，在第一次调用函数`malloc_consolidate()`对fast bins进行chunk合并时，如果max_fast大于0，会调用`clear_fastchunks`宏，标志该分配区中已经没有fast chunk，因为函数`malloc_consolidate()`会合并所有的fast bins中的chunk。`clear_fastchunks`宏只会在函数`malloc_consolidate()`中调用。当有fast chunk加入fast bins时，就是调用`set_fastchunks`宏标识分配区的fast bins中存在fast chunk。
`Flags`的bit1如果为0，表示`MORCORE`返回连续虚拟地址空间，bit1为1，表示`MORCORE`返回非连续虚拟地址空间，对于主分配区，`MORECORE`其实为`sbr()`，默认返回连续虚拟地址空间，对于非主分配区，使用`mmap()`分配大块虚拟内存，然后进行切分来模拟主分配区的行为，而默认情况下mmap映射区域是不保证虚拟地址空间连续的，所以非主分配区默认分配非连续虚拟地址空间。
`fastbinsY`是有十个元素的数组，存放了`fastbin`的链表头。
`top`指向了该分配区的`top chunk`。
`last_remainde`r是一个chunk指针，分配区上次分配small chunk时，从一个chunk中分裂出一个small chunk返回给用户，分裂后的剩余部分形成一个chunk，`last_remainder`就是指向的这个chunk。
`bins`是当前分配区存储`unstored bin`，`small bins`和`large bins`的chunk链表头的数组。
**注意：计算出来数组有254个元素，之前bin头被描述为一个`malloc chunk`但是要链接chunk，我们只需要`fd`和`bk`，对于`large bin`来说只需要`fd_nextsize`和`bk_nextsize`，所以只要为指针申请空间即可，其余域都是被复用的**
`binmap`字段是一个int数组，共128位。ptmalloc用一个bit来标识该bit对应的bin中是否包含空闲chunk。
`next`字段用于将分配区以单向链表链接起来。
`next_free`字段空闲的分配区链接在单向链表中，只有在定义了PER_THREAD的情况下才定义该字段。
`system_mem`字段记录了当前分配区已经分配的内存大小。
`max_system_mem`记录了当前分配区最大能分配的内存大小。
### malloc_par
```c
struct malloc_par
{
  /* Tunable parameters */
  unsigned long trim_threshold;
  INTERNAL_SIZE_T top_pad;
  INTERNAL_SIZE_T mmap_threshold;
  INTERNAL_SIZE_T arena_test;
  INTERNAL_SIZE_T arena_max;

  /* Memory map support */
  int n_mmaps;
  int n_mmaps_max;
  int max_n_mmaps;
  /* the mmap_threshold is dynamic, until the user sets
     it manually, at which point we need to disable any
     dynamic behavior. */
  int no_dyn_threshold;

  /* Statistics */
  INTERNAL_SIZE_T mmapped_mem;
  /*INTERNAL_SIZE_T  sbrked_mem;*/
  /*INTERNAL_SIZE_T  max_sbrked_mem;*/
  INTERNAL_SIZE_T max_mmapped_mem;
  INTERNAL_SIZE_T max_total_mem;  /* only kept for NO_THREADS */

  /* First address handed out by MORECORE/sbrk.  */
  char *sbrk_base;
};
```
`malloc_par`记录了一些参数和统计信息，`trim_threshold`字段表示收缩阈值，默认为128KB，当每个分配区的`top chunk`大小大于这个阈值时，在一定的条件下，调用free时会收缩内存，减小`top chunk`的大小。由于`mmap`分配阈值的动态调整，在`free`时可能将收缩阈值修改为`mmap`分配阈值的2倍，在64位系统上，`mmap`分配阈值最大值为32MB，所以收缩阈值的最大值为64MB，在32位系统上，`mmap`分配阈值最大值为512KB，所以收缩阈值的最大值为1MB。收缩阈值可以通过函数`mallopt()`进行设置。
`top_pad`：表示在分配内存时是否添加额外的pad，默认该字段为0。
`mmap_threshold`：表示`mmap`分配阈值，默认值为128KB，在32位系统上最大值为512KB，64位系统上的最大值为32MB，由于默认开启`mmap`分配阈值动态调整，该字段的值会动态修改，但不会超过最大值。
`arena_test`和`arena_max`用于`PER_THREAD`优化，在32位系统上`arena_test`默认值为2，64位系统上的默认值为8，当每个进程的分配区数量小于等于`arena_test`时，不会重用已有的分配区。为了限制分配区的总数，用`arena_max`来保存分配区的最大数量，当系统中的分配区数量达到`arena_max`，就不会再创建新的分配区，只会重用已有的分配区。这两个字段都可以使用`mallopt()`函数设置。
`n_mmaps`：表示当前进程使用`mmap()`函数分配的内存块的个数。
`n_mmaps_max`：表示进程使用`mmap()`函数分配的内存块的最大数量，默认值为65536，可以使用`mallopt()`函数修改。
`max_n_mmaps`：表示当前进程使用`mmap()`函数分配的内存块的数量的最大值，有关系`n_mmaps` <= `max_n_mmaps`成立。这个字段是由于`mstats()`函数输出统计需要这个字段。
`no_dyn_threshold`：表示是否开启`mmap`分配阈值动态调整机制，默认值为0，也就是默认开启mmap分配阈值动态调整机制。
`pagesize`：表示系统的页大小，默认为4KB。
`mmapped_mem`和`max_mmapped_mem`都用于统计mmap分配的内存大小，一般情况下两个字段的值相等，`max_mmapped_mem`用于`mstats()`函数。
`max_total_mem`：在单线程情况下用于统计进程分配的内存总数。
`sbrk_base`：表示堆的起始地址。
```c
/* There are several instances of this struct ("arenas") in this
   malloc.  If you are adapting this malloc in a way that does NOT use
   a static or mmapped malloc_state, you MUST explicitly zero-fill it
   before using. This malloc relies on the property that malloc_state
   is initialized to all zeroes (as is true of C statics).  */

static struct malloc_state main_arena =
{
  .mutex = MUTEX_INITIALIZER,
  .next = &main_arena
};

/* There is only one instance of the malloc parameters.  */

static struct malloc_par mp_ =
{
  .top_pad = DEFAULT_TOP_PAD,
  .n_mmaps_max = DEFAULT_MMAP_MAX,
  .mmap_threshold = DEFAULT_MMAP_THRESHOLD,
  .trim_threshold = DEFAULT_TRIM_THRESHOLD,
#define NARENAS_FROM_NCORES(n) ((n) * (sizeof (long) == 4 ? 2 : 8))
  .arena_test = NARENAS_FROM_NCORES (1)
};


/*  Non public mallopt parameters.  */
#define M_ARENA_TEST -7
#define M_ARENA_MAX  -8


/* Maximum size of memory handled in fastbins.  */
static INTERNAL_SIZE_T global_max_fast;
```
`main_arena`表示主分配区，任何进程有且仅有一个全局的主分配区，`mp_`是全局唯一的一个`malloc_par`实例，用于管理参数和统计信息，`global_max_fast`全局变量表示fast bins中最大的chunk大小。
### malloc_init_state
```c
/*
   Initialize a malloc_state struct.

   This is called only from within malloc_consolidate, which needs
   be called in the same contexts anyway.  It is never called directly
   outside of malloc_consolidate because some optimizing compilers try
   to inline it at all call points, which turns out not to be an
   optimization at all. (Inlining it in malloc_consolidate is fine though.)
 */

static void
malloc_init_state (mstate av)
{
  int i;
  mbinptr bin;

  /* Establish circular links for normal bins */
  for (i = 1; i < NBINS; ++i)
    {
      bin = bin_at (av, i);
      bin->fd = bin->bk = bin;
    }

#if MORECORE_CONTIGUOUS
  if (av != &main_arena)
#endif
  set_noncontiguous (av);
  if (av == &main_arena)
    set_max_fast (DEFAULT_MXFAST);
  av->flags |= FASTCHUNKS_BIT;

  av->top = initial_top (av);
}
```
`malloc_init_state`将分配区中的bin链表头都指向自身。在初始化主分配区时，av默认为0，即默认分配连续的空间(也仅有主分配区才能这样做)，对于非主分配区，需要设置分配非连续的空间。如果初始化的是主分配区，需要设置`fast bins`中最大chunk大小，由于主分配区只有一个，并且一定是最先初始化，这就保证了对全局变量`global_max_fast`只初始化了一次，只要该全局变量的值非0，也就意味着主分配区初始化了。最后初始化`top chunk`。
### __libc_mallopt()
```c
int
__libc_mallopt (int param_number, int value)
{
  mstate av = &main_arena;
  int res = 1;

  if (__malloc_initialized < 0)
    ptmalloc_init ();
  (void) mutex_lock (&av->mutex);
  /* Ensure initialization/consolidation */
  malloc_consolidate (av);

  LIBC_PROBE (memory_mallopt, 2, param_number, value);

  switch (param_number)
    {
    case M_MXFAST:
      if (value >= 0 && value <= MAX_FAST_SIZE)
        {
          LIBC_PROBE (memory_mallopt_mxfast, 2, value, get_max_fast ());
          set_max_fast (value);
        }
      else
        res = 0;
      break;

    case M_TRIM_THRESHOLD:
      LIBC_PROBE (memory_mallopt_trim_threshold, 3, value,
                  mp_.trim_threshold, mp_.no_dyn_threshold);
      mp_.trim_threshold = value;
      mp_.no_dyn_threshold = 1;
      break;

    case M_TOP_PAD:
      LIBC_PROBE (memory_mallopt_top_pad, 3, value,
                  mp_.top_pad, mp_.no_dyn_threshold);
      mp_.top_pad = value;
      mp_.no_dyn_threshold = 1;
      break;

    case M_MMAP_THRESHOLD:
      /* Forbid setting the threshold too high. */
      if ((unsigned long) value > HEAP_MAX_SIZE / 2)
        res = 0;
      else
        {
          LIBC_PROBE (memory_mallopt_mmap_threshold, 3, value,
                      mp_.mmap_threshold, mp_.no_dyn_threshold);
          mp_.mmap_threshold = value;
          mp_.no_dyn_threshold = 1;
        }
      break;

    case M_MMAP_MAX:
      LIBC_PROBE (memory_mallopt_mmap_max, 3, value,
                  mp_.n_mmaps_max, mp_.no_dyn_threshold);
      mp_.n_mmaps_max = value;
      mp_.no_dyn_threshold = 1;
      break;

    case M_CHECK_ACTION:
      LIBC_PROBE (memory_mallopt_check_action, 2, value, check_action);
      check_action = value;
      break;

    case M_PERTURB:
      LIBC_PROBE (memory_mallopt_perturb, 2, value, perturb_byte);
      perturb_byte = value;
      break;

    case M_ARENA_TEST:
      if (value > 0)
        {
          LIBC_PROBE (memory_mallopt_arena_test, 2, value, mp_.arena_test);
          mp_.arena_test = value;
        }
      break;

    case M_ARENA_MAX:
      if (value > 0)
        {
          LIBC_PROBE (memory_mallopt_arena_max, 2, value, mp_.arena_max);
          mp_.arena_max = value;
        }
      break;
    }
  (void) mutex_unlock (&av->mutex);
  return res;
}
libc_hidden_def (__libc_mallopt)
```
在`mallopt()`函数配置前，需要检查主分配区是否初始化了，如果没有初始化，调用`ptmalloc_init()`函数初始化`ptmalloc`，然后获得主分配区的锁，调用`malloc_consolidate()`函数，`malloc_consolidate()`函数会判断主分配区是否已经初始化，如果没有，则初始化主分配区。同时我们也看到，`mp_`都没有锁，对`mp_`中参数字段的修改，是通过主分配区的锁来同步的。
### ptmalloc_init()
```c
static void
ptmalloc_init (void)
{
  if (__malloc_initialized >= 0)
    return;

  __malloc_initialized = 0;
```
`ptmalloc_init()`用于初始化`ptmalloc`，它首先检查全局变量`__malloc_initialized`是否大于等于0，如果该值大于0，表示`ptmalloc`已经初始化，如果该值为0，表示`ptmalloc`正在初始化，全局变量`__malloc_initialized`用来保证全局只初始化`ptmalloc`一次。
```c
#ifdef SHARED
  /* In case this libc copy is in a non-default namespace, never use brk.
     Likewise if dlopened from statically linked program.  */
  Dl_info di;
  struct link_map *l;

  if (_dl_open_hook != NULL
      || (_dl_addr (ptmalloc_init, &di, &l, NULL) != 0
          && l->l_ns != LM_ID_BASE))
    __morecore = __failing_morecore;
#endif
```
Ptmalloc需要保证只有主分配区才能使用`sbrk()`分配连续虚拟内存空间，如果有多个分配区使用`sbrk()`就不能获得连续的虚拟地址空间，大多数情况下Glibc库都是以动态链接库的形式加载的，处于默认命名空间，多个进程共用Glibc库，Glibc库代码段在内存中只有一份拷贝，数据段在每个用户进程都有一份拷贝。但如果Glibc库不在默认名字空间，或是用户程序是静态编译的并调用了`dlopen`函数加载Glibc库中的`ptamalloc_init()`，这种情况下的`ptmalloc`不允许使用`sbrk()`分配内存，只需修改`__morecore`函数指针指向`__failing_morecore`就可以禁止使用`sbrk()`了，`__morecore`默认指向`sbrk()`。
```c
  tsd_key_create (&arena_key, NULL);
  tsd_setspecific (arena_key, (void *) &main_arena);
  thread_atfork (ptmalloc_lock_all, ptmalloc_unlock_all, ptmalloc_unlock_all2);
  const char *s = NULL;
```
初始化全局锁`list_lock`，`list_lock`主要用于同步分配区的单向循环链表。然后创建线程私有实例`arena_key`，该私有实例保存的是分配区（arena）的`malloc_state`实例指针。`arena_key`指向的可能是主分配区的指针，也可能是非主分配区的指针，这里将调用`ptmalloc_init()`的线程的`arena_key`绑定到主分配区上。意味着本线程首选从主分配区分配内存。
然后调用`thread_atfork()`设置当前进程在fork子线程（linux下线程是轻量级进程，使用类似fork进程的机制创建）时处理mutex的回调函数，在本进程fork子线程时，调用`ptmalloc_lock_all()`获得所有分配区的锁，禁止所有分配区分配内存，当子线程创建完毕，父进程调用`ptmalloc_unlock_all()`重新unlock每个分配区的锁`mutex`，子线程调用`ptmalloc_unlock_all2()`重新初始化每个分配区的锁`mutex`。
```c
  if (__glibc_likely (_environ != NULL))
    {
      char **runp = _environ;
      char *envline;

      while (__builtin_expect ((envline = next_env_entry (&runp)) != NULL,
                               0))
        {
          size_t len = strcspn (envline, "=");

          if (envline[len] != '=')
            /* This is a "MALLOC_" variable at the end of the string
               without a '=' character.  Ignore it since otherwise we
               will access invalid memory below.  */
            continue;

          switch (len)
            {
            case 6:
              if (memcmp (envline, "CHECK_", 6) == 0)
                s = &envline[7];
              break;
            case 8:
              if (!__builtin_expect (__libc_enable_secure, 0))
                {
                  if (memcmp (envline, "TOP_PAD_", 8) == 0)
                    __libc_mallopt (M_TOP_PAD, atoi (&envline[9]));
                  else if (memcmp (envline, "PERTURB_", 8) == 0)
                    __libc_mallopt (M_PERTURB, atoi (&envline[9]));
                }
              break;
            case 9:
              if (!__builtin_expect (__libc_enable_secure, 0))
                {
                  if (memcmp (envline, "MMAP_MAX_", 9) == 0)
                    __libc_mallopt (M_MMAP_MAX, atoi (&envline[10]));
                  else if (memcmp (envline, "ARENA_MAX", 9) == 0)
                    __libc_mallopt (M_ARENA_MAX, atoi (&envline[10]));
                }
              break;
            case 10:
              if (!__builtin_expect (__libc_enable_secure, 0))
                {
                  if (memcmp (envline, "ARENA_TEST", 10) == 0)
                    __libc_mallopt (M_ARENA_TEST, atoi (&envline[11]));
                }
              break;
            case 15:
              if (!__builtin_expect (__libc_enable_secure, 0))
                {
                  if (memcmp (envline, "TRIM_THRESHOLD_", 15) == 0)
                    __libc_mallopt (M_TRIM_THRESHOLD, atoi (&envline[16]));
                  else if (memcmp (envline, "MMAP_THRESHOLD_", 15) == 0)
                    __libc_mallopt (M_MMAP_THRESHOLD, atoi (&envline[16]));
                }
              break;
            default:
              break;
            }
        }
    }
  if (s && s[0])
    {
      __libc_mallopt (M_CHECK_ACTION, (int) (s[0] - '0'));
      if (check_action != 0)
        __malloc_check_init ();
    }
```
从环境变量中读取相应的配置参数值，这些参数包括`MALLOC_TRIM_THRESHOLD_`，`MALLOC_TOP_PAD_`，`MALLOC_PERTURB_`，`MALLOC_MMAP_THRESHOLD_`，`MALLOC_CHECK_`，`MALLOC_MMAP_MAX_`，`MALLOC_ARENA_MAX`,`MALLOC_ ARENA_TEST`,如果这些选项中的某些项存在，调用mallopt()函数设置相应的选项。如果这段程序是在Glibc库初始化中执行的，会做更多的安全检查工作。
```c
  void (*hook) (void) = atomic_forced_read (__malloc_initialize_hook);
  if (hook != NULL)
    (*hook)();
  __malloc_initialized = 1;
}
```
在`ptmalloc_init()`函数结束处，查看是否存在`__malloc_initialize_hook`函数，如果存在，执行该hook函数。最后将全局变量`__malloc_initialized`设置为1，表示`ptmalloc_init()`已经初始化完成。
## 多分配区
由于只有一个主分配区从堆中分配小内存块，而稍大的内存块都必须从`mmap`映射区域分配，如果有多个线程都要分配小内存块，但多个线程是不能同时调用`sbrk()`函数的，因为只有一个函数调用`sbrk()`时才能保证分配的虚拟地址空间是连续的。如果多个线程都从主分配区中分配小内存块，效率很低效。为了解决这个问题，`ptmalloc`使用非主分配区来模拟主分配区的功能，非主分配区同样可以分配小内存块，并且可以创建多个非主分配区，从而在线程分配内存竞争比较激烈的情况下，可以创建更多的非主分配区来完成分配任务，减少分配区的锁竞争，提高分配效率。
Ptmalloc怎么用非主分配区来模拟主分配区的行为呢？首先创建一个新的非主分配区，非主分配区使用`mmap()`函数分配一大块内存来模拟堆（sub-heap），所有的从该非主分配区总分配的小内存块都从`sub-heap`中切分出来，如果一个`sub-heap`的内存用光了，或是`sub-heap`中的内存不够用时，使用`mmap()`分配一块新的内存块作为sub-heap，并将新的`sub-heap`链接在非主分配区中`sub-heap`的单向链表中。
分主分配区中的`sub-heap`所占用的内存不会无限的增长下去，同样会像主分配区那样进行`sub-heap`收缩，将`sub-heap`中`top chunk`的一部分返回给操作系统，如果`top chunk`为整个`sub-heap`，会把整个`sub-heap`还回给操作系统。收缩堆的条件是当前free的chunk大小加上前后能合并chunk的大小大于64KB，并且`top chunk`的大小达到`mmap`收缩阈值，才有可能收缩堆。
一般情况下，进程中有多个线程，也有多个分配区，线程的数据一般会比分配区数量多，所以必能保证没有线程独享一个分配区，每个分配区都有可能被多个线程使用，为了保证分配区的线程安全，对分配区的访问需要锁保护，当线程获得分配区的锁时，可以使用该分配区分配内存，并将该分配区的指针保存在线程的私有实例中。
当某一线程需要调用malloc分配内存空间时，该线程先查看线程私有变量中是否已经存在一个分配区，如果存在，尝试对该分配区加锁，如果加锁成功，使用该分配区分配内存，如果失败，该线程搜分配区索循环链表试图获得一个空闲的分配区。如果所有的分配区都已经加锁，那么malloc会开辟一个新的分配区，把该分配区加入到分配区的全局分配区循环链表并加锁，然后使用该分配区进行分配操作。在回收操作中，线程同样试图获得待回收块所在分配区的锁，如果该分配区正在被别的线程使用，则需要等待直到其他线程释放该分配区的互斥锁之后才可以进行回收操作。
### heap_info
```c
/* A heap is a single contiguous memory region holding (coalesceable)
   malloc_chunks.  It is allocated with mmap() and always starts at an
   address aligned to HEAP_MAX_SIZE.  */

typedef struct _heap_info
{
  mstate ar_ptr; /* Arena for this heap. */
  struct _heap_info *prev; /* Previous heap. */
  size_t size;   /* Current size in bytes. */
  size_t mprotect_size; /* Size in bytes that has been mprotected
                           PROT_READ|PROT_WRITE.  */
  /* Make sure the following data is properly aligned, particularly
     that sizeof (heap_info) + 2 * SIZE_SZ is a multiple of
     MALLOC_ALIGNMENT. */
  char pad[-6 * SIZE_SZ & MALLOC_ALIGN_MASK];
} heap_info;
```
`ar_ptr`是指向所属分配区的指针;
`prev`字段用于将同一个分配区中的`sub_heap`用单向链表链接起来。`prev`指向链表中的前一个`sub_heap`。
`size`字段表示当前`sub_heap`中的内存大小，以page对齐。
`mprotect_size`字段表示当前`sub_heap`中被读写保护的内存大小，也就是说还没有被分配的内存大小。
Pad字段用于保证`sizeof (heap_info)` + 2 * `SIZE_SZ`是按`MALLOC_ALIGNMENT`对齐的。`MALLOC_ALIGNMENT_MASK`为2 *`SIZE_SZ` \- 1，无论`SIZE_SZ`为4或8，\-6 * `SIZE_SZ` &` MALLOC_ALIGN_MASK`的值为0，如果`sizeof (heap_info)`+ 2 * `SIZE_SZ`不是按`MALLOC_ALIGNMENT`对齐，编译的时候就会报错，编译时会执行下面的宏。
```c
/* Get a compile-time error if the heap_info padding is not correct
   to make alignment work as expected in sYSMALLOc.  */
extern int sanity_check_heap_info_alignment[(sizeof (heap_info)
                                             + 2 * SIZE_SZ) % MALLOC_ALIGNMENT
                                            ? -1 : 1];
```
为什么一定要保证对齐呢？作为分主分配区的第一个`sub_heap`，`heap_info`存放在`sub_heap`的头部，紧跟`heap_info`之后是该非主分配区的`malloc_state`实例，紧跟`malloc_state`实例后，是`sub_heap`中的第一个chunk，但chunk的首地址必须按照`MALLOC_ALIGNMENT`对齐，所以在`malloc_state`实例和第一个`chunk`之间可能有几个字节的pad，但如果`sub_heap`不是非主分配区的第一个`sub_heap`，则紧跟`heap_info`后是第一个chunk，但`sysmalloc()`函数默认`heap_info`是按照`MALLOC_ALIGNMENT`对齐的，没有再做对齐的工作，直接将`heap_info`后的内存强制转换成一个chunk。所以这里在编译时保证`sizeof (heap_info)` + 2 * `SIZE_SZ`是按`MALLOC_ALIGNMENT`对齐的，在运行时就不用再做检查了，也不必再做对齐。
```c
/* Thread specific data */

static tsd_key_t arena_key;
static mutex_t list_lock = MUTEX_INITIALIZER;
static size_t narenas = 1;
static mstate free_list;

/* Mapped memory in non-main arenas (reliable only for NO_THREADS). */
static unsigned long arena_mem;

/* Already initialized? */
int __malloc_initialized = -1;
```
`arena_key`存放的是线程的私用实例，该私有实例保存的是分配区（arena）的`malloc_state`实例的指针。`arena_key`指向的可能是主分配区的指针，也可能是非主分配区的指针。
`list_lock`用于同步分配区的单向环形链表。
如果定义了`PRE_THREAD`，`narenas`全局变量表示当前分配区的数量，`free_list`全局变量是空闲分配区的单向链表，这些空闲的分配区可能是从父进程那里继承来的。全局变量`narenas`和`free_list`都用锁`list_lock`同步。
`arena_mem`只用于单线程的`ptmalloc`版本，记录了非主分配区所分配的内存大小。
`__malloc_initializd`全局变量用来标识是否`ptmalloc`已经初始化了，其值大于0时表示已经初始化。
```c
/* arena_get() acquires an arena and locks the corresponding mutex.
   First, try the one last locked successfully by this thread.  (This
   is the common case and handled with a macro for speed.)  Then, loop
   once over the circularly linked list of arenas.  If no arena is
   readily available, create a new one.  In this latter case, `size'
   is just a hint as to how much memory will be required immediately
   in the new arena. */

#define arena_get(ptr, size) do { \
      arena_lookup (ptr);						      \
      arena_lock (ptr, size);						      \
  } while (0)

#define arena_lookup(ptr) do { \
      void *vptr = NULL;						      \
      ptr = (mstate) tsd_getspecific (arena_key, vptr);			      \
  } while (0)

#define arena_lock(ptr, size) do {					      \
      if (ptr)								      \
        (void) mutex_lock (&ptr->mutex);				      \
      else								      \
        ptr = arena_get2 (ptr, (size), NULL);				      \
  } while (0)
```
上述用以获得一个分配区。
## 公共包装
### __libc_malloc
```c
/*
 malloc(size_t n)
 Returns a pointer to a newly allocated chunk of at least n bytes, or null
 if no space is available. Additionally, on failure, errno is
 set to ENOMEM on ANSI C systems.

 If n is zero, malloc returns a minumum-sized chunk. (The minimum
 size is 16 bytes on most 32bit systems, and 24 or 32 bytes on 64bit
 systems.)  On most systems, size_t is an unsigned type, so calls
 with negative arguments are interpreted as requests for huge amounts
 of space, which will often fail. The maximum supported value of n
 differs across systems, but is in all cases less than the maximum
 representable value of a size_t.
*/
void *  __libc_malloc(size_t);
```
` __libc_malloc`是`malloc`的真正调用的函数，这里是关于其功能的概述。
```c
void *
__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;

  void *(*hook) (size_t, const void *)
    = atomic_forced_read (__malloc_hook);
  if (__builtin_expect (hook != NULL, 0))
    return (*hook)(bytes, RETURN_ADDRESS (0));

  arena_lookup (ar_ptr);

  arena_lock (ar_ptr, bytes);
  if (!ar_ptr)
    return 0;

  victim = _int_malloc (ar_ptr, bytes);
  if (!victim)
    {
      LIBC_PROBE (memory_malloc_retry, 1, bytes);
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      if (__builtin_expect (ar_ptr != NULL, 1))
        {
          victim = _int_malloc (ar_ptr, bytes);
          (void) mutex_unlock (&ar_ptr->mutex);
        }
    }
  else
    (void) mutex_unlock (&ar_ptr->mutex);
  assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
          ar_ptr == arena_for_chunk (mem2chunk (victim)));
  return victim;
}
```
首先，检查`__malloc_hook`是否为空，是则向下执行，否则执行`__malloc_hook`指向的函数。这个功能是为了让使用者定义自己的`malloc`，其也存在于`free`、`realloc`等函数中。在进程初始化时`__malloc_hook`指向的函数为`malloc_hook_ini()`。
```c
/* arena_get() acquires an arena and locks the corresponding mutex.
   First, try the one last locked successfully by this thread.  (This
   is the common case and handled with a macro for speed.)  Then, loop
   once over the circularly linked list of arenas.  If no arena is
   readily available, create a new one.  In this latter case, `size'
   is just a hint as to how much memory will be required immediately
   in the new arena. */

#define arena_get(ptr, size) do { \
      arena_lookup (ptr);						      \
      arena_lock (ptr, size);						      \
  } while (0)

#define arena_lookup(ptr) do { \
      void *vptr = NULL;						      \
      ptr = (mstate) tsd_getspecific (arena_key, vptr);			      \
  } while (0)

#define arena_lock(ptr, size) do {					      \
      if (ptr)								      \
        (void) mutex_lock (&ptr->mutex);				      \
      else								      \
        ptr = arena_get2 (ptr, (size), NULL);				      \
  } while (0)
```
调用`arena_lookup`查找本线程的私用实例中是否包含一个分配区的指针，返回该指针，调用`arena_lock`尝试对该分配区加锁，如果加锁成功，使用该分配区分配内存，如果对该分配区加锁失败，调用`arena_get2`获得一个分配区指针。
之后调用了`_int_malloc`从分配区中获取内存。如果`_int_malloc()`函数分配内存失败，并且使用的分配区不是主分配区，这种情况可能是mmap区域的内存被用光了，当主分配区可以从堆中分配内存，所以需要再尝试从主分配区中分配内存。首先释放所使用分配区的锁，然后获得主分配区的锁，并调用`_int_malloc()`函数分配内存，最后释放主分配区的锁。
```c
/* If we don't have the main arena, then maybe the failure is due to running
   out of mmapped areas, so we can try allocating on the main arena.
   Otherwise, it is likely that sbrk() has failed and there is still a chance
   to mmap(), so try one of the other arenas.  */
static mstate
arena_get_retry (mstate ar_ptr, size_t bytes)
{
  LIBC_PROBE (memory_arena_retry, 2, bytes, ar_ptr);
  if (ar_ptr != &main_arena)
    {
      (void) mutex_unlock (&ar_ptr->mutex);
      ar_ptr = &main_arena;
      (void) mutex_lock (&ar_ptr->mutex);
    }
  else
    {
      /* Grab ar_ptr->next prior to releasing its lock.  */
      mstate prev = ar_ptr->next ? ar_ptr : 0;
      (void) mutex_unlock (&ar_ptr->mutex);
      ar_ptr = arena_get2 (prev, bytes, ar_ptr);
    }

  return ar_ptr;
}
```
如果`_int_malloc()`函数分配内存失败，并且使用的分配区是主分配区，查看是否有非主分配区，如果有，调用`arena_get2()`获取分配区，然后对主分配区解锁，如果`arena_get2()`返回一个非主分配区，尝试调用`_int_malloc()`函数从该非主分配区分配内存，最后释放该非主分配区的锁。
如果`_int_malloc()`函数分配内存成功，释放所使用的分配区的锁。
可以发现真正分配内存的函数是`_int_malloc()`，而`__libc_malloc()`只是其简单的封装。
### _int_malloc()
下面重点分析`_int_malloc()`：
```c
/*
   ------------------------------ malloc ------------------------------
 */

static void *
_int_malloc (mstate av, size_t bytes)
{
  INTERNAL_SIZE_T nb;               /* normalized request size */
  unsigned int idx;                 /* associated bin index */
  mbinptr bin;                      /* associated bin */

  mchunkptr victim;                 /* inspected/selected chunk */
  INTERNAL_SIZE_T size;             /* its size */
  int victim_index;                 /* its bin index */

  mchunkptr remainder;              /* remainder from a split */
  unsigned long remainder_size;     /* its size */

  unsigned int block;               /* bit map traverser */
  unsigned int bit;                 /* bit map traverser */
  unsigned int map;                 /* current word of binmap */

  mchunkptr fwd;                    /* misc temp for linking */
  mchunkptr bck;                    /* misc temp for linking */

  const char *errstr = NULL;
```
这里是定义的一些变量
```c
  /*
     Convert request size to internal form by adding SIZE_SZ bytes
     overhead plus possibly more to obtain necessary alignment and/or
     to obtain a size of at least MINSIZE, the smallest allocatable
     size. Also, checked_request2size traps (returning 0) request sizes
     that are so large that they wrap around zero when padded and
     aligned.
   */

  checked_request2size (bytes, nb);
```
`checked_request2size()`将请求的大小转化为chunk的大小，在`_int_malloc()`内部分配内存是以chunk为单位的。
```c
  /*
     If the size qualifies as a fastbin, first check corresponding bin.
     This code is safe to execute even if av is not yet initialized, so we
     can try it without checking, which saves some time on this fast path.
   */

  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
    {
      idx = fastbin_index (nb);
      mfastbinptr *fb = &fastbin (av, idx);
      mchunkptr pp = *fb;
      do
        {
          victim = pp;
          if (victim == NULL)
            break;
        }
      while ((pp = catomic_compare_and_exchange_val_acq (fb, victim->fd, victim))
             != victim);
      if (victim != 0)
        {
          if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
            {
              errstr = "malloc(): memory corruption (fast)";
            errout:
              malloc_printerr (check_action, errstr, chunk2mem (victim));
              return NULL;
            }
          check_remalloced_chunk (av, victim, nb);
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
    }
```
如果chunk的大小在`fast bins`的范围内，首先尝试在`fast bins`中寻找适合的chunk。
首先根据所需chunk的大小获得该chunk所属`fast bin`的index，根据该index获得所需`fast bin`的空闲chunk链表的头指针，然后将头指针的下一个chunk作为空闲chunk链表的头部。为了加快从`fast bins`中分配chunk，处于fast bins中chunk的状态仍然保持为inuse状态，避免被相邻的空闲chunk合并，从`fast bins`中分配chunk，只需取出第一个chunk，并调用`chunk2mem()`函数返回用户所需的内存块。
```c
  /*
     If a small request, check regular bin.  Since these "smallbins"
     hold one size each, no searching within bins is necessary.
     (For a large request, we need to wait until unsorted chunks are
     processed to find best fit. But for small ones, fits are exact
     anyway, so we can check now, which is faster.)
   */

  if (in_smallbin_range (nb))
    {
      idx = smallbin_index (nb);
      bin = bin_at (av, idx);

      if ((victim = last (bin)) != bin)
        {
          if (victim == 0) /* initialization check */
            malloc_consolidate (av);
          else
            {
              bck = victim->bk;
	if (__glibc_unlikely (bck->fd != victim))
                {
                  errstr = "malloc(): smallbin double linked list corrupted";
                  goto errout;
                }
              set_inuse_bit_at_offset (victim, nb);
              bin->bk = bck;
              bck->fd = bin;

              if (av != &main_arena)
                victim->size |= NON_MAIN_ARENA;
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
        }
    }
```
如果分配的chunk属于`small bin`，首先查找chunk所对应`small bins`数组的index，然后根据index获得某个`small bin`的空闲chunk双向循环链表表头，然后将最后一个chunk赋值给victim，如果victim与表头相同，表示该链表为空，不能从`small bin`的空闲chunk链表中分配。若victim为0，表示`small bin`并没有初始化。所以调用`malloc_consolidate`将该分配区`fast bins`中chunk进行合并。否则对该bin中最后一个chunk进行双向链表检查，检查上一个chunk的后一个是否是`victim`。正确之后，设置其控制位。最后将指针转化位`mem`返回给用户。
可以发现，这里并没有链表为空时的相应处理，这种情况会在之后进行处理。

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

  else
    {
      idx = largebin_index (nb);
      if (have_fastchunks (av))
        malloc_consolidate (av);
    }
```
若请求大小不在`small bin`的范围内，那必然就在`large bins`中。但不会直接遍历`large bins`。在`fast bins`和`small bins`中存在很多较小的chunk，若不对这些进行处理就会浪费很多的空间，降低内存的利用率，所以首先检查`fast bins`中是否有chunk，若有则进行合并，加入到`unsorted bin`中。合并中的细节我们将之后再分析。
之后就进入了一个大循环中
**大循环**
大循环会最终实现内存的分配。
```c
  /*
     Process recently freed or remaindered chunks, taking one only if
     it is exact fit, or, if this a small request, the chunk is remainder from
     the most recent non-exact fit.  Place other traversed chunks in
     bins.  Note that this step is the only place in any routine where
     chunks are placed in bins.

     The outer loop here is needed because we might not realize until
     near the end of malloc that we should have consolidated, so must
     do so and retry. This happens at most once, and only when we would
     otherwise need to expand memory to service a "small" request.
   */

  for (;; )
    {
      int iters = 0;
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {
          bck = victim->bk;
          if (__builtin_expect (victim->size <= 2 * SIZE_SZ, 0)
              || __builtin_expect (victim->size > av->system_mem, 0))
            malloc_printerr (check_action, "malloc(): memory corruption",
                             chunk2mem (victim));
          size = chunksize (victim);
```
首先，反向遍历`unsorted bin`，直到只剩链表头。并要求大小大于`2*SIZE_SZ`且不超过分配区的边界。
```c
          /*
             If a small request, try to use last remainder if it is the
             only chunk in unsorted bin.  This helps promote locality for
             runs of consecutive small requests. This is the only
             exception to best-fit, and applies only when there is
             no exact fit for a small chunk.
           */

          if (in_smallbin_range (nb) &&
              bck == unsorted_chunks (av) &&
              victim == av->last_remainder &&
              (unsigned long) (size) > (unsigned long) (nb + MINSIZE))
            {
```
如果需要分配一个`small bin chunk`，在之前的判断中中没有匹配到合适的chunk，并且`unsorted bin`中只有一个chunk，并且这个chunk为`last remainder chunk`，并且这个chunk的大小大于所需chunk的大小加上`MINSIZE`，在满足这些条件的情况下，可以使用`last remainder chunk`切分出需要的`small bin chunk`。
```c
              /* split and reattach remainder */
              remainder_size = size - nb;
              remainder = chunk_at_offset (victim, nb);
              unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder;
              av->last_remainder = remainder;
              remainder->bk = remainder->fd = unsorted_chunks (av);
              if (!in_smallbin_range (remainder_size))
                {
                  remainder->fd_nextsize = NULL;
                  remainder->bk_nextsize = NULL;
                }

              set_head (victim, nb | PREV_INUSE |
                        (av != &main_arena ? NON_MAIN_ARENA : 0));
              set_head (remainder, remainder_size | PREV_INUSE);
              set_foot (remainder, remainder_size);

              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
```
将分割后剩下的部分作为新的`last remainder chunk`，更新`last remainder chunk`的size等一些相关的设置。若剩余部分的大小属于`large bin`将其的`fd_nextsize`和`fd_nextsize`都设置为NULL，因为`last remainder chunk`只能存在于`unsorted bin`中。最后，设置分割好的chunk的头部信息，对于`last remainder chunk`还要设置foot即`prev_size`域。
```c
          /* remove from unsorted list */
          unsorted_chunks (av)->bk = bck;
          bck->fd = unsorted_chunks (av);

          /* Take now instead of binning if exact fit */

          if (size == nb)
            {
              set_inuse_bit_at_offset (victim, size);
              if (av != &main_arena)
                victim->size |= NON_MAIN_ARENA;
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
```
从`unsorted bins`中取出最后的那个chunk。若其大小正好满足要求，设置其后一chunk的标志位，然后设置该chunk的控制信息等，转化为`mem`返回给用户。
```c
          /* place chunk in bin */

          if (in_smallbin_range (size))
            {
              victim_index = smallbin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;
            }
          else
            {
              victim_index = largebin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;
```
若取出的chunk属于`small bins`，获得当前chunk所属`small bin`的index，并将该`small bin`的链表表头赋值给bck，第一个chunk赋值给fwd，也就是当前的chunk会插入到bck和fwd之间，作为`small bin`链表的第一个chunk。
若属于`large bins`,也会进行相应的操作，不过还要设置`fd_nextsize`和`bk_nextsize`。
```c
              /* maintain large bins in sorted order */
              if (fwd != bck)
                {
                  /* Or with inuse bit to speed comparisons */
                  size |= PREV_INUSE;
                  /* if smaller than smallest, bypass loop below */
                  assert ((bck->bk->size & NON_MAIN_ARENA) == 0);
```
如果`fwd!=bck`则说明当前`large bin`不为空。，由于`large bin`中的空闲chunk是按照大小顺序排序的，需要将当前从`unsorted bin`中取出的chunk插入到`large bin`中合适的位置。将当前chunk的size的`inuse`标志bit置位，相当于加1，便于加快chunk大小的比较，找到合适的地方插入当前chunk。这里还做了一次检查，断言在`large bin`双向循环链表中的最后一个chunk的size字段中的非主分配区的标志bit没有置位，因为所有在`large bin`中的chunk都处于空闲状态，该标志位一定是清零的。
```c
                  if ((unsigned long) (size) < (unsigned long) (bck->bk->size))
                    {
                      fwd = bck;
                      bck = bck->bk;

                      victim->fd_nextsize = fwd->fd;
                      victim->bk_nextsize = fwd->fd->bk_nextsize;
                      fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
                    }
```
如果当前chunk比large bin的最后一个chunk的大小还小，那么当前chunk就插入到large bin的链表的最后，作为最后一个chunk。
> 这里可能会对large bin中的四个指针产生迷惑，所以进行详细的说明：
> 在`large bins`中，chunk都是从大到小排序的，不同大小的chunk通过`fd_nextsize`和`bk_nextsize`进行链接，`fd_nextsize`指向下一个比当前`chunk size`小的第一个空闲chunk，不包含 bin 的头指针。`bk_nextszie`指向上一个比当前`chunk size`大的第一个空闲chunk，不包含 bin 的头指针。先被free的chunk会成为堆头，而大小与堆头相等的chunk会通过`fd`和`bk`链接到堆头的后面。所以说一个`large bin chunk`存在于两个链表中。其四个指针都被利用了起来。这加快了`large bins`中的搜索。
```c
                  else
                    {
                      assert ((fwd->size & NON_MAIN_ARENA) == 0);
                      while ((unsigned long) size < fwd->size)
                        {
                          fwd = fwd->fd_nextsize;
                          assert ((fwd->size & NON_MAIN_ARENA) == 0);
                        }
```
正向遍历chunk size链表，直到找到第一个chunk大小小于等于当前chunk大小的chunk退出循环。
```c
                      if ((unsigned long) size == (unsigned long) fwd->size)
                        /* Always insert in the second position.  */
                        fwd = fwd->fd;
```
如果从large bin链表中找到了与当前chunk大小相同的chunk，则同一大小的chunk已经存在，那么chunk size链表中一定包含了fwd所指向的chunk，为了不修改chunk size链表，当前chunk只能插入fwd之后。
```c
                      else
                        {
                          victim->fd_nextsize = fwd;
                          victim->bk_nextsize = fwd->bk_nextsize;
                          fwd->bk_nextsize = victim;
                          victim->bk_nextsize->fd_nextsize = victim;
                        }
```
如果chunk size链表中还没有包含当前chunk大小的chunk，也就是说当前chunk的大小大于fwd的大小，则将当前chunk作为该chunk size的代表加入chunk size链表，chunk size链表也是按照由大到小的顺序排序。
```c
                      bck = fwd->bk;
                    }
                }
              else
                victim->fd_nextsize = victim->bk_nextsize = victim;
            }
```
如果`large bin`中没有chunk，那么直接将其作为堆头加入链表。
```c
          mark_bin (av, victim_index);
          victim->bk = bck;
          victim->fd = fwd;
          fwd->bk = victim;
          bck->fd = victim;
```
上面的代码最终完成了将chunk加入到对应的链表中，并设置了`binmap`。
```c
#define MAX_ITERS       10000
          if (++iters >= MAX_ITERS)
            break;
        }
```
这里设置了一个计数器，默认最多遍历`unsorted bin`中的10000个chunk，避免影响分配效率。
> 为了避免混乱，现在可以思考一下循环中之前的代码做了什么。虽然现在仍在分析循环。
```c
      /*
         If a large request, scan through the chunks of current bin in
         sorted order to find smallest that fits.  Use the skip list for this.
       */

      if (!in_smallbin_range (nb))
        {
          bin = bin_at (av, idx);

          /* skip scan if empty or largest chunk is too small */
          if ((victim = first (bin)) != bin &&
              (unsigned long) (victim->size) >= (unsigned long) (nb))
            {
              victim = victim->bk_nextsize;
              while (((unsigned long) (size = chunksize (victim)) <
                      (unsigned long) (nb)))
                victim = victim->bk_nextsize;
```
如果请求的大小在`large bins`的范围内，判断对应`large bin`是否为空且其中最大的chunk是否大于请求大小，若是，则说明在这个bin中存在满足要求的chunk。反向遍历链表，找到第一个大于等于请求大小的chunk，跳出循环。
```c
              /* Avoid removing the first entry for a size so that the skip
                 list does not have to be rerouted.  */
              if (victim != last (bin) && victim->size == victim->fd->size)
                victim = victim->fd;
```
如果从large bin链表中选取的chunk victim不是链表中的最后一个chunk，并且与victim大小相同的chunk不止一个，那么意味着victim为chunk size链表中的节点，为了不调整chunk size链表，需要避免将chunk size链表中的节点取出，所以取`victim->fd`节点对应的chunk作为候选chunk。
```c
              remainder_size = size - nb;
              unlink (victim, bck, fwd);
```
计算分割后的`remainder_size`，并使用`unlink()`将其从`large bin`中取出.
```c
              /* Exhaust */
              if (remainder_size < MINSIZE)
                {
                  set_inuse_bit_at_offset (victim, size);
                  if (av != &main_arena)
                    victim->size |= NON_MAIN_ARENA;
                }
```
若剩余的大小小于`MINSIZE`，那么就要将整个chunk给用户，相比于多给一部分内存，切割后产生的小碎片对内存管理的影响更大。并设置相应的标志位。
```c
              /* Split */
              else
                {
                  remainder = chunk_at_offset (victim, nb);
                  /* We cannot assume the unsorted list is empty and therefore
                     have to perform a complete insert here.  */
                  bck = unsorted_chunks (av);
                  fwd = bck->fd;
	  if (__glibc_unlikely (fwd->bk != bck))
                    {
                      errstr = "malloc(): corrupted unsorted chunks";
                      goto errout;
                    }
                  remainder->bk = bck;
                  remainder->fd = fwd;
                  bck->fd = remainder;
                  fwd->bk = remainder;
                  if (!in_smallbin_range (remainder_size))
                    {
                      remainder->fd_nextsize = NULL;
                      remainder->bk_nextsize = NULL;
                    }
                  set_head (victim, nb | PREV_INUSE |
                            (av != &main_arena ? NON_MAIN_ARENA : 0));
                  set_head (remainder, remainder_size | PREV_INUSE);
                  set_foot (remainder, remainder_size);
                }
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
        }
```
切分出需要的chunk，剩余部分加入`unsorted bin`中。同时检查了头部的双向链接。如果剩余大小在`large bins`的范围，但是因为加入了`unsorted bin`，要把`fd_nextsize`和`bk_nextsize`清空。最后设置控制相关的控制信息和标志位，将`mem`返回给用户。
```c
      /*
         Search for a chunk by scanning bins, starting with next largest
         bin. This search is strictly by best-fit; i.e., the smallest
         (with ties going to approximately the least recently used) chunk
         that fits is selected.

         The bitmap avoids needing to check that most blocks are nonempty.
         The particular case of skipping all bins during warm-up phases
         when no chunks have been returned yet is faster than it might look.
       */

      ++idx;
      bin = bin_at (av, idx);
      block = idx2block (idx);
      map = av->binmap[block];
      bit = idx2bit (idx);
```
如果在对应的`small bin`和`large bin`中都没找到满足要求的chunk，则需要在更大bin中寻找是否有chunk可以分配。这里通过查询binmap快速判断较大的bin中是否有空闲的chunk。
```c
      for (;; )
        {
          /* Skip rest of block if there are no more set bits in this block.  */
          if (bit > map || bit == 0)
            {
              do
                {
                  if (++block >= BINMAPSIZE) /* out of bins */
                    goto use_top;
                }
              while ((map = av->binmap[block]) == 0);

              bin = bin_at (av, (block << BINMAPSHIFT));
              bit = 1;
            }
```
Idx2bit()宏将idx指定的位设置为1，其它位清零，map表示一个`block（unsigned int）`值，如果bit大于map，意味着map为0，该block所对应的所有bins中都没有空闲chunk，于是遍历binmap的下一个block，直到找到一个不为0的block或者遍历完所有的block。退出循环遍历后，设置bin指向block的第一个bit对应的bin，并将bit置为1，表示该block中bit 1对应的bin，这个bin中如果有空闲chunk，该chunk的大小一定满足要求。
```c
          /* Advance to bin with set bit. There must be one. */
          while ((bit & map) == 0)
            {
              bin = next_bin (bin);
              bit <<= 1;
              assert (bit != 0);
            }
```
在一个block遍历对应的bin，直到找到一个bit不为0退出遍历，则该bit对于的bin中有空闲chunk存在。
```c
          /* Inspect the bin. It is likely to be non-empty */
          victim = last (bin);

          /*  If a false alarm (empty bin), clear the bit. */
          if (victim == bin)
            {
              av->binmap[block] = map &= ~bit; /* Write through */
              bin = next_bin (bin);
              bit <<= 1;
            }
```
找到了不为空的bin，将最后一个chunk赋值给victim，并判断bin是否为空。若为空则表示binmap相应位设置不准确，重新进行设置。并寻找下一个bin。这里与之前讲的对应了，当malloc时binmap才会更新。
```c
          else
            {
              size = chunksize (victim);

              /*  We know the first chunk in this bin is big enough to use. */
              assert ((unsigned long) (size) >= (unsigned long) (nb));

              remainder_size = size - nb;

              /* unlink */
              unlink (victim, bck, fwd);

              /* Exhaust */
              if (remainder_size < MINSIZE)
                {
                  set_inuse_bit_at_offset (victim, size);
                  if (av != &main_arena)
                    victim->size |= NON_MAIN_ARENA;
                }

              /* Split */
              else
                {
                  remainder = chunk_at_offset (victim, nb);

                  /* We cannot assume the unsorted list is empty and therefore
                     have to perform a complete insert here.  */
                  bck = unsorted_chunks (av);
                  fwd = bck->fd;
	  if (__glibc_unlikely (fwd->bk != bck))
                    {
                      errstr = "malloc(): corrupted unsorted chunks 2";
                      goto errout;
                    }
                  remainder->bk = bck;
                  remainder->fd = fwd;
                  bck->fd = remainder;
                  fwd->bk = remainder;

                  /* advertise as last remainder */
                  if (in_smallbin_range (nb))
                    av->last_remainder = remainder;
                  if (!in_smallbin_range (remainder_size))
                    {
                      remainder->fd_nextsize = NULL;
                      remainder->bk_nextsize = NULL;
                    }
                  set_head (victim, nb | PREV_INUSE |
                            (av != &main_arena ? NON_MAIN_ARENA : 0));
                  set_head (remainder, remainder_size | PREV_INUSE);
                  set_foot (remainder, remainder_size);
                }
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
        }
```
若不为空，则满足要求的chunk就在其中了。于是重复了与之前找到`large bin`时的相同的操作。
```c
    use_top:
      /*
         If large enough, split off the chunk bordering the end of memory
         (held in av->top). Note that this is in accord with the best-fit
         search rule.  In effect, av->top is treated as larger (and thus
         less well fitting) than any other available chunk since it can
         be extended to be as large as necessary (up to system
         limitations).

         We require that av->top always exists (i.e., has size >=
         MINSIZE) after initialization, so if it would otherwise be
         exhausted by current request, it is replenished. (The main
         reason for ensuring it exists is that we may need MINSIZE space
         to put in fenceposts in sysmalloc.)
       */

      victim = av->top;
      size = chunksize (victim);
```
最后若以上，都没能找到满足要求的chunk。这说明即使取出`unsorted bin`最后一个chunk，有可能满足要求的bins仍然为空或是用户请求的空间过大。这时需要切割`top chunk`。
```c
      if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
        {
          remainder_size = size - nb;
          remainder = chunk_at_offset (victim, nb);
          av->top = remainder;
          set_head (victim, nb | PREV_INUSE |
                    (av != &main_arena ? NON_MAIN_ARENA : 0));
          set_head (remainder, remainder_size | PREV_INUSE);

          check_malloced_chunk (av, victim, nb);
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
```
由于`top chunk`切分出所需chunk后，还需要`MINSIZE`的空间来作为`fencepost`，所需必须满足`top chunk`的大小大于所需chunk的大小加上`MINSIZE`这个条件，才能从`top chunk`中分配所需chunk。从`top chunk`切分出所需chunk的处理过程跟前面的chunk切分类似，不同的是，原`top chunk`切分后的剩余部分将作为新的`top chunk`，原`top chunk`的`fencepost`仍然作为新的`top chunk`的`fencepost`，所以切分之后剩余的chunk不用`set_foot`。
```c
      /* When we are using atomic ops to free fast chunks we can get
         here for all block sizes.  */
      else if (have_fastchunks (av))
        {
          malloc_consolidate (av);
          /* restore original bin index */
          if (in_smallbin_range (nb))
            idx = smallbin_index (nb);
          else
            idx = largebin_index (nb);
        }
```
这里再次判断`fast bins`是否为空。并将其合并到`unsorted bin`中回到外层大循环。
 在进入大循环之前，已经对`fast bins`和`small bins`进行了遍历，但是没有找到符合要求的chunk。之后，进入大循环，从`unsorted bin`中取出一个chunk，首先判断是否满足要求，再将其放入对应得bin中。然后对`small bins`和`large bins`进行遍历。仍然没有满足要求。同时切割`top chunk`得条件未满足，这时或许有其他线程向`fast bins`中加入了chunk。所以重新尝试分配`small bin chunk`。
```c
      /*
         Otherwise, relay to handle system-dependent cases
       */
      else
        {
          void *p = sysmalloc (nb, av);
          if (p != NULL)
            alloc_perturb (p, bytes);
          return p;
        }
    }
}
```
最后，请系统分配内存。
#### sysmalloc
难理解，参考《ptmalloc源码分析》
```c
/*
   sysmalloc handles malloc cases requiring more memory from the system.
   On entry, it is assumed that av->top does not have enough
   space to service request for nb bytes, thus requiring that av->top
   be extended or replaced.
 */

static void *
sysmalloc (INTERNAL_SIZE_T nb, mstate av)
{
  mchunkptr old_top;              /* incoming value of av->top */
  INTERNAL_SIZE_T old_size;       /* its size */
  char *old_end;                  /* its end address */

  long size;                      /* arg to first MORECORE or mmap call */
  char *brk;                      /* return value from MORECORE */

  long correction;                /* arg to 2nd MORECORE call */
  char *snd_brk;                  /* 2nd return val */

  INTERNAL_SIZE_T front_misalign; /* unusable bytes at front of new space */
  INTERNAL_SIZE_T end_misalign;   /* partial page left at end of new space */
  char *aligned_brk;              /* aligned offset into brk */

  mchunkptr p;                    /* the allocated/returned chunk */
  mchunkptr remainder;            /* remainder from allocation */
  unsigned long remainder_size;   /* its size */


  size_t pagemask = GLRO (dl_pagesize) - 1;
  bool tried_mmap = false;
```
当`top chunk`都无法满足要求时，证明`top chunk`没有足够的空间，所以需要替换或拓展。
```c
  /*
     If have mmap, and the request size meets the mmap threshold, and
     the system supports mmap, and there are few enough currently
     allocated mmapped regions, try to directly map this request
     rather than expanding top.
   */

  if ((unsigned long) (nb) >= (unsigned long) (mp_.mmap_threshold) &&
      (mp_.n_mmaps < mp_.n_mmaps_max))
    {
      char *mm;           /* return value from mmap call*/
```
若当前请求满足`mmap`的分配阈值（默认为128k），并且当前进程`mmap()`分配的内存小于设定的最大值，则尝试使用`mmap()`进行分配，从而避免拓展`top chunk`。
```c
    try_mmap:
      /*
         Round up size to nearest page.  For mmapped chunks, the overhead
         is one SIZE_SZ unit larger than for normal chunks, because there
         is no following chunk whose prev_size field could be used.

         See the front_misalign handling below, for glibc there is no
         need for further alignments unless we have have high alignment.
       */
      if (MALLOC_ALIGNMENT == 2 * SIZE_SZ)
        size = (nb + SIZE_SZ + pagemask) & ~pagemask;
      else
        size = (nb + SIZE_SZ + MALLOC_ALIGN_MASK + pagemask) & ~pagemask;
      tried_mmap = true;
```
由于nb为所需chunk的大小，在`_int_malloc()`函数中已经将用户需要分配的大小转化为chunk大小，当如果这个chunk直接使用`mmap()`分配的话，该chunk不存在下一个相邻的chunk，也就没有`prev_size`的内存空间可以复用，所以还需要额外`SIZE_SZ`大小的内存。由于`mmap()`分配的内存块必须页对齐。如果使用`mmap()`分配内存，需要重新计算分配的内存大小size。
```c
      /* Don't try if size wraps around 0 */
      if ((unsigned long) (size) > (unsigned long) (nb))
        {
          mm = (char *) (MMAP (0, size, PROT_READ | PROT_WRITE, 0));

          if (mm != MAP_FAILED)
            {
              /*
                 The offset to the start of the mmapped region is stored
                 in the prev_size field of the chunk. This allows us to adjust
                 returned start address to meet alignment requirements here
                 and in memalign(), and still be able to compute proper
                 address argument for later munmap in free() and realloc().
               */

              if (MALLOC_ALIGNMENT == 2 * SIZE_SZ)
                {
                  /* For glibc, chunk2mem increases the address by 2*SIZE_SZ and
                     MALLOC_ALIGN_MASK is 2*SIZE_SZ-1.  Each mmap'ed area is page
                     aligned and therefore definitely MALLOC_ALIGN_MASK-aligned.  */
                  assert (((INTERNAL_SIZE_T) chunk2mem (mm) & MALLOC_ALIGN_MASK) == 0);
                  front_misalign = 0;
                }
              else
                front_misalign = (INTERNAL_SIZE_T) chunk2mem (mm) & MALLOC_ALIGN_MASK;
              if (front_misalign > 0)
                {
                  correction = MALLOC_ALIGNMENT - front_misalign;
                  p = (mchunkptr) (mm + correction);
                  p->prev_size = correction;
                  set_head (p, (size - correction) | IS_MMAPPED);
                }
              else
                {
                  p = (mchunkptr) mm;
                  set_head (p, size | IS_MMAPPED);
                }
```
如果重新计算所需分配的size小于nb，表示溢出了，不分配内存，否则，调用`mmap()`分配所需大小的内存。如果`mmap()`分配内存成功，将`mmap()`返回的内存指针强制转换为chunk指针，并设置该chunk的大小为size，同时设置该chunk的`IS_MMAPPED`标志位，表示本chunk是通过`mmap()`函数直接从系统分配的。由于`mmap()`返回的内存地址是按照页对齐的，也一定是按照2*`SIZE_SZ`对齐的，满足chunk的边界对齐规则，使用`chunk2mem()`获取chunk中实际可用的内存也没有问题，所以这里不需要做额外的对齐操作。
```c
              /* update statistics */

              int new = atomic_exchange_and_add (&mp_.n_mmaps, 1) + 1;
              atomic_max (&mp_.max_n_mmaps, new);

              unsigned long sum;
              sum = atomic_exchange_and_add (&mp_.mmapped_mem, size) + size;
              atomic_max (&mp_.max_mmapped_mem, sum);

              check_chunk (av, p);

              return chunk2mem (p);
            }
        }
    }
```
之后更新统计信息，`mmap()`分配的chunk数和总量都进行了更新。最后返回分配`chunk`的`mem`指针。到这里`mmap()`成功了。
```c
  /* Record incoming configuration of top */

  old_top = av->top;
  old_size = chunksize (old_top);
  old_end = (char *) (chunk_at_offset (old_top, old_size));

  brk = snd_brk = (char *) (MORECORE_FAILURE);
```
若`mmap()`也没有成功那么只能拓展`top chunk`，将`top chunk`的起始地址、大小和终止地址保存在局部变量中。
```c
  /*
     If not the first time through, we require old_size to be
     at least MINSIZE and to have prev_inuse set.
   */

  assert ((old_top == initial_top (av) && old_size == 0) ||
          ((unsigned long) (old_size) >= MINSIZE &&
           prev_inuse (old_top) &&
           ((unsigned long) old_end & pagemask) == 0));

  /* Precondition: not enough current space to satisfy nb request */
  assert ((unsigned long) (old_size) < (unsigned long) (nb + MINSIZE));
```
检查`top chunk`的合法性，如果第一次调用本函数，`top chunk`可能没有初始化，可能`old_size`为0，如果`top chunk`已经初始化，则`top chunk`的大小必须大于等于`MINSIZE`，因为`top chunk`中包含了`fencepost`，`fencepost`需要`MINSIZE`大小的内存。`Top chun`k必须标识前一个chunk处于inuse状态，这是规定，并且`top chunk`的结束地址必定是页对齐的。另外top chunk的除去`fencepost`的大小必定小于所需chunk的大小，不然在`_int_malloc()`函数中就应该使用`top chunk`获得所需的chunk。
```c
  if (av != &main_arena)
    {
      heap_info *old_heap, *heap;
      size_t old_heap_size;

      /* First try to extend the current heap. */
      old_heap = heap_for_ptr (old_top);
      old_heap_size = old_heap->size;
      if ((long) (MINSIZE + nb - old_size) > 0
          && grow_heap (old_heap, MINSIZE + nb - old_size) == 0)
        {
          av->system_mem += old_heap->size - old_heap_size;
          arena_mem += old_heap->size - old_heap_size;
          set_head (old_top, (((char *) old_heap + old_heap->size) - (char *) old_top)
                    | PREV_INUSE);
        }
```
若当前分配区非主分配区，获取`heap_info`，如果`top chunk`的剩余有效空间不足以分配出所需的chunk（前面已经断言，这个肯定成立），尝试增长`sub_heap`的可读可写区域大小，如果成功，修改过内存分配的统计信息，并更新新的`top chunk`的size。
```c
      else if ((heap = new_heap (nb + (MINSIZE + sizeof (*heap)), mp_.top_pad)))
        {
          /* Use a newly allocated heap.  */
          heap->ar_ptr = av;
          heap->prev = old_heap;
          av->system_mem += heap->size;
          arena_mem += heap->size;
          /* Set up the new top.  */
          top (av) = chunk_at_offset (heap, sizeof (*heap));
          set_head (top (av), (heap->size - sizeof (*heap)) | PREV_INUSE);
```
调用`new_heap()`函数创建一个新的`sub_heap`，由于这个`sub_heap`中至少需要容下大小为nb的chunk，大小为`MINSIZE`的`fencepost`和大小为`sizeof(*heap)`的`heap_info`实例，所以传入`new_heap()`函数的分配大小为`nb + (MINSIZE + sizeof(*heap))`。
使新创建的`sub_heap`保存当前的分配区指针，将该`sub_heap`加入当前分配区的`sub_heap`链表中，更新当前分配区内存分配统计，将新创建的`sub_heap`仅有的一个空闲chunk作为当前分配区的`top chunk`，并设置`top chunk`的状态。
```c
          /* Setup fencepost and free the old top chunk with a multiple of
             MALLOC_ALIGNMENT in size. */
          /* The fencepost takes at least MINSIZE bytes, because it might
             become the top chunk again later.  Note that a footer is set
             up, too, although the chunk is marked in use. */
          old_size = (old_size - MINSIZE) & ~MALLOC_ALIGN_MASK;
          set_head (chunk_at_offset (old_top, old_size + 2 * SIZE_SZ), 0 | PREV_INUSE);
          if (old_size >= MINSIZE)
            {
              set_head (chunk_at_offset (old_top, old_size), (2 * SIZE_SZ) | PREV_INUSE);
              set_foot (chunk_at_offset (old_top, old_size), (2 * SIZE_SZ));
              set_head (old_top, old_size | PREV_INUSE | NON_MAIN_ARENA);
              _int_free (av, old_top, 1);
            }
          else
            {
              set_head (old_top, (old_size + 2 * SIZE_SZ) | PREV_INUSE);
              set_foot (old_top, (old_size + 2 * SIZE_SZ));
            }
        }
```
设置原`top chunk`的`fencepost`，`fencepost`需要`MINSIZE`大小的内存空间，将该`old_size`减去`MINSIZE`得到原`top chunk`的有效内存空间，首先设置`fencepost`的第二个chunk的size为0，并标识前一个chunk处于inuse状态。接着判断原`top chunk`的有效内存空间上是否大于等于`MINSIZE`，如果是，表示原`top chunk`可以分配出大于等于`MINSIZE`大小的chunk，于是将原`top chunk`切分成空闲chunk和`fencepost`两部分，先设置`fencepost`的第一个chunk的大小为`2*SIZE_SZ`，并标识前一个chunk处于inuse状态，`fencepost`的第一个chunk还需要设置foot，表示该chunk处于空闲状态，而`fencepost`的第二个chunk却标识第一个chunk处于inuse状态，因为不能有两个空闲chunk相邻，才会出现这么奇怪的`fencepost`。另外其实`top chunk`切分出来的chunk也是处于空闲状态，但`fencepost`的第一个chunk却标识前一个chunk为inuse状态，然后强制将该处于inuse状态的chunk调用`_int_free()`函数释放掉。这样做完全是要遵循不能有两个空闲chunk相邻的约定。
如果原`top chunk`中有效空间不足`MINSIZE`，则将整个原`top chunk`作为`fencepost`，并设置`fencepost`的第一个chunk的相关状态。
```c
      else if (!tried_mmap)
        /* We can at least try to use to mmap memory.  */
        goto try_mmap;
    }
  else     /* av == main_arena */


    { /* Request enough space for nb + pad + overhead */
      size = nb + mp_.top_pad + MINSIZE;

      /*
         If contiguous, we can subtract out existing space that we hope to
         combine with new space. We add it back later only if
         we don't actually get contiguous space.
       */

      if (contiguous (av))
        size -= old_size;
```
如果增长`sub_heap`的可读可写区域大小和创建新`sub_heap`都失败了，尝试使用`mmap()`函数直接从系统分配所需chunk。
如果为当前分配区为主分配区，重新计算需要分配的size。
一般情况下，主分配区使用`sbrk()`从heap中分配内存，sbrk()返回连续的虚拟内存，这里调整需要分配的size，减掉`top chunk`中已有空闲内存大小。
```c
      /*
         Round to a multiple of page size.
         If MORECORE is not contiguous, this ensures that we only call it
         with whole-page arguments.  And if MORECORE is contiguous and
         this is not first time through, this preserves page-alignment of
         previous calls. Otherwise, we correct to page-align below.
       */

      size = (size + pagemask) & ~pagemask;
```
将size按照页对齐，`sbrk()`必须以页为单位分配连续虚拟内存。
```c
      /*
         Don't try to call MORECORE if argument is so big as to appear
         negative. Note that since mmap takes size_t arg, it may succeed
         below even if we cannot call MORECORE.
       */

      if (size > 0)
        {
          brk = (char *) (MORECORE (size));
          LIBC_PROBE (memory_sbrk_more, 2, brk, size);
        }

      if (brk != (char *) (MORECORE_FAILURE))
        {
          /* Call the `morecore' hook if necessary.  */
          void (*hook) (void) = atomic_forced_read (__after_morecore_hook);
          if (__builtin_expect (hook != NULL, 0))
            (*hook)();
        }
```
使用`sbrk()`从heap中分配size大小的虚拟内存块。如果`sbrk()`分配成功，并且`morecore`的hook函数存在，调用`morecore`的hook函数。
```c
      else
        {
          /*
             If have mmap, try using it as a backup when MORECORE fails or
             cannot be used. This is worth doing on systems that have "holes" in
             address space, so sbrk cannot extend to give contiguous space, but
             space is available elsewhere.  Note that we ignore mmap max count
             and threshold limits, since the space will not be used as a
             segregated mmap region.
           */

          /* Cannot merge with old top, so add its size back in */
          if (contiguous (av))
            size = (size + old_size + pagemask) & ~pagemask;

          /* If we are relying on mmap as backup, then use larger units */
          if ((unsigned long) (size) < (unsigned long) (MMAP_AS_MORECORE_SIZE))
            size = MMAP_AS_MORECORE_SIZE;

          /* Don't try if size wraps around 0 */
          if ((unsigned long) (size) > (unsigned long) (nb))
            {
              char *mbrk = (char *) (MMAP (0, size, PROT_READ | PROT_WRITE, 0));

              if (mbrk != MAP_FAILED)
                {
                  /* We do not need, and cannot use, another sbrk call to find end */
                  brk = mbrk;
                  snd_brk = brk + size;

                  /*
                     Record that we no longer have a contiguous sbrk region.
                     After the first time mmap is used as backup, we do not
                     ever rely on contiguous space since this could incorrectly
                     bridge regions.
                   */
                  set_noncontiguous (av);
                }
            }
        }
```
如果`sbrk(`)返回失败，或是`sbrk()`不可用，使用`mmap()`代替，重新计算所需分配的内存大小并按页对齐，如果重新计算的size小于1M，将size设为1M，也就是说使用mmap()作为`morecore`函数分配的最小内存块大小为1M。如果所需分配的内存大小合法，使用`mmap()`函数分配内存。如果分配成功，更新brk和snd_brk，并将当前分配区属性设置为可分配不连续虚拟内存块。
```c
      if (brk != (char *) (MORECORE_FAILURE))
        {
          if (mp_.sbrk_base == 0)
            mp_.sbrk_base = brk;
          av->system_mem += size;
```
如果brk合法，即`sbrk()`或`mmap()`分配成功，如果`sbrk_base`还没有初始化，更新`sbrk_base`和当前分配区的内存分配总量。
```c
          /*
             If MORECORE extends previous space, we can likewise extend top size.
           */

          if (brk == old_end && snd_brk == (char *) (MORECORE_FAILURE))
            set_head (old_top, (size + old_size) | PREV_INUSE);

          else if (contiguous (av) && old_size && brk < old_end)
            {
              /* Oops!  Someone else killed our space..  Can't touch anything.  */
              malloc_printerr (3, "break adjusted to free malloc space", brk);
            }
```
如果`sbrk()`分配成功，更新`top chunk`的大小，并设定`top chunk`的前一个chunk处于inuse状态。如果当前分配区可分配连续虚拟内存，原`top chunk`的大小大于0，但新的brk值小于原`top chunk`的结束地址，出错了。
```c
          /*
             Otherwise, make adjustments:

           * If the first time through or noncontiguous, we need to call sbrk
              just to find out where the end of memory lies.

           * We need to ensure that all returned chunks from malloc will meet
              MALLOC_ALIGNMENT

           * If there was an intervening foreign sbrk, we need to adjust sbrk
              request size to account for fact that we will not be able to
              combine new space with existing space in old_top.

           * Almost all systems internally allocate whole pages at a time, in
              which case we might as well use the whole last page of request.
              So we allocate enough more memory to hit a page boundary now,
              which in turn causes future contiguous calls to page-align.
           */

          else
            {
              front_misalign = 0;
              end_misalign = 0;
              correction = 0;
              aligned_brk = brk;
```
执行到这个分支，意味着`sbrk()`返回的brk值大于原`top chunk`的结束地址，那么新的地址与原`top chunk`的地址不连续，可能是由于外部其它地方调用`sbrk()`函数，这里需要处理地址的重新对齐问题
```c
              /* handle contiguous cases */
              if (contiguous (av))
                {
                  /* Count foreign sbrk as system_mem.  */
                  if (old_size)
                    av->system_mem += brk - old_end;
```
如果本分配区可分配连续虚拟内存，并且有外部调用了`sbrk()`函数，将外部调用`sbrk()`分配的内存计入当前分配区所分配内存统计中。
```c
                  /* Guarantee alignment of first new chunk made from this space */

                  front_misalign = (INTERNAL_SIZE_T) chunk2mem (brk) & MALLOC_ALIGN_MASK;
                  if (front_misalign > 0)
                    {
                      /*
                         Skip over some bytes to arrive at an aligned position.
                         We don't need to specially mark these wasted front bytes.
                         They will never be accessed anyway because
                         prev_inuse of av->top (and any chunk created from its start)
                         is always true after initialization.
                       */

                      correction = MALLOC_ALIGNMENT - front_misalign;
                      aligned_brk += correction;
                    }
```
计算当前的brk要矫正的字节数据，保证brk地址按`MALLOC_ALIGNMENT`对齐。
```c
                  /*
                     If this isn't adjacent to existing space, then we will not
                     be able to merge with old_top space, so must add to 2nd request.
                   */

                  correction += old_size;

                  /* Extend the end address to hit a page boundary */
                  end_misalign = (INTERNAL_SIZE_T) (brk + size + correction);
                  correction += ((end_misalign + pagemask) & ~pagemask) - end_misalign;

                  assert (correction >= 0);
                  snd_brk = (char *) (MORECORE (correction));
```
由于原`top chunk`的地址与当前brk不相邻，也就不能再使用原`top chunk`的内存了，需要重新为所需chunk分配足够的内存，将原`top chunk`的大小加到矫正值中，从当前brk中分配所需chunk，计算出未对齐的chunk结束地址`end_misalign`，然后将`end_misalign`按照页对齐计算出需要矫正的字节数加到矫正值上。然后再调用`sbrk()`分配矫正值大小的内存，如果`sbrk()`分配成功，则当前的top chunk中可以分配出所需的连续内存的chunk。
```c
                  /*
                     If can't allocate correction, try to at least find out current
                     brk.  It might be enough to proceed without failing.

                     Note that if second sbrk did NOT fail, we assume that space
                     is contiguous with first sbrk. This is a safe assumption unless
                     program is multithreaded but doesn't use locks and a foreign sbrk
                     occurred between our first and second calls.
                   */

                  if (snd_brk == (char *) (MORECORE_FAILURE))
                    {
                      correction = 0;
                      snd_brk = (char *) (MORECORE (0));
                    }
```
如果`sbrk()`执行失败，更新当前brk的结束地址。
```c
                  else
                    {
                      /* Call the `morecore' hook if necessary.  */
                      void (*hook) (void) = atomic_forced_read (__after_morecore_hook);
                      if (__builtin_expect (hook != NULL, 0))
                        (*hook)();
                    }
                }
```
如果`sbrk(`)执行成功，并且有`morecore hook`函数存在，执行该hook函数。
```c
              /* handle non-contiguous cases */
              else
                {
                  if (MALLOC_ALIGNMENT == 2 * SIZE_SZ)
                    /* MORECORE/mmap must correctly align */
                    assert (((unsigned long) chunk2mem (brk) & MALLOC_ALIGN_MASK) == 0);
                  else
                    {
                      front_misalign = (INTERNAL_SIZE_T) chunk2mem (brk) & MALLOC_ALIGN_MASK;
                      if (front_misalign > 0)
                        {
                          /*
                             Skip over some bytes to arrive at an aligned position.
                             We don't need to specially mark these wasted front bytes.
                             They will never be accessed anyway because
                             prev_inuse of av->top (and any chunk created from its start)
                             is always true after initialization.
                           */

                          aligned_brk += MALLOC_ALIGNMENT - front_misalign;
                        }
                    }

                  /* Find out current end of memory */
                  if (snd_brk == (char *) (MORECORE_FAILURE))
                    {
                      snd_brk = (char *) (MORECORE (0));
                    }
                }
```
执行到这里，意味着brk是用`mmap()`分配的，断言brk一定是按`MALLOC_ALIGNMENT`对齐的，因为`mmap()`返回的地址按页对齐。如果brk的结束地址非法，使用`morecore`获得当前brk的结束地址。
```c
              /* Adjust top based on results of second sbrk */
              if (snd_brk != (char *) (MORECORE_FAILURE))
                {
                  av->top = (mchunkptr) aligned_brk;
                  set_head (av->top, (snd_brk - aligned_brk + correction) | PREV_INUSE);
                  av->system_mem += correction;
```
如果brk的结束地址合法，设置当前分配区的`top chunk`为brk，设置`top chunk`的大小，并更新分配区的总分配内存量。
```c
                  /*
                     If not the first time through, we either have a
                     gap due to foreign sbrk or a non-contiguous region.  Insert a
                     double fencepost at old_top to prevent consolidation with space
                     we don't own. These fenceposts are artificial chunks that are
                     marked as inuse and are in any case too small to use.  We need
                     two to make sizes and alignments work out.
                   */

                  if (old_size != 0)
                    {
                      /*
                         Shrink old_top to insert fenceposts, keeping size a
                         multiple of MALLOC_ALIGNMENT. We know there is at least
                         enough space in old_top to do this.
                       */
                      old_size = (old_size - 4 * SIZE_SZ) & ~MALLOC_ALIGN_MASK;
                      set_head (old_top, old_size | PREV_INUSE);

                      /*
                         Note that the following assignments completely overwrite
                         old_top when old_size was previously MINSIZE.  This is
                         intentional. We need the fencepost, even if old_top otherwise gets
                         lost.
                       */
                      chunk_at_offset (old_top, old_size)->size =
                        (2 * SIZE_SZ) | PREV_INUSE;

                      chunk_at_offset (old_top, old_size + 2 * SIZE_SZ)->size =
                        (2 * SIZE_SZ) | PREV_INUSE;

                      /* If possible, release the rest. */
                      if (old_size >= MINSIZE)
                        {
                          _int_free (av, old_top, 1);
                        }
                    }
                }
            }
        }
    } /* if (av !=  &main_arena) */
```
设置原`top chunk`的`fencepost`，`fencepost`需要`MINSIZE`大小的内存空间，将该`old_size`减去`MINSIZE`得到原`top chunk`的有效内存空间，我们可以确信原`top chunk`的有效内存空间一定大于`MINSIZE`，将原`top chunk`切分成空闲chunk和`fencepost`两部分，首先设置切分出来的chunk的大小为`old_size`，并标识前一个chunk处于inuse状态，原 `top chunk`切分出来的chunk本应处于空闲状态，但`fencepost`的第一个chunk却标识前一个chunk为inuse状态，然后强制将该处于inuse状态的chunk调用`_int_free()`函数释放掉。然后设置`fencepost`的第一个chunk的大小为2*`SIZE_SZ`，并标识前一个chunk处于inuse状态，然后设置`fencepost`的第二个chunk的size为2*`SIZE_SZ`，并标识前一个chunk处于inuse状态。这里的主分配区的`fencepost`与非主分配区的`fencepost`不同，主分配区`fencepost`的第二个chunk的大小设置为2*`SIZE_SZ`，而非主分配区的`fencepost`的第二个chunk的大小设置为0。
```c
  if ((unsigned long) av->system_mem > (unsigned long) (av->max_system_mem))
    av->max_system_mem = av->system_mem;
  check_malloc_state (av);

  /* finally, do the allocation */
  p = av->top;
  size = chunksize (p);

  /* check that one of the above allocation paths succeeded */
  if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
    {
      remainder_size = size - nb;
      remainder = chunk_at_offset (p, nb);
      av->top = remainder;
      set_head (p, nb | PREV_INUSE | (av != &main_arena ? NON_MAIN_ARENA : 0));
      set_head (remainder, remainder_size | PREV_INUSE);
      check_malloced_chunk (av, p, nb);
      return chunk2mem (p);
    }

  /* catch all failure paths */
  __set_errno (ENOMEM);
  return 0;
}

```
如果当前分配区所分配的内存量大于设置的最大值，更新当前分配区最大分配的内存量，如果当前`top chunk`中已经有足够的内存来分配所需的chunk，从当前的`top chunk`中分配所需的chunk并返回。
### malloc_consolidate
```c
static void malloc_consolidate(mstate av)
{
  mfastbinptr*    fb;                 /* current fastbin being consolidated */
  mfastbinptr*    maxfb;              /* last fastbin (for loop control) */
  mchunkptr       p;                  /* current chunk being consolidated */
  mchunkptr       nextp;              /* next chunk to consolidate */
  mchunkptr       unsorted_bin;       /* bin header */
  mchunkptr       first_unsorted;     /* chunk to link to */

  /* These have same use as in free() */
  mchunkptr       nextchunk;
  INTERNAL_SIZE_T size;
  INTERNAL_SIZE_T nextsize;
  INTERNAL_SIZE_T prevsize;
  int             nextinuse;
  mchunkptr       bck;
  mchunkptr       fwd;

  /*
    If max_fast is 0, we know that av hasn't
    yet been initialized, in which case do so below
  */

  if (get_max_fast () != 0) {
    clear_fastchunks(av);

    unsorted_bin = unsorted_chunks(av);

    /*
      Remove each chunk from fast bin and consolidate it, placing it
      then in unsorted bin. Among other reasons for doing this,
      placing in unsorted bin avoids needing to calculate actual bins
      until malloc is sure that chunks aren't immediately going to be
      reused anyway.
    */

    maxfb = &fastbin (av, NFASTBINS - 1);
    fb = &fastbin (av, 0);
```
将分配区最大的一个`fast bin`赋值给`maxfb`，第一个`fast bin`赋值给fb，然后遍历`fast bins`。
```c
    do {
      p = atomic_exchange_acq (fb, 0);
      if (p != 0) {
	do {
	  check_inuse_chunk(av, p);
	  nextp = p->fd;
```
将空闲chunk链表的下一个chunk赋值给`nextp`。
```c
	  /* Slightly streamlined version of consolidation code in free() */
	  size = p->size & ~(PREV_INUSE|NON_MAIN_ARENA);
	  nextchunk = chunk_at_offset(p, size);
	  nextsize = chunksize(nextchunk);
```
获得当前chunk的size，需要去除size中的`PREV_INUSE`和`NON_MAIN_ARENA`标志，并获取相邻的下一个chunk和下一个chunk的大小。
```c
	  if (!prev_inuse(p)) {
	    prevsize = p->prev_size;
	    size += prevsize;
	    p = chunk_at_offset(p, -((long) prevsize));
	    unlink(p, bck, fwd);
	  }
```
如果当前chunk的前一个chunk空闲，则将当前chunk与前一个chunk合并成一个空闲chunk，由于前一个chunk空闲，则当前chunk的`prev_size`保存了前一个chunk的大小，计算出合并后的chunk大小，并获取前一个chunk的指针，将前一个chunk从空闲链表中删除。
```c
	  if (nextchunk != av->top) {
	    nextinuse = inuse_bit_at_offset(nextchunk, nextsize);
```
如果与当前chunk相邻的下一个chunk不是分配区的`top chunk`，查看与当前chunk相邻的下一个chunk是否处于inuse状态。
```c
	    if (!nextinuse) {
	      size += nextsize;
	      unlink(nextchunk, bck, fwd);
	    } else
	      clear_inuse_bit_at_offset(nextchunk, 0);

	    first_unsorted = unsorted_bin->fd;
	    unsorted_bin->fd = p;
	    first_unsorted->bk = p;
```
如果与当前chunk相邻的下一个chunk处于inuse状态，清除当前chunk的inuse状态，则当前chunk空闲了。否则，将相邻的下一个空闲chunk从空闲链表中删除，并计算当前chunk与下一个chunk合并后的chunk大小。将合并后的chunk加入`unsorted bin`的双向循环链表中。
```c
	    if (!in_smallbin_range (size)) {
	      p->fd_nextsize = NULL;
	      p->bk_nextsize = NULL;
	    }
```
如果合并后的chunk属于large bin，将chunk的`fd_nextsize`和`bk_nextsize`设置为NULL，因为在`unsorted bin`中这两个字段无用。
```c
	    set_head(p, size | PREV_INUSE);
	    p->bk = unsorted_bin;
	    p->fd = first_unsorted;
	    set_foot(p, size);
	  }
```
设置合并后的空闲chunk大小，并标识前一个chunk处于inuse状态，因为必须保证不能有两个相邻的chunk都处于空闲状态。然后将合并后的chunk加入`unsorted bin`的双向循环链表中。最后设置合并后的空闲chunk的foot，chunk空闲时必须设置foot，该foot处于下一个chunk的`prev_size`中，只有chunk空闲是foot才是有效的。
```c
	  else {
	    size += nextsize;
	    set_head(p, size | PREV_INUSE);
	    av->top = p;
	  }
```
如果当前chunk的下一个chunk为`top chunk`，则将当前chunk合并入`top chunk`，修改`top chunk`的大小。
```c
	} while ( (p = nextp) != 0);
```
直到遍历完当前`fast bin`中的所有空闲chunk。
```c
      }
    } while (fb++ != maxfb);
  }
```
直到遍历完所有的fast bins。
```c
  else {
    malloc_init_state(av);
    check_malloc_state(av);
  }
}
```
如果`ptmalloc`没有初始化，初始化`ptmalloc`。
### __libc_free
```c
void
__libc_free (void *mem)
{
  mstate ar_ptr;
  mchunkptr p;                          /* chunk corresponding to mem */

  void (*hook) (void *, const void *)
    = atomic_forced_read (__free_hook);
  if (__builtin_expect (hook != NULL, 0))
    {
      (*hook)(mem, RETURN_ADDRESS (0));
      return;
    }
```
同样，这里检查了用户是否实现自定义的`__free_hook`。
```c
  if (mem == 0)                              /* free(0) has no effect */
    return;

  p = mem2chunk (mem);

  if (chunk_is_mmapped (p))                       /* release mmapped memory. */
    {
      /* see if the dynamic brk/mmap threshold needs adjusting */
      if (!mp_.no_dyn_threshold
          && p->size > mp_.mmap_threshold
          && p->size <= DEFAULT_MMAP_THRESHOLD_MAX)
        {
          mp_.mmap_threshold = chunksize (p);
          mp_.trim_threshold = 2 * mp_.mmap_threshold;
          LIBC_PROBE (memory_mallopt_free_dyn_thresholds, 2,
                      mp_.mmap_threshold, mp_.trim_threshold);
        }
      munmap_chunk (p);
      return;
    }
```
如果当前free的chunk是通过`mmap()`分配的，调用`munmap_chunk()`函数unmap本chunk。`munmap_chunk()`函数调用`munmap()`函数释放`mmap()`分配的内存块。同时查看是否开启了mmap分配阈值动态调整机制，默认是开启的，如果当前free的chunk的大小大于设置的mmap分配阈值，小于mmap分配阈值的最大值，将当前chunk的大小赋值给mmap分配阈值，并修改mmap收缩阈值为mmap分配阈值的2倍。默认情况下mmap分配阈值与mmap收缩阈值相等，都为128KB。
```c
  ar_ptr = arena_for_chunk (p);
  _int_free (ar_ptr, p, 0);
}
```
获取当前分配区指针，最后调用`_int_free`。
### _int_free
```c
static void
_int_free (mstate av, mchunkptr p, int have_lock)
{
  INTERNAL_SIZE_T size;        /* its size */
  mfastbinptr *fb;             /* associated fastbin */
  mchunkptr nextchunk;         /* next contiguous chunk */
  INTERNAL_SIZE_T nextsize;    /* its size */
  int nextinuse;               /* true if nextchunk is used */
  INTERNAL_SIZE_T prevsize;    /* size of previous contiguous chunk */
  mchunkptr bck;               /* misc temp for linking */
  mchunkptr fwd;               /* misc temp for linking */

  const char *errstr = NULL;
  int locked = 0;

  size = chunksize (p);
```
获取其chunk size
```c
  /* Little security check which won't hurt performance: the
     allocator never wrapps around at the end of the address space.
     Therefore we can exclude some size values which might appear
     here by accident or by "design" from some intruder.  */
  if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)
      || __builtin_expect (misaligned_chunk (p), 0))
    {
      errstr = "free(): invalid pointer";
    errout:
      if (!have_lock && locked)
        (void) mutex_unlock (&av->mutex);
      malloc_printerr (check_action, errstr, chunk2mem (p));
      return;
    }
  /* We know that each chunk is at least MINSIZE bytes in size or a
     multiple of MALLOC_ALIGNMENT.  */
  if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size)))
    {
      errstr = "free(): invalid size";
      goto errout;
    }

  check_inuse_chunk(av, p);
```
上面的代码用于安全检查，chunk的指针地址不能溢出，chunk的大小必须大于等于`MINSIZE`且要求对齐。
```c
  /*
    If eligible, place chunk on a fastbin so it can be found
    and used quickly in malloc.
  */

  if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())

#if TRIM_FASTBINS
      /*
	If TRIM_FASTBINS set, don't place chunks
	bordering top into fastbins
      */
      && (chunk_at_offset(p, size) != av->top)
#endif
      ) {

    if (__builtin_expect (chunk_at_offset (p, size)->size <= 2 * SIZE_SZ, 0)
	|| __builtin_expect (chunksize (chunk_at_offset (p, size))
			     >= av->system_mem, 0))
      {
	/* We might not have a lock at this point and concurrent modifications
	   of system_mem might have let to a false positive.  Redo the test
	   after getting the lock.  */
	if (have_lock
	    || ({ assert (locked == 0);
		  mutex_lock(&av->mutex);
		  locked = 1;
		  chunk_at_offset (p, size)->size <= 2 * SIZE_SZ
		    || chunksize (chunk_at_offset (p, size)) >= av->system_mem;
	      }))
	  {
	    errstr = "free(): invalid next size (fast)";
	    goto errout;
	  }
	if (! have_lock)
	  {
	    (void)mutex_unlock(&av->mutex);
	    locked = 0;
	  }
      }
```
如果当前free的chunk属于`fast bins`，查看下一个相邻的chunk的大小是否小于等于2*`SIZE_SZ`，下一个相邻chunk的大小是否大于分配区所分配的内存总量，如果是，报错。这里计算下一个相邻chunk的大小似乎有点问题，因为chunk的size字段中包含了一些标志位，正常情况下下一个相邻chunk的size中的`PREV_INUSE`标志位会置位，但这里就是要检出错的情况，也就是下一个相邻chunk的size中标志位都没有置位，并且该chunk大小为2*`SIZE_SZ`的错误情况。如果调用本函数前没有对分配区加锁， 所以读取分配区所分配的内存总量需要对分配区加锁，检查完以后，释放分配区的锁。
```c
    free_perturb (chunk2mem(p), size - 2 * SIZE_SZ);

    set_fastchunks(av);
    unsigned int idx = fastbin_index(size);
    fb = &fastbin (av, idx);
```
设置当前分配区的`fast bin flag`，表示当前分配区的`fast bins`中已有空闲chunk。然后根据当前free的chunk大小获取所属的`fast bin`。
```c
    /* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */
    mchunkptr old = *fb, old2;
    unsigned int old_idx = ~0u;
    do
      {
	/* Check that the top of the bin is not the record we are going to add
	   (i.e., double free).  */
	if (__builtin_expect (old == p, 0))
	  {
	    errstr = "double free or corruption (fasttop)";
	    goto errout;
	  }
	/* Check that size of fastbin chunk at the top is the same as
	   size of the chunk that we are adding.  We can dereference OLD
	   only if we have the lock, otherwise it might have already been
	   deallocated.  See use of OLD_IDX below for the actual check.  */
	if (have_lock && old != NULL)
	  old_idx = fastbin_index(chunksize(old));
	p->fd = old2 = old;
      }
    while ((old = catomic_compare_and_exchange_val_rel (fb, p, old2)) != old2);

    if (have_lock && old != NULL && __builtin_expect (old_idx != idx, 0))
      {
	errstr = "invalid fastbin entry (free)";
	goto errout;
      }
  }
```
这里检查了当前释放的chunk和之前释放的`fastbin chunk`是否相同，相同则触发了`double free`，校验表头不为NULL情况下，保证表头chunk的所属的`fast bin`与当前free的chunk所属的`fast bin`相同。
```c
  /*
    Consolidate other non-mmapped chunks as they arrive.
  */

  else if (!chunk_is_mmapped(p)) {
    if (! have_lock) {
      (void)mutex_lock(&av->mutex);
      locked = 1;
    }

    nextchunk = chunk_at_offset(p, size);
```
如果当前free的chunk不是通过`mmap()`分配的，并且当前还没有获得分配区的锁，获取分配区的锁。
```c
    /* Lightweight tests: check whether the block is already the
       top block.  */
    if (__glibc_unlikely (p == av->top))
      {
	errstr = "double free or corruption (top)";
	goto errout;
      }
    /* Or whether the next chunk is beyond the boundaries of the arena.  */
    if (__builtin_expect (contiguous (av)
			  && (char *) nextchunk
			  >= ((char *) av->top + chunksize(av->top)), 0))
      {
	errstr = "double free or corruption (out)";
	goto errout;
      }
    /* Or whether the block is actually not marked used.  */
    if (__glibc_unlikely (!prev_inuse(nextchunk)))
      {
	errstr = "double free or corruption (!prev)";
	goto errout;
      }

    nextsize = chunksize(nextchunk);
    if (__builtin_expect (nextchunk->size <= 2 * SIZE_SZ, 0)
	|| __builtin_expect (nextsize >= av->system_mem, 0))
      {
	errstr = "free(): invalid next size (normal)";
	goto errout;
      }

    free_perturb (chunk2mem(p), size - 2 * SIZE_SZ);
```
一系列的安全检查，当前free的chunk不能为`top chunk`，因为`top chunk`为空闲chunk，如果再次free就可能为`double free`错误了。
如果当前free的chunk是通过`sbrk()`分配的，并且下一个相邻的chunk的地址已经超过了top chunk的结束地址，超过了当前分配区的结束地址，报错。
如果当前free的chunk的下一个相邻chunk的size中标志位没有标识当前`free chunk`为inuse状态，可能为`double free`错误。
计算当前free的chunk的下一个相邻chunk的大小，该大小如果小于等于2*`SIZE_SZ`或是大于了分配区所分配区的内存总量，报错。
```c
    /* consolidate backward */
    if (!prev_inuse(p)) {
      prevsize = p->prev_size;
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      unlink(p, bck, fwd);
    }

    if (nextchunk != av->top) {
      /* get and clear inuse bit */
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

      /* consolidate forward */
      if (!nextinuse) {
	unlink(nextchunk, bck, fwd);
	size += nextsize;
      } else
	clear_inuse_bit_at_offset(nextchunk, 0);
```
前向合并与后向合并
```c
      /*
	Place the chunk in unsorted chunk list. Chunks are
	not placed into regular bins until after they have
	been given one chance to be used in malloc.
      */

      bck = unsorted_chunks(av);
      fwd = bck->fd;
      if (__glibc_unlikely (fwd->bk != bck))
	{
	  errstr = "free(): corrupted unsorted chunks";
	  goto errout;
	}
      p->fd = fwd;
      p->bk = bck;
      if (!in_smallbin_range(size))
	{
	  p->fd_nextsize = NULL;
	  p->bk_nextsize = NULL;
	}
      bck->fd = p;
      fwd->bk = p;

      set_head(p, size | PREV_INUSE);
      set_foot(p, size);

      check_free_chunk(av, p);
    }
```
合并后的chunk加入到`unsorted bin`的双向链表中。如果合并后的chunk属于`large bins`，将chunk的`fd_nextsize`和`bk_nextsize`设置为NULL，因为在`unsorted bin`中这两个字段无用。
设置合并后的空闲chunk大小，并标识前一个chunk处于inuse状态，因为必须保证不能有两个相邻的chunk都处于空闲状态。然后将合并后的chunk加入`unsorted bin`的双向循环链表中。最后设置合并后的空闲chunk的foot，chunk空闲时必须设置foot，该foot处于下一个chunk的`prev_size`中，只有chunk空闲是foot才是有效的。
```c
    /*
      If the chunk borders the current high end of memory,
      consolidate into top
    */

    else {
      size += nextsize;
      set_head(p, size | PREV_INUSE);
      av->top = p;
      check_chunk(av, p);
    }
```
如果当前chunk与`top chunk`相邻则要将其合并入`top chunk`，并修改`top chunk`的大小。
```c
    /*
      If freeing a large space, consolidate possibly-surrounding
      chunks. Then, if the total unused topmost memory exceeds trim
      threshold, ask malloc_trim to reduce top.

      Unless max_fast is 0, we don't know if there are fastbins
      bordering top, so we cannot tell for sure whether threshold
      has been reached unless fastbins are consolidated.  But we
      don't want to consolidate on each free.  As a compromise,
      consolidation is performed if FASTBIN_CONSOLIDATION_THRESHOLD
      is reached.
    */

    if ((unsigned long)(size) >= FASTBIN_CONSOLIDATION_THRESHOLD) {
      if (have_fastchunks(av))
	malloc_consolidate(av);
```
如果合并后的chunk大小大于64KB，并且`fast bins`中存在空闲chunk，调用`malloc_consolidate()`函数合并`fast bins`中的空闲chunk到`unsorted bin`中。
```c
      if (av == &main_arena) {
#ifndef MORECORE_CANNOT_TRIM
	if ((unsigned long)(chunksize(av->top)) >=
	    (unsigned long)(mp_.trim_threshold))
	  systrim(mp_.top_pad, av);
```
如果当前分配区为主分配区，并且`top chunk`的大小大于heap的收缩阈值，调用`systrim()`函数首先heap。
```c
#endif
      } else {
	/* Always try heap_trim(), even if the top chunk is not
	   large, because the corresponding heap might go away.  */
	heap_info *heap = heap_for_ptr(top(av));

	assert(heap->ar_ptr == av);
	heap_trim(heap, mp_.top_pad);
      }
    }
```
如果为非主分配区，调用`heap_trim()`函数收缩非主分配区的`sub_heap`。
```c
    if (! have_lock) {
      assert (locked);
      (void)mutex_unlock(&av->mutex);
    }
  }
  /*
    If the chunk was allocated via mmap, release via munmap().
  */

  else {
    munmap_chunk (p);
  }
}
```
如果当前free的chunk是通过`mmap()`分配的，调用`munma_chunk()`释放内存。

## End
到这里，malloc的只要框架与逻辑就分析完了。在很多难懂得地方都参考了《ptmalloc源码分析》，推荐读一下。不过想要深入的理解堆的话，还是要自己动手实现一个内存分配器。这样才能知道哪一部分是要干什么的，也能更好的理解源码。这次仅仅是glibc-2.20，在新的glibc中有了新的机制，这部分在之后进行补充分析。