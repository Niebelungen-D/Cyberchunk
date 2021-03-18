---
title: Heap-unlink
date: 2021-01-17 12:52:23
tags: 
 - PWN
 - CTF
 - Heap
categories: "PWN"
banner_img: /pic/unlink.png
---

# unlink

<!-- more -->

```c
/* Take a chunk off a bin list */
// unlink p
#define unlink(AV, P, BK, FD) {                                            
    if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      
      malloc_printerr ("corrupted size vs. prev_size");               
    FD = P->fd;                                                                      
    BK = P->bk;                                                                      
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);  
    else {                                                                      
        FD->bk = BK;                                                              
        BK->fd = FD;                                                              
        if (!in_smallbin_range (chunksize_nomask (P))                              
            && __builtin_expect (P->fd_nextsize != NULL, 0)) {                      
            if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)              
                || __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    
              malloc_printerr (check_action,                                      
                               "corrupted double-linked list (not small)",    
                               P, AV);                                              
            if (FD->fd_nextsize == NULL) {                                      
                if (P->fd_nextsize == P)                                      
                  FD->fd_nextsize = FD->bk_nextsize = FD;                      
                else {                                                              
                    FD->fd_nextsize = P->fd_nextsize;                              
                    FD->bk_nextsize = P->bk_nextsize;                              
                    P->fd_nextsize->bk_nextsize = FD;                              
                    P->bk_nextsize->fd_nextsize = FD;                              
                  }                                                              
              } else {                                                              
                P->fd_nextsize->bk_nextsize = P->bk_nextsize;                      
                P->bk_nextsize->fd_nextsize = P->fd_nextsize;                      
              }                                                                      
          }                                                                      
      }                                                                              
}
```

unlink适用于small bin，且在最新的libc2.27及以上中，加入了新的机制，该攻击不再那么适用。但是对于该技巧的学习，有助于更好的理解堆操作。



