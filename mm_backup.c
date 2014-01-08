/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 * 
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  Only a header is stored with the size to allow
 * for realloc() to retrieve the block size.  Blocks are never coalesced 
 * or reused in this naive implementation. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>

#include "list.h"
#include "mm.h"
#include "memlib.h"
#include "config.h"             /* defines ALIGNMENT */

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 ********************************************************/
team_t team = {
    /* Team name */
    "Sematizers",
    /* First member's full name */
    "Ryan Merkel",
    /* First member's SLO (@cs.vt.edu) email address */
    "orionf22",
    /* Second member's full name (leave blank if none) */
    "Patrick Lewis",
    /* Second member's SLO (@cs.vt.edu) email address (leave blank if none) */
    "patl1"
};


/* 
 * If size is a multiple of ALIGNMENT, return size.
 * Else, return next larger multiple of ALIGNMENT:
 * (size/ALIGNMENT + 1) * ALIGNMENT
 * Does so without requiring integer division, assuming
 * ALIGNMENT is a power of 2.
 */
static size_t roundup(size_t size)
{
    return (size + ALIGNMENT - 1) & ~(ALIGNMENT - 1);
}

struct boundary_tag
{
	unsigned inuse:1;
	unsigned size:31;
};

#define MIN_BLOCK_SIZE_BYTES 24 

/* 
 * This C struct captures an allocated header.
 *
 * By casting a memory location to a pointer to a block,
 * we are able to treat a part of memory as if a header had been allocated
 * in it.
 *
 * Note: you should never define instances of 'struct block' -
 *       all accesses will be through pointers.
 */
struct block 
{
    struct boundary_tag header;
	struct list_elem	elem;
    /* 
     * Zero length arrays do not add size to the structure, they simply
     * provide a syntactic form to refer to a char array following the
     * structure.
     * See http://gcc.gnu.org/onlinedocs/gcc/Zero-Length.html
     *
     * The 'aligned' attribute forces 'payload' to be aligned at a
     * multiple of alignment, counted from the beginning of the struct
     * See http://gcc.gnu.org/onlinedocs/gcc/Variable-Attributes.html
     */
    char        payload[0] __attribute__((aligned(ALIGNMENT)));
};

const struct boundary_tag HEAD_FENCE = {.size = 0, .inuse = 1};
const struct boundary_tag TAIL_FENCE = {.size = 0, .inuse = 1};

//the explicit freelist for managing free blocks in memory
struct list freelist;

static struct boundary_tag * prev_blk_footer(struct block *blk);
static struct block * prev_blk(struct block *blk);
static struct block * next_blk(struct block *blk);
static bool blk_free(struct block *blk);
static size_t blk_size(struct block *blk);
static struct boundary_tag * get_footer(struct block *blk);
static void set_header_and_footer(struct block *blk, int size, int inuse);
static void mark_block_used(struct block *blk, int size);
static void mark_block_free(struct block *blk, int size);
static struct block *coalesce(struct block *blk);
//static void split(struct block *blk, size_t size);
void printheap();

/* Given a block, obtain previous's block footer.
   Works for left-most block also. */
static struct boundary_tag * prev_blk_footer(struct block *blk) 
{
    return &blk->header - 1;
}

/* Return if block is free */
static bool blk_free(struct block *blk) 
{ 
    return !blk->header.inuse; 
}

/* Return size of block is free */
static size_t blk_size(struct block *blk) 
{ 
    return blk->header.size; 
}

/* Given a block, obtain pointer to previous block.
   Not meaningful for left-most block. */
static struct block *prev_blk(struct block *blk) 
{
    struct boundary_tag *prevfooter = prev_blk_footer(blk);
    //assert(prevfooter->size != 0);
    return (struct block *)((size_t *)blk - prevfooter->size);
}

/* Given a block, obtain pointer to next block.
   Not meaningful for right-most block. */
static struct block *next_blk(struct block *blk) 
{
    assert(blk_size(blk) != 0);
    return (struct block *)((size_t *)blk + blk->header.size);
}

/* Given a block, obtain its footer boundary tag */
static struct boundary_tag * get_footer(struct block *blk) 
{
    return (void *)((size_t *)blk + blk->header.size) 
                   - sizeof(struct boundary_tag);
}

/* Set a block's size and inuse bit in header and footer */
static void set_header_and_footer(struct block *blk, int size, int inuse) 
{
    blk->header.inuse = inuse;
    blk->header.size = size;
    * get_footer(blk) = blk->header;    /* Copy header to footer */
}

/* Mark a block as used and set its size. */
static void mark_block_used(struct block *blk, int size) 
{
    printf("called for %p, with %d\n", blk, size);
    set_header_and_footer(blk, size, 1);
}

/* Mark a block as free and set its size. */
static void mark_block_free(struct block *blk, int size) 
{
    set_header_and_footer(blk, size, 0);
}

/* 
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{
    /* Sanity checks. */
    assert((ALIGNMENT & (ALIGNMENT - 1)) == 0); // power of 2
    ///assert(sizeof(struct block) == ALIGNMENT);
    //assert(offsetof(struct block, size) == 0);
    //assert(offsetof(struct block, payload) % ALIGNMENT == 0);
	list_init(&freelist);
	struct boundary_tag * initial = mem_sbrk(2 * sizeof(struct boundary_tag));
	initial[0] = HEAD_FENCE;
	initial[1] = TAIL_FENCE;
    //printheap();
    return 0;
}

void printheap()
{
    printf("----\t\tprintheap\t\t----\n");
	void * addr = mem_heap_lo();
	struct block * curr = (struct block *) (addr + sizeof(struct boundary_tag));
	void * high = mem_heap_hi();
	while (addr <= high)
	{
		size_t size = blk_size(curr);
		if ((addr == mem_heap_lo()) || (addr == (mem_heap_hi()-sizeof(struct boundary_tag))))
		{ 
            struct boundary_tag * tag = (struct boundary_tag *) addr;
            printf("Block: %p;\t FENCE;\t in use: %d\n", addr, tag->inuse);
			size = sizeof(struct boundary_tag);
		}
        else
        {
		    curr = (struct block *) (addr);
		    printf("Block %p;\t size: %d;\t payload: %p;\t", curr, blk_size(curr), curr->payload);
		    if((curr->header).inuse == 1) printf("in use\n");
		    else printf("free \n");
        }
		addr += size;
	}
}

/* 
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void *mm_malloc(size_t size)
{
	if (size == 0)
	{
		return NULL;
	}
    size_t newsize = roundup(size + sizeof(struct block));
	//if the freelist is empty then there is no free space available
    //printheap();
	if (list_empty(&freelist))
	{

       // printf("before\n");
    	struct boundary_tag * tag = mem_sbrk(newsize);
    	if (tag == NULL)
		{
			return NULL;
		}
       // printf("tag = %p\n", tag);
        tag = tag - (sizeof(struct boundary_tag)/4);
        struct boundary_tag * tail = (struct boundary_tag*)(mem_heap_hi() - sizeof(struct boundary_tag));
        *tail = TAIL_FENCE;
        
        tail->size = 0;
        tail->inuse = 1;
        struct block * blk = (struct block *) tag;
	    mark_block_used(blk, newsize);
      //  printf("heap_lo: %p\t heap_hi: %p\t blk: %p\t size: %zu", mem_heap_lo(), mem_heap_hi(), blk, newsize);
      //  printheap();
      //  printf("size of new block: %zu.\t done doing stuff\n", blk_size(blk));
    //	exit(0);
        return blk->payload;
	}
	struct list_elem * i;
	struct block * current;
	//iterate through freelist to find a block large enough to satisfy the request
	for (i = list_begin(&freelist); i != list_end(&freelist); i = list_next(i))
	{
		current = list_entry(i, struct block, elem);
		//block has sufficient space
		size_t csize = blk_size(current);
		if (csize >= newsize && blk_free(current))
		{
			list_remove(&current->elem);
	     	mark_block_used(current, csize);
     //       printheap();
			return current->payload;
		}
	}
	//space is in the freelist, but not enough for the request. allocate more
    struct boundary_tag * tag = mem_sbrk(newsize);
    if (tag == NULL)
	{
		return NULL;
	}
    tag = tag - sizeof(TAIL_FENCE);
    struct boundary_tag * tail = (struct boundary_tag*)(mem_heap_hi() - sizeof(TAIL_FENCE) + 1);
    *tail = TAIL_FENCE;
    struct block * blk = (struct block *) tag;
    mark_block_used(blk, newsize);
	if (1 == 0)
	{
		coalesce(blk);
	}
    //printheap();
   	return blk->payload;
}

//static void split(struct block *blk, size_t size)
//{
//	size_t csize = blk_size(blk);
//	if ((csize - size) >= MIN_BLOCK_SIZE_BYTES)
//	{
//		mark_block_used(blk, size);
//        blk = next_blk(blk);
//		mark_block_free(blk, csize - size);
//		list_push_front(&freelist, &blk->elem);
//		printf("splitting: %p, csize: %d, newsize: %d, c-n: %d size: %d\n", 
//			blk, csize, size, csize - size, blk_size(blk));
//	}
//	else
//	{
//		mark_block_used(blk, csize);
//	}
//}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *ptr)
{
	if (ptr == NULL)
	{
		return;
	}

	struct block * curr = ptr - offsetof(struct block, payload);
	mark_block_free(curr, blk_size(curr));
	list_push_front(&freelist, &curr->elem);
}

static struct block * coalesce(struct block *blk)
{
	printf("Coalescing...\n");
	bool leftFree = !prev_blk_footer(blk)->inuse;
	bool rightFree = next_blk(blk)->header.inuse;
	struct block * right = next_blk(blk);
	//combine left, this, and right blocks into one; starts at left's start, has size of
	//left + this + right
	if (leftFree && rightFree)
	{
		struct block *left = prev_blk(blk);
		list_remove(&left->elem);
		list_remove(&right->elem);
		mark_block_used(left, blk_size(blk) + blk_size(left) + blk_size(right));
		list_push_front(&freelist, &left->elem);
		return left;
	}
	//combine left and this into one; starts at left's start, has size of left + this
	else if (leftFree && !rightFree)
	{
		struct block *left = prev_blk(blk);
		list_remove(&left->elem);
		mark_block_used(left, blk_size(blk) + blk_size(left));
		list_push_front(&freelist, &left->elem);
		return left;
	}
	//combine right and this into one; starts at this guy's start, size of this + right
	else if (!leftFree && rightFree)
	{
		list_remove(&right->elem);
		mark_block_used(right, blk_size(blk) + blk_size(right));
		list_push_front(&freelist, &blk->elem);
		return blk;
	}
	//no free adjacent blocks; simply insert this one
	else
	{
		mark_block_used(blk, blk_size(blk));
		list_push_front(&freelist, &blk->elem);
		return blk;
	}
}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void *mm_realloc(void *oldptr, size_t size)
{
    printheap();
    printf("Reallocate %zu bytes. \t", size);
    void *newptr = mm_malloc(size);
    if (newptr == NULL) return NULL;
    struct block *newblk = newptr - offsetof(struct block, payload);
    /* Assuming 'oldptr' was a '&payload[0]' in an block,
     * determine its start as 'oldblk'.  Then its size can be accessed
     * more easily.
     */
    struct block *oldblk;
    oldblk = oldptr - offsetof(struct block, payload);

    size_t copySize = blk_size(oldblk); //account for size of struct block
    if (size < copySize) copySize = size;

    printf("Had %zu bytes, now have %zu bytes.\t", blk_size(oldblk),blk_size(newblk));
    printf("Copying %zu bytes to new memory...\n", copySize);
    memcpy(newptr, oldptr, copySize);
    mm_free(oldptr);
    printheap();
    printf("%p reallocated to %p\n", oldblk, newblk);
    return newptr;
}
