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

/* 
 * This C struct captures an allocated header.
 *
 * By casting a memory location to a pointer to a allocated_block_header,
 * we are able to treat a part of memory as if a header had been allocated
 * in it.
 *
 * Note: you should never define instances of 'struct allocated_block_header' -
 *       all accesses will be through pointers.
 */
struct allocated_block_header {
    size_t      size;

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
	struct list_elem	elem;
};

//the explicit freelist for managing free blocks in memory
struct list freelist;
struct list allocatedList;

/* 
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{
    /* Sanity checks. */
    assert((ALIGNMENT & (ALIGNMENT - 1)) == 0); // power of 2
    ///assert(sizeof(struct allocated_block_header) == ALIGNMENT);
    //assert(offsetof(struct allocated_block_header, size) == 0);
    //assert(offsetof(struct allocated_block_header, payload) % ALIGNMENT == 0);
	list_init(&freelist);
	struct allocated_block_header * firstBlock;
	firstBlock->size = mem_heapsize();
	//firstBlock->payload = mem_heap_lo();
	list_push_front(&freelist, &firstBlock->elem);
	list_init(&allocatedList);
	printf("end init\n");
    return 0;
}

/* 
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void *mm_malloc(size_t size)
{
    int newsize = roundup(size + sizeof(struct allocated_block_header));
	//if the freelist is empty then there is no free space available
	if (list_empty(&freelist))
	{	
		printf("freelist empty\n");
    	struct allocated_block_header * blk = mem_sbrk(newsize);
    	if (blk == NULL)
		{
			return NULL;
		}
	    blk->size = size;
		list_push_back(&allocatedList, &blk->elem);
    	return blk->payload;
	}
	printf("freelist not empty\n");
	struct list_elem * i;
	struct allocated_block_header * current;
	//iterate through freelist to find a block large enough to satisfy the request
	for (i = list_head(&freelist); i != list_end(&freelist); i = list_next(i))
	{
		current = list_entry(i, struct allocated_block_header, elem);
		if (current->size >= newsize)
		{
			list_remove(&current->elem);
			void * ret = current->payload;
			size_t insertSize = current->size - size;
			printf("found block\n");
			if (insertSize > 0)
			{
				printf("extras\n");
				current->size = size;
				struct allocated_block_header * leftover = current + size;
				leftover->payload[0] = current->payload[0] + size;
				leftover->size = insertSize;
				list_push_back(&freelist, &leftover->elem);
			}
			list_push_back(&allocatedList, &current->elem);
			return ret;
		}
	}
	printf("need moar space!\n");
	//space is in the freelist, but not enough for the request. allocate more
	struct allocated_block_header * blk = mem_sbrk(newsize);
    if (blk == NULL)
	{
		printf("no moar space!\n");
		return NULL;
	}
	blk->size = size;
	list_push_back(&allocatedList, &blk->elem);
    return blk->payload;
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *ptr)
{
	printf("free\n");
	//ptr points to a memblock or something...put it back in the free list after clearing it out
	//see FreeBlockList.java
	size_t currSize;
	int valid = 0;
	struct allocated_block_header * curr;
	struct list_elem * e;
	for (e = list_head(&allocatedList); e != list_end(&allocatedList); e = list_next(e))
	{
		curr = list_entry(e, struct allocated_block_header, elem);
		printf("examining block\n");
		if (curr->payload == ptr)
		{
			valid = 1;
			break;
		}
	}
	//if ptr doesn't point to a previously allocated block
	if (!valid)	
	{
		printf("invalid\n");
		return;
	}

	struct list_elem * i;
	//address of block we want to free
	void * freeAddress = curr->payload;
	//boundary with a potential free block to the right of the block we're inserting
	void * rightSum = freeAddress + curr->size + sizeof(struct allocated_block_header);
	//boundary with a potential free block to the left of the block we're inserting
	void * leftSum;
	struct allocated_block_header * left = NULL;
	struct allocated_block_header * right = NULL;
	for (i = list_head(&freelist); i != list_end(&freelist); i = list_next(i))
	{
		struct allocated_block_header * block = ptr - offsetof(struct allocated_block_header, payload);
		printf("examining block for reclamation\n");
		//size of potential adjacent block
		size_t size = block->size;
		//ptr to payload of potential adjacent block
		void * blockPtr = block->payload;
		leftSum = blockPtr + size + sizeof(struct allocated_block_header);
		if (rightSum == blockPtr)
		{
			list_remove(&block->elem);
			right = block;
		}
		else if (leftSum == ptr)
		{
			list_remove(&block->elem);
			left = block;
		}
	}
	void * start = ptr;
	size_t size = currSize;
	//if left is not null, there is a left-adjacent block. the new block
	//must address here, and the size will be the size of the new block
	//plus the size of the left block
	if (left != NULL)
	{
		start = left->payload;
		size += left->size;
	}
	//if right is not null, the address will be unaffected from the previous
	//two conditionals, but the size must change to include the size
	//determined above plus the size of the right block. in cases where
	//there is a left-adjacent block, the final size will be the sum of the
	//sizes of the left, new and right blocks. in cases where the right is
	//the only adjacent block, the size will be the sum of the new block
	//plus that of the right
	if (right != NULL)
	{
		size += right->size;
	}
}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void *mm_realloc(void *oldptr, size_t size)
{
    void *newptr = mm_malloc(size);
    if (newptr == NULL)
      return NULL;

    /* Assuming 'oldptr' was a '&payload[0]' in an allocated_block_header,
     * determine its start as 'oldblk'.  Then its size can be accessed
     * more easily.
     */
    struct allocated_block_header *oldblk;
    oldblk = oldptr - offsetof(struct allocated_block_header, payload);

    size_t copySize = oldblk->size;
    if (size < copySize)
      copySize = size;

    memcpy(newptr, oldptr, copySize);
    mm_free(oldptr);
    return newptr;
}
