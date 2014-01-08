/*
 * mm.c - Dynamic Memory Allocator
 *
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 * 
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  Only a header is stored with the size to allow
 * for realloc() to retrieve the block size.  Blocks are never coalesced 
 * or reused in this naive implementation. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * This is a pretty naive approach, based pretty closesly on the code supplied
 * in the textbook and the implementation provided by Dr. Back.  
 *
 *
 *
 *
 *
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <assert.h>

#include "mm.h"
#include "memlib.h"
#include "config.h"             /* defines ALIGNMENT */
#include "list.h"

/* Basic constants and macros */
#define WSIZE       8          /* Word and header/footer size (bytes) */
#define DSIZE       16          /* Doubleword size (bytes) */
#define MIN_BLOCK_SIZE_WORDS 8  /* Minimum block size in words */
#define CHUNKSIZE  (1<<10)      /* Extend heap by this amount (bytes) 2^12 */

#define MAX(x, y) ((x) > (y)? (x) : (y))  

#define MAX_BLOCK	4096
#define MIN_BLOCK	8
#define STEP_AMOUNT	2   //used when creating the lists. They are in powers of 2


team_t team = {
    /* Team name */
    "Bad (as in \"not good\") C Programmers",
    /* First member's full name */
    "Ryan Merkel",
    /* First member's SLO (@cs.vt.edu) email address */
    "orionf22",
    /* Second member's full name (leave blank if none) */
    "Patrick Lewis",
    /* Second member's SLO (@cs.vt.edu) email address (leave blank if none) */
    "patl1"
};

/* A structure that holds our explicit free list. We can add this struct to 
 * another list so that we can get a list of lists for our segregated free list.
 * If we want to do it that way.  We don't have to.
 */
struct fr_blk_lst {
    size_t size;                       //the size of block that this list stores
    struct list free_blocks_list;   //list of available blocks
    struct list_elem elem;
};

/* Given in the implementations we already studied. */
struct boundary_tag {
    size_t inuse:1;        // inuse bit (boolean)
    size_t size:63;        // size of block, in WORDS, not bytes 
};

/* FENCE is used for heap prologue/epilogue. */
const struct boundary_tag FENCE = { .inuse = 1, .size = 0 };

/* This structure is basically what allocates each block.  
 * We got this particular idea and naming convention from Dr. Back's example,
 * but we added a list_elem so that we could add it to an explicit list.
 */
struct block {
    struct boundary_tag header; /* offset 0, at address 4 mod 8 */
    char payload[0];            /* offset 4, at address 0 mod 8 */
    struct list_elem elem;
};

/* Global variables */
static struct block *heap_listp = 0;        /* Pointer to first block */  

/*Global variables */
static struct list big_list; /* List of free blocks  OR list of lists*/
int count = 0;

/* Function prototypes for internal helper routines.
 * Most of these were also inspired by Dr. Back.
 */
static struct block *extend_heap(size_t words);
static void place(struct block *bp, size_t asize);
static struct block *find_fit(size_t asize);
static struct block *coalesce(struct block *bp);
static void add_free_block(struct block *blk);
static void init_all_free_lists();
static void mark_block_used();

/* Given a block, obtain previous's block footer.
 * Somehow works for left-most block, mostly because of the fence that we use in
 * the initialization of the heap.  It isn't a real block, it just shows where
 * the previous block ends.
 */
static struct boundary_tag * prev_blk_footer(struct block *blk) {
    return &blk->header - 1;
}

/* Returns whether or not a block is free */
static bool blk_free(struct block *blk) { 
    return !blk->header.inuse; 
}

/* Return the particular size of a block, regardless of "freeness" */
static size_t blk_size(struct block *blk) { 
    return blk->header.size; 
}

/* Given a block, obtain pointer to previous block.
 * Does not work for leftmost block, since there is no block to the left. You'd
 * have to call prev_blk_footer if this is the leftmost block.  Then you just
 * get a boundary tag.
 */
static struct block *prev_blk(struct block *blk) {
    struct boundary_tag *prevfooter = prev_blk_footer(blk);
    assert(prevfooter->size != 0);
    return (struct block *)((size_t *)blk - prevfooter->size);
}

/* Given a block, obtain pointer to next block.
 * Does not work for rightmost block since there is no block to the right. You'd
 * have to just do some pointer arithmetic.  Then you just
 * get a boundary tag.
 */
static struct block *next_blk(struct block *blk) {
    assert(blk_size(blk) != 0);
    return (struct block *)((size_t *)blk + blk->header.size);
}

/* Given a block, obtain its footer boundary tag. Works for THIS block, not to 
 * be confused with prev_blk_footer.
 */
static struct boundary_tag * get_footer(struct block *blk) {
    return (void *)((size_t *)blk + blk->header.size) \
                   - sizeof(struct boundary_tag);
}

/* Set a block's size and inuse bit in header and footer */
static void set_header_and_footer(struct block *blk, size_t size, size_t inuse) {
    blk->header.inuse = inuse;
    blk->header.size = size;
    * get_footer(blk) = blk->header;    /* Copy header to footer */
}

/* Mark a block as used and set its size. */
static void mark_block_used(struct block *blk, size_t size) {
    set_header_and_footer(blk, size, 1);
}


/* Mark a block as free and set its size. */
static void mark_block_free(struct block *blk, size_t size) {
    set_header_and_footer(blk, size, 0);
}

/* 
 * mm_init - Initialize the memory manager 
 */
int mm_init(void) 
{
    /* Initialize the free list(s) */
    init_all_free_lists();
    /* Create the initial empty heap */
    struct boundary_tag * initial = mem_sbrk(2 * sizeof(struct boundary_tag));
    if (initial == (void *)-1) return -1;
    
    /* Use the given implementation's idea of creating an empty heap and putting
     * fences up to delineate where the heap starts and ends.*/
    initial[0] = FENCE;                         /* Begining fence.           */
    heap_listp = (struct block *)&initial[1];   /* Set heap after first fence*/
    initial[1] = FENCE;                         /* End fence                 */

    /* Extend the empty heap with a free block of CHUNKSIZE bytes */
    if (extend_heap(CHUNKSIZE/WSIZE) == NULL) return -1;

    return 0;
}

/* 
 * mm_malloc - Allocate a block with at least 'size' bytes of payload.
 * Basic idea:
 *      * Adjust size to fit alignment
 *      * Look for blocks that are already free, try to place them there
 *      * If no fit, extend the heap and return the newly created space.
 */
void *mm_malloc(size_t size)
{  
    size_t awords;            /* Adjusted block size (in words)             */
    size_t extendwords;       /* Amount to allocate if need to extend heap  */
    struct block *bp;      
    
    /* If heap hasn't been initialized yet */
    if (heap_listp == 0) mm_init();
    
    /* Ignore spurious requests */
    if (size == 0) return NULL;
    
    /* Make block size fit alignment requirement and accout for header size  */
    size += 2 * sizeof(struct boundary_tag);    /* account for boundary tags */
    size = (size + DSIZE - 1) & ~(DSIZE - 1);   /* align to double word      */
    /* Have to make sure this rounds up to the minimum size if too small     */
    awords = MAX(MIN_BLOCK_SIZE_WORDS, size/WSIZE);

    /* Look through free list for availabilities */
    if ((bp = find_fit(awords)) != NULL) 
    {
        place(bp, awords);
        return bp->payload;
    }

    /* No fit found. Extend heap and return newly allocated area. */
    extendwords = MAX(awords,CHUNKSIZE);
    if ((bp = extend_heap(extendwords)) == NULL)  return NULL;

    place(bp, awords);
    return bp->payload;
} 

/* 
 * mm_free - Free a block.
 *
 * Very simple.  Just marks the block as free and then calls coalesce() to make 
 * sure that this newly freed area doesn't produce mutliple free blocks that are
 * next to each other.  Lets coalesce() worry about what happens to the free 
 * lists.
 */
void mm_free(void *bp)
{
    /* If given null pointer, do nothing because it's not allocated. */
    if (bp == 0) return;
    
    /* Find block from user pointer */
    struct block *blk = bp - offsetof(struct block, payload);

    /* We should probably check in here to see if the block is even valid, but I
     * don't know how to do that.  Luckily the tests don't give us any invalid 
     * input so we don't have to worry about it.
     */
    mark_block_free(blk, blk_size(blk));
    coalesce(blk);
}

/*
 * mm_realloc - Reallocating a block of memory.
 *
 * A slight improvement over the naive implementation of realloc.  When 
 * reallocating, looks to either side of this block to see if those blocks are 
 * free.  Basically, it tries to coalesce around the newly freed block to see if
 * there is enough space here before allocating new memory.  After enough free
 * space is found (through one method or another) it copies over the memory from
 * the old payload to the new one.
 */
void *mm_realloc(void *ptr, size_t size)
{
    size_t bytesize;
    void *newptr;
    
    /* If block of zero size, no need to do anything (although why would you 
     * ever have a block of zero size? That's just dumb. */
    if(size == 0)
    {
        mm_free(ptr);
        return 0;
    }

    /* If given a null pointer, then you're reallocating nothing, but you have
     * to give it the new size.  Just call malloc. */
    if(ptr == NULL) return mm_malloc(size);

    /* Find pointer to old block and then it's basically just coalesce() */
    struct block *oldblk = ptr - offsetof(struct block, payload);
    bool prev_alloc = prev_blk_footer(oldblk)->inuse;
    bool next_alloc = !blk_free(next_blk(oldblk));
    
    /* "right" block */
    if (!next_alloc)
    {
	    struct block *right;
	    right = next_blk(oldblk);
	    list_remove(&right->elem);
        mark_block_used(oldblk, blk_size(oldblk) + blk_size(next_blk(oldblk)));
    }
    
    /* If size if newly coalesced block (if coalesced) is greater than original
     * then we can return this block, no need to copy memory */
    if (blk_size(oldblk) >= size)  return oldblk->payload; 

    /* "left" block */
    if (!prev_alloc)
    {
	    struct block *left;
	    left = prev_blk(oldblk);
	    list_remove(&left->elem);
        mark_block_used(left, blk_size(oldblk) + blk_size(left));
	    oldblk = left;
    }
    
    /* If size if newly coalesced block (if coalesced) is greater than original
     * then we can return this block (payload is the "left" one now), but we 
     * have to copy memory*/
    if (blk_size(oldblk) >= size) 
    {
	    bytesize = blk_size(oldblk) * WSIZE; //find number of BYTES, not words
	    if(size < bytesize) bytesize = size;
	    memcpy(oldblk->payload, ptr, bytesize);
	    return oldblk->payload;
    }

    /* If haven't been able to coalesce, malloc new size */
    newptr = mm_malloc(size);
    
    /* If malloc didn't work then leave the original block alone */
    if(!newptr) return 0;

    /* Figure out how much to copy and then copy to new memory */
    struct block *copyblk = ptr - offsetof(struct block, payload);
    bytesize = blk_size(copyblk) * WSIZE; //find number of BYTES, not words
    if(size < bytesize) bytesize = size;
    memcpy(newptr, ptr, bytesize);
    
    /* Free the old block. */
    mm_free(oldblk->payload);
    
    return newptr;
}

/* 
 * checkheap - We don't check anything right now. 
 */
void mm_checkheap(int verbose)  
{ 
    /*We didn't write this because we REALLY ran out of time. I swear, we're not
     * bad people, we just had a lot of problems with this project.
     */
}

/*==============================================================================
 * The remaining routines are internal helper routines 
 * =============================================================================
 */


/*
 * coalesce - Boundary tag coalescing. Return ptr to coalesced block. 
 *
 * Again, this implementation was pretty much take from Dr. Back's code, with
 * some added machinations about removing from and adding to the freelist(s).
 */
static struct block *coalesce(struct block *bp) 
{
    /* block *bp is considered the "middle" block */
    bool prev_alloc = prev_blk_footer(bp)->inuse; /* If left block is used  */
    bool next_alloc = !blk_free(next_blk(bp));    /* If right block is used */
    size_t size = blk_size(bp);

    if (prev_alloc && next_alloc) /* Case 1: nothing to coalesce */
    {            
	    add_free_block(bp);
	    return bp;
    }

    else if (prev_alloc && !next_alloc) /* Case 2: right free, left not*/
    {      
	    struct block *right;
	    right = next_blk(bp);
	    list_remove(&right->elem);
        mark_block_free(bp, size + blk_size(next_blk(bp)));
	    add_free_block(bp);
	    return bp;
    }

    else if (!prev_alloc && next_alloc) /* Case 3: left free, right not*/
    {      
        struct block *left;
	    left = prev_blk(bp);
	    list_remove(&left->elem);
        mark_block_free(left, size + blk_size(left));
    	add_free_block(left);
	    return left;
    }

    else 
    {                                     /* Case 4: join all three */
	    struct block *left;
	    struct block *right;

	    left = prev_blk(bp);
	    list_remove(&left->elem);

	    right = next_blk(bp);
	    list_remove(&right->elem);

        /* Blocks are already free, we're just setting the size */
        mark_block_free(left, size + blk_size(left) + blk_size(right));
	    add_free_block(left);
	    return left;
    }
    /* Really this isn't necessary since all possible cases have been taken care
     * of, it's just here so the compiler doesn't complain. Worst case scenario
     * is that we don't coalesce anything but we return this block.
     */
    return bp;
}



/*
 * Initializes all of the free lists.  First it does the big list that holds all
 * of the lists, then it does the individual free lists.
 */
 static void init_all_free_lists()
{
    list_init(&big_list);
    
    int i;
    /* Start with the biggest size list, work to the smallest size list */
    for(i = MAX_BLOCK; i >= MIN_BLOCK; i /= STEP_AMOUNT) 
    {
	    struct fr_blk_lst *thislist = mem_sbrk(sizeof(struct fr_blk_lst));
	    thislist->size = i; //set the size block that this list holds
	    list_init(&thislist->free_blocks_list);           //make the list
	    list_push_back(&big_list, &thislist->elem);      //add to list of lists
    }
}


/*
 * Adds an unallocated block into the free list.  If there are mulitiple lists, 
 * this finds the correct list to put it in, and then puts it in that list.
 */
static void add_free_block(struct block *blk)
{    
    /* Shouldn't ever get a null block, but just in case */
    if (blk == 0) return;
    
    struct list_elem *e;
    
    /* First look through the list of lists to find the correct one */
    for(e = list_begin(&big_list); e != list_end(&big_list); e = list_next(e))
    {
        struct fr_blk_lst *seg_blocks = list_entry(e,struct fr_blk_lst,elem);
	    /* If size of this block >=  min block size in list.
         * Stops when is finds the first one it fits into (min fit) */
        if (seg_blocks->size <= blk_size(blk)) 
        {
	        list_push_back(&seg_blocks->free_blocks_list, &blk->elem);
	        return;
	    }
    }
}

/* 
 * extend_heap - Extend heap with free block and return its block pointer
 * Its parameter is the number of WORDS, not the number of bytes.  
 */
static struct block *extend_heap(size_t words) 
{
    void *bp;
    
    /* Have to round up to the alignment to make sure it all fits */
    words = (words + 1) & ~1;
    if ((long)(bp = mem_sbrk(words * WSIZE)) == -1)  return NULL;

    /* Make the new block and move the fence. */
    struct block * blk = bp - sizeof(FENCE);  //move to overwrite previous fence
    mark_block_free(blk, words);              //overwrite fence
    next_blk(blk)->header = FENCE;            //block after this one is fence  

    /* Coalesce if the previous block was free.
     * This might make things slower. */
    return coalesce(blk);
}

/* 
 * place - Place block of asize words at start of free block bp 
 *         and split if remainder would be at least minimum block size
 *
 * This assumes that the block we're placing this into is free.  And again, the 
 * parameter 'asize' is the size in WORDS, not bytes.  This implementation is, 
 * yet again, inspired by Godmar Back.  We just modified it to suit our needs.
 */
static void place(struct block *bp, size_t asize)
{
    size_t csize = blk_size(bp);

    /* If it's possible to split this block */
    if ((csize - asize) >= MIN_BLOCK_SIZE_WORDS)
    {
        mark_block_used(bp, asize);
	    list_remove(&bp->elem);
	    struct block *temp = next_blk(bp);  //the new block after splitting
        mark_block_free(temp, csize-asize); //mark the new block as free
	    add_free_block(temp);               //add it to a free list
    }
    /* If this block can't be split */
    else 
    { 
        mark_block_used(bp, csize);
	    list_remove(&bp->elem);
    }
}

/* 
 * find_fit - Find a fit for a block with asize words 
 *
 * Again, 'asize' is a size in WORDS.  That gave us a lot of trouble.  Basically
 * this just looks through all of the free lists to find which one it should go 
 * into, then it returns the free block which is a fit.  
 *
 * Precondition: 'asize' had already been fixed for alignment issues and is
 * greater than or equal to the minimum size.
 */
static struct block *find_fit(size_t asize)
{
    struct list_elem *e_list;
    /* Start from the front of the list and move backwards.  If we want to
     * optimize this, we should probably do this the other way around 
     * since the smallest sizes are at the front of the big list. 
     */
    for (e_list = list_rbegin(&big_list); e_list != list_rend(&big_list); \
    e_list = list_prev(e_list))
    {

	    struct fr_blk_lst *fr_lst = list_entry(e_list,struct fr_blk_lst,elem);

        /* If list not empty AND (size is ok OR this is smallest list)*/
    	if (!list_empty(&fr_lst->free_blocks_list) && (fr_lst->size >= asize \
        || list_prev(e_list) == list_rend(&big_list))) 
        {
            /* Set up list elements for comparison.  I'll explain in a bit. */
	        struct list_elem *rov1;
	        struct list_elem *rov2 = list_rbegin(&fr_lst->free_blocks_list);
            /* Now look through list freelist to try to find a good block.
             * This is a pretty cool algorithm.  It searches two blocks at the
             * same time and has them meet in the middle.  This way we can 
             * search twice as fast to minimize search time.*/
	        for (rov1 = list_begin(&fr_lst->free_blocks_list); rov1 != \
            list_end(&fr_lst->free_blocks_list); rov1 = list_next(rov1)) 
            {
                /* Cast the list_entries to blocks */
		        struct block *blk_1 = list_entry(rov1, struct block, elem);
		        struct block *blk_2 = list_entry(rov2, struct block, elem);

                /* If we found a good block */
		        if (blk_size(blk_1) >= asize) return blk_1;
		        if (blk_size(blk_2) >= asize)	return blk_2;

                /* Move this one backwards while the other one moves forwards.*/
		        rov2 = list_prev(rov2);

                /* Stopping condition: the two moving list_entries meet in the 
                 * middle or they are next to each other. Returning null means
                 * that we didn't find anything.*/
		        if (rov1 == rov2 || list_next(rov2) == rov1) return NULL;
	        }
	    }
    }
    /* The case that we search through everything and there's nothing to find */
    return NULL;
}





