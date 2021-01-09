////////////////////////////////////////////////////////////////////////////////
//
//  File           : sg_driver.c
//  Description    : This file contains the driver code to be developed by
//                   the students of the 311 class.  See assignment details
//                   for additional information.
//
//   Author        : Myung Joon Kim
//   Last Modified : 12/11/2020
//

// Include Files
#include <stdlib.h>
#include <cmpsc311_log.h>
#include <string.h>

// Project Includes
#include <sg_cache.h>

// Defines
typedef struct cache
{
    SG_Node_ID nid;
    SG_Block_ID blkid;
    char data[SG_BLOCK_SIZE];
    struct cache *llink;
    struct cache *rlink;
} Cache;

Cache *front, *rear;
unsigned miss, hit;
unsigned num, max;

// Functional Prototypes

//
// Functions

////////////////////////////////////////////////////////////////////////////////
//
// Function     : initSGCache
// Description  : Initialize the cache of block elements
//
// Inputs       : maxElements - maximum number of elements allowed
// Outputs      : 0 if successful, -1 if failure

int initSGCache(uint16_t maxElements)
{
    max = maxElements;
    front = rear = NULL;
    num = hit = miss = 0;
    return (0);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : closeSGCache
// Description  : Close the cache of block elements, clean up remaining data
//
// Inputs       : none
// Outputs      : 0 if successful, -1 if failure

int closeSGCache(void)
{
    while (front != NULL)
    {
        Cache *cache = front->rlink;
        free(front);
        front = cache;
    }

    double hitRate = 100 * (double)hit / (miss + hit);
    logMessage(LOG_INFO_LEVEL, "SGCache hit rate %f\n", hitRate);

    return (0);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : getSGDataBlock
// Description  : Get the data block from the block cache
//
// Inputs       : nde - node ID to find
//                blk - block ID to find
// Outputs      : pointer to block or NULL if not found

Cache *findCache(SG_Node_ID nde, SG_Block_ID blk)
{
    Cache *cache = front;
    while (cache != NULL)
    {
        if (cache->nid == nde && cache->blkid == blk)
        {
            return cache;
        }
        cache = cache->rlink;
    }
    return NULL;
}

void deleteCache(Cache *cache)
{
    // dumpCache();
    if (front == cache)
    {
        front = front->rlink;
    }
    if (cache == rear)
    {
        rear = rear->llink;
    }
    if (cache->rlink != NULL)
    {
        cache->rlink->llink = cache->llink;
    }
    if (cache->llink != NULL)
    {
        cache->llink->rlink = cache->rlink;
    }
}

void adjustSize()
{
    if (num != max)
    {
        return;
    }
    Cache *cache = rear;
    deleteCache(cache);
    free(cache);
    num = num - 1;
}

void putCache(Cache *cache)
{
    adjustSize();
    cache->llink = NULL;
    cache->rlink = front;
    if (front != NULL)
    {
        front->llink = cache;
    }
    if (rear == NULL)
    {
        rear = cache;
    }
    front = cache;
}

char *getSGDataBlock(SG_Node_ID nde, SG_Block_ID blk)
{
    Cache *cache = findCache(nde, blk);
    if (cache == NULL)
    {
        miss = miss + 1;
        return NULL;
    }
    else
    {
        hit = hit + 1;
        deleteCache(cache);
        putCache(cache);
        return cache->data;
    }
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : putSGDataBlock
// Description  : Get the data block from the block cache
//
// Inputs       : nde - node ID to find
//                blk - block ID to find
//                block - block to insert into cache
// Outputs      : 0 if successful, -1 if failure

int putSGDataBlock(SG_Node_ID nde, SG_Block_ID blk, char *block)
{
    Cache *cache;
    if ((cache = findCache(nde, blk)) != NULL)
    {
        deleteCache(cache);
        putCache(cache);
        return 0;
    }
    cache = (Cache *)malloc(sizeof(Cache));
    memset(cache, 0x00, sizeof(Cache));
    cache->nid = nde;
    cache->blkid = blk;
    memcpy(cache->data, block, SG_BLOCK_SIZE);
    cache->llink = cache->rlink = NULL;
    putCache(cache);
    num = num + 1;
    return (0);
}


