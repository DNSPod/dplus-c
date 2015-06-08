/* Copyright (c) 2006-2015, DNSPod Inc.
 * All rights reserved.

 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1.Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 2.Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are those
 * of the authors and should not be interpreted as representing official policies,
 * either expressed or implied, of the FreeBSD Project.
*/

#include "lruhash.h"

static void bucket_delete(struct lruhash *table, struct lruhash_bucket *bucket)
{
    struct lruhash_entry *p, *np;
    void *d;
    if(!bucket)
        return;
    p = bucket->overflow_list;
    bucket->overflow_list = NULL;
    while(p) {
        lock_basic_lock(&p->lock);
        np = p->overflow_next;
        d = p->data;
        lock_basic_unlock(&p->lock);
        (*table->delkeyfunc)(p->key);
        (*table->deldatafunc)(d);
        p = np;
    }
}

static void bucket_split(struct lruhash *table,
    struct lruhash_bucket *newarray, int newmask)
{
    size_t i;
    struct lruhash_entry *p, *np;
    struct lruhash_bucket *newbucket;

    for(i=0; i<table->size; i++)
    {
        p = table->array[i].overflow_list;
        while(p) {
            np = p->overflow_next;
            newbucket = &newarray[p->hash & newmask];
            p->overflow_next = newbucket->overflow_list;
            newbucket->overflow_list = p;
            p = np;
        }
    }
}

void bucket_overflow_remove(struct lruhash_bucket *bucket,
    struct lruhash_entry *entry)
{
    struct lruhash_entry *p = bucket->overflow_list;
    struct lruhash_entry **prevp = &bucket->overflow_list;
    while(p) {
        if(p == entry) {
            *prevp = p->overflow_next;
            return;
        }
        prevp = &p->overflow_next;
        p = p->overflow_next;
    }
}

static void reclaim_space(struct lruhash *table, struct lruhash_entry **list)
{
    struct lruhash_entry *d;
    struct lruhash_bucket *bucket;

    while(table->num > 1 && table->space_used > table->space_max) {
        d = table->lru_tail;
        table->lru_tail = d->prev;
        d->prev->next = NULL;

        bucket = &table->array[d->hash & table->size_mask];
        table->num--;

        bucket_overflow_remove(bucket, d);
        d->overflow_next = *list;
        *list = d;

        lock_basic_lock(&d->lock);
        table->space_used -= table->sizefunc(d->key, d->data);
        lock_basic_unlock(&d->lock);
    }
}

static void table_grow(struct lruhash *table)
{
    struct lruhash_bucket *newarray;
    int newmask;

    newarray = calloc(table->size*2, sizeof(struct lruhash_bucket));
    if(!newarray) {
        fprintf(stderr, "hash grow: malloc failed\n");
        return;
    }

    newmask = (table->size_mask << 1) | 1;
    bucket_split(table, newarray, newmask);
    free(table->array);

    table->size *= 2;
    table->size_mask = newmask;
    table->array = newarray;
    return;
}

struct lruhash_entry *bucket_find_entry(struct lruhash *table, 
    struct lruhash_bucket *bucket, hashvalue_t hash, void *key)
{
    struct lruhash_entry *p = bucket->overflow_list;
    while(p) {
        if(p->hash == hash && table->compfunc(p->key, key) == 0)
            return p;
        p = p->overflow_next;
    }
    return NULL;
}

void lru_front(struct lruhash *table, struct lruhash_entry *entry)
{
    entry->prev = NULL;
    entry->next = table->lru_head;
    if(!table->lru_head)
        table->lru_tail = entry;
    else
        table->lru_head->prev = entry;
    table->lru_head = entry;
}

void lru_remove(struct lruhash *table, struct lruhash_entry *entry)
{
    if(entry->prev)
        entry->prev->next = entry->next;
    else
        table->lru_head = entry->next;
    if(entry->next)
        entry->next->prev = entry->prev;
    else
        table->lru_tail = entry->prev;
}

static void lru_touch(struct lruhash *table, struct lruhash_entry *entry)
{
    if(entry == table->lru_head)
        return;
    //move to front
    lru_remove(table, entry);
    lru_front(table, entry);
}

struct lruhash *lruhash_create(size_t size, size_t maxmem,
    lruhash_sizefunc_t sizefunc, lruhash_compfunc_t compfunc,
    lruhash_delkeyfunc_t delkeyfunc, lruhash_deldatafunc_t deldatafunc)
{
    struct lruhash *table = (struct lruhash*)calloc(1, sizeof(struct lruhash));
    if(!table)
        return NULL;

    lock_basic_init(&table->lock);
    table->sizefunc = sizefunc;
    table->compfunc = compfunc;
    table->delkeyfunc = delkeyfunc;
    table->deldatafunc = deldatafunc;
    table->size = size;
    table->size_mask = (int)(size-1);
    table->lru_head = NULL;
    table->lru_tail = NULL;
    table->num = 0;
    table->space_used = 0;
    table->space_max = maxmem;
    table->array = calloc(table->size, sizeof(struct lruhash_bucket));
    if(!table->array) {
        lock_basic_destroy(&table->lock);
        free(table);
        return NULL;
    }
    return table;
}

void lruhash_delete(struct lruhash *table)
{
    size_t i;
    if(!table)
        return;
    lock_basic_destroy(&table->lock);
    for(i=0; i<table->size; i++)
        bucket_delete(table, &table->array[i]);
    free(table->array);
    free(table);
}

void lruhash_insert(struct lruhash *table, hashvalue_t hash,
    struct lruhash_entry *entry, void *data)
{
    struct lruhash_bucket *bucket;
    struct lruhash_entry *found, *reclaimlist=NULL;
    size_t need_size;
    need_size = table->sizefunc(entry->key, data);

    //find bucket
    lock_basic_lock(&table->lock);
    bucket = &table->array[hash & table->size_mask];

    //see if entry exists
    if(!(found=bucket_find_entry(table, bucket, hash, entry->key))) {
        //if not found: add to bucket
        entry->overflow_next = bucket->overflow_list;
        bucket->overflow_list = entry;
        lru_front(table, entry);
        table->num++;
        table->space_used += need_size;
    } else {
        //if found: update data
        table->space_used += need_size -
            (*table->sizefunc)(found->key, found->data);
        (*table->delkeyfunc)(entry->key);
        lru_touch(table, found);
        lock_basic_lock(&found->lock);
        (*table->deldatafunc)(found->data);
        found->data = data;
        lock_basic_unlock(&found->lock);
    }
    if(table->space_used > table->space_max)
        reclaim_space(table, &reclaimlist);
    if(table->num >= table->size)
        table_grow(table);
    lock_basic_unlock(&table->lock);

    //del reclaim without lock
    while(reclaimlist) {
        struct lruhash_entry *n = reclaimlist->overflow_next;
        void *d = reclaimlist->data;
        (*table->delkeyfunc)(reclaimlist->key);
        (*table->deldatafunc)(d);
        reclaimlist = n;
    }
}

struct lruhash_entry *lruhash_lookup(struct lruhash *table,
    hashvalue_t hash, void *key)
{
    struct lruhash_entry *entry;
    struct lruhash_bucket *bucket;

    lock_basic_lock(&table->lock);
    bucket = &table->array[hash & table->size_mask];
    if((entry=bucket_find_entry(table, bucket, hash, key))) {
        lru_touch(table, entry);
        lock_basic_lock(&entry->lock);
    }
    lock_basic_unlock(&table->lock);
    return entry;
}

void lruhash_clear(struct lruhash* table)
{
    size_t i;
    if(!table)
        return;

    lock_basic_lock(&table->lock);
    for(i=0; i<table->size; i++) {
        bucket_delete(table, &table->array[i]);
    }
    table->lru_head = NULL;
    table->lru_tail = NULL;
    table->num = 0;
    table->space_used = 0;
    lock_basic_unlock(&table->lock);
}

void lruhash_remove(struct lruhash *table, hashvalue_t hash, void *key)
{
    struct lruhash_entry *entry;
    struct lruhash_bucket *bucket;
    void *d;

    lock_basic_lock(&table->lock);
    bucket = &table->array[hash & table->size_mask];
    if((entry=bucket_find_entry(table, bucket, hash, key))) {
        bucket_overflow_remove(bucket, entry);
        lru_remove(table, entry);
    } else {
        lock_basic_unlock(&table->lock);
        return;
    }

    table->num--;
    lock_basic_lock(&entry->lock);
    table->space_used -= (*table->sizefunc)(entry->key, entry->data);
    lock_basic_unlock(&entry->lock);
    lock_basic_unlock(&table->lock);

    //del key data
    d = entry->data;
    (*table->delkeyfunc)(entry->key);
    (*table->deldatafunc)(d);
}

void lruhash_status(struct lruhash *table, lruhash_printkey_t print_key,
    lruhash_printvalue_t print_value)
{
    size_t i;
    int min, max;
    lock_basic_lock(&table->lock);
    fprintf(stdout, "lruhash: %u entries, memory %u / %u",
        (unsigned)table->num, (unsigned)table->space_used,
        (unsigned)table->space_max);
    fprintf(stdout, "  itemsize %u, array %u, mask %d\n",
        (unsigned)(table->num ? table->space_used/table->num : 0),
        (unsigned)table->size, table->size_mask);

    min = (int)table->size*2;
    max = 0;
    for(i=0; i<table->size; i++) {
        int here = 0;
        struct lruhash_entry *en;
        en = table->array[i].overflow_list;
        while(en) {
            here++;
            if (print_key) {
                print_key(en->key);
            }
            if (print_value) {
                print_value(en->data);
            }
            en = en->overflow_next;
        }
        if (here > 0) {
            fprintf(stdout, "bucket[%d] %d\n", (int)i, here);
        }
        if(here > max) max = here;
        if(here < min) min = here;
    }
    fprintf(stdout, "bucket min %d, avg %.2lf, max %d\n", min, 
        (double)table->num/(double)table->size, max);

    lock_basic_unlock(&table->lock);
}
