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

#ifndef LRUHASH_H
#define LRUHASH_H

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

typedef pthread_mutex_t lock_basic_t;
#define lock_basic_init(lock) pthread_mutex_init(lock, NULL)
#define lock_basic_destroy(lock) pthread_mutex_destroy(lock)
#define lock_basic_lock(lock) pthread_mutex_lock(lock)
#define lock_basic_unlock(lock) pthread_mutex_unlock(lock)

struct lruhash_bucket;
struct lruhash_entry;

#define HASH_DEFAULT_ARRAY_SIZE     1024
#define HASH_DEFAULT_MAXMEM     4*1024*1024

typedef uint32_t hashvalue_t;

typedef size_t (*lruhash_sizefunc_t)(void *, void *);
typedef int (*lruhash_compfunc_t)(void *, void *);
typedef void (*lruhash_delkeyfunc_t)(void *);
typedef void (*lruhash_deldatafunc_t)(void *);

typedef void (*lruhash_printkey_t)(void *);
typedef void (*lruhash_printvalue_t)(void *);

//LRU Hash table.
struct lruhash {
    lock_basic_t lock;

    /* lru hash functions */
    lruhash_sizefunc_t sizefunc;
    lruhash_compfunc_t compfunc;
    lruhash_delkeyfunc_t delkeyfunc;
    lruhash_deldatafunc_t deldatafunc;

    //size of array, power of 2
    size_t size;
    //size bitmask
    int size_mask;
    //array of entry
    struct lruhash_bucket *array;

    //lru list head and tail
    struct lruhash_entry *lru_head;
    struct lruhash_entry *lru_tail;

    //num of entries
    size_t num;
    //used space
    size_t space_used;
    //max space allowed to use
    size_t space_max;
};

//linked list of overflow entries
struct lruhash_bucket {
    struct lruhash_entry *overflow_list;
};

//hash table entry
struct lruhash_entry {
    //lock for access to the contents of the entry
    lock_basic_t lock;

    //next entry in overflow list
    struct lruhash_entry *overflow_next;

    //next and prev entry in lru list
    struct lruhash_entry *next;
    struct lruhash_entry *prev;

    //hash value of the key
    hashvalue_t hash;

    void *key;
    void *data;
};

struct lruhash *lruhash_create(size_t size, size_t maxmem,
    lruhash_sizefunc_t sizefunc, lruhash_compfunc_t compfunc,
    lruhash_delkeyfunc_t delkeyfunc, lruhash_deldatafunc_t deldatafunc);

void lruhash_delete(struct lruhash *table);

void lruhash_clear(struct lruhash *table);

void lruhash_insert(struct lruhash *table, hashvalue_t hash, 
    struct lruhash_entry *entry, void *data);

void lruhash_remove(struct lruhash *table, hashvalue_t hash, void *key);

//the function will lock the entry, unlock it when done.
struct lruhash_entry *lruhash_lookup(struct lruhash *table,
    hashvalue_t hash, void *key);

void lruhash_status(struct lruhash *table, lruhash_printkey_t print_key,
    lruhash_printvalue_t print_value);

#endif
