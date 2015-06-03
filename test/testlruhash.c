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

#include "testmain.h"
#include "../lruhash.h"

struct testkey_t {
    int id;
    struct lruhash_entry entry;
};

struct testdata_t {
    int data;
};

typedef struct testkey_t testkey;
typedef struct testdata_t testdata;

static void delkey(void *k1)
{
    testkey *k = (testkey *)k1;
    lock_basic_destroy(&k->entry.lock);
    free(k);
}

static void deldata(void *d)
{
    free(d);
}

static size_t sizefunc(void *k1, void *k2)
{
    return sizeof(testkey) + sizeof(testdata);
}

static int compfunc(void *key1, void *key2)
{
    testkey *k1 = (testkey *)key1;
    testkey *k2 = (testkey *)key2;
    if(k1->id == k2->id)
        return 0;
    if(k1->id > k2->id)
        return 1;
    return -1; 
}

static hashvalue_t simplehash(int id)
{
    return (hashvalue_t)id & 0x0f;
}

static testkey *newkey(int id)
{
    testkey *k = (testkey *)calloc(1, sizeof(testkey));
    if(!k) {
        printf("calloc testkey: out of memory\n");
        exit(1);
    }
    k->id = id;
    k->entry.hash = simplehash(id);
    k->entry.key = k;
    lock_basic_init(&k->entry.lock);
    return k;
}

static testdata *newdata(int val)
{
    testdata *d = (testdata *)calloc(1, sizeof(testdata));
    if(!d) {
        printf("calloc testdata: out of memory\n");
        exit(1);
    }
    d->data = val;
    return d;
}

//test bucket_find_entry and bucket_overflow_remove
static void test_bucket_find_entry(struct lruhash *table)
{
    testkey *k1 = newkey(12);
    testkey *k2 = newkey(12 + 1024);
    testkey *k3 = newkey(14);
    testkey *k4 = newkey(12 + 1024*2);
    hashvalue_t h = simplehash(12);
    struct lruhash_bucket bucket;
    memset(&bucket, 0, sizeof(bucket));

    //remove from empty list
    bucket_overflow_remove(&bucket, &k1->entry);

    //find in empty list
    unit_assert(bucket_find_entry(table, &bucket, h, k1) == NULL);

    //insert
    bucket.overflow_list = &k1->entry;
    unit_assert(bucket_find_entry(table, &bucket, simplehash(13), k1) == NULL);
    unit_assert(k1->entry.hash == k2->entry.hash);
    unit_assert(bucket_find_entry(table, &bucket, h, k2) == NULL);
    unit_assert(bucket_find_entry(table, &bucket, h, k1) == &k1->entry);

    //remove
    bucket_overflow_remove(&bucket, &k1->entry);
    unit_assert(bucket_find_entry(table, &bucket, h, k1) == NULL);

    //insert multi
    unit_assert(k1->entry.hash == k4->entry.hash);
    k4->entry.overflow_next = &k1->entry;
    k3->entry.overflow_next = &k4->entry;
    bucket.overflow_list = &k3->entry;
    unit_assert(bucket_find_entry(table, &bucket, simplehash(13), k1) == NULL);
    unit_assert(k1->entry.hash == k2->entry.hash);
    unit_assert(bucket_find_entry(table, &bucket, h, k2) == NULL);
    unit_assert(bucket_find_entry(table, &bucket, h, k1) == &k1->entry);

    //remove mid
    unit_assert(bucket_find_entry(table, &bucket, k4->entry.hash, k4) == &k4->entry);
    bucket_overflow_remove(&bucket, &k4->entry);
    unit_assert(bucket_find_entry(table, &bucket, k4->entry.hash, k4) == NULL);

    //remove last
    bucket_overflow_remove(&bucket, &k1->entry);
    unit_assert(bucket_find_entry(table, &bucket, h, k1) == NULL);

    delkey(k1);
    delkey(k2);
    delkey(k3);
    delkey(k4);
}

//test lru_front and lru_remove
static void test_lru(struct lruhash *table)
{
    testkey *k1 = newkey(12);
    testkey *k2 = newkey(14);
    lock_basic_lock(&table->lock);

    unit_assert(table->lru_head == NULL && table->lru_tail == NULL);
    lru_remove(table, &k1->entry);
    unit_assert(table->lru_head == NULL && table->lru_tail == NULL);

    //add one
    lru_front(table, &k1->entry);
    unit_assert( table->lru_head == &k1->entry && table->lru_tail == &k1->entry);

    //remove
    lru_remove(table, &k1->entry);
    unit_assert(table->lru_head == NULL && table->lru_tail == NULL);

    //add two
    lru_front(table, &k1->entry);
    unit_assert(table->lru_head == &k1->entry && 
        table->lru_tail == &k1->entry);
    lru_front(table, &k2->entry);
    unit_assert(table->lru_head == &k2->entry && 
        table->lru_tail == &k1->entry);

    //remove first
    lru_remove(table, &k2->entry);
    unit_assert(table->lru_head == &k1->entry && 
        table->lru_tail == &k1->entry);
    lru_front(table, &k2->entry);
    unit_assert(table->lru_head == &k2->entry && 
        table->lru_tail == &k1->entry);

    //remove last
    lru_remove(table, &k1->entry);
    unit_assert(table->lru_head == &k2->entry && 
        table->lru_tail == &k2->entry);

    //empty
    lru_remove(table, &k2->entry);
    unit_assert(table->lru_head == NULL && table->lru_tail == NULL);

    lock_basic_unlock(&table->lock);

    delkey(k1);
    delkey(k2);
}

//test lruhash_insert, lruhash_lookup and lruhash_remove
static void test_short_table(struct lruhash *table) 
{
    testkey *k1 = newkey(12);
    testkey *k2 = newkey(14);
    testdata *d1 = newdata(128);
    testdata *d2 = newdata(129);

    k1->entry.data = d1;
    k2->entry.data = d2;

    lruhash_insert(table, simplehash(12), &k1->entry, d1);
    lruhash_insert(table, simplehash(14), &k2->entry, d2);

    unit_assert(lruhash_lookup(table, simplehash(12), k1) == &k1->entry);
    lock_basic_unlock(&k1->entry.lock);

    unit_assert(lruhash_lookup(table, simplehash(14), k2) == &k2->entry);
    lock_basic_unlock(&k2->entry.lock );

    lruhash_remove(table, simplehash(12), k1);
    lruhash_remove(table, simplehash(14), k2);
}

//number of hash test
#define MAXHASH 25

//test add a random element
static void testadd(struct lruhash *table, testdata *ref[])
{
    int num = random() % MAXHASH;
    testdata *data = newdata(num);
    testkey *key = newkey(num);
    key->entry.data = data;
    lruhash_insert(table, simplehash(num), &key->entry, data);
    if(ref)
        ref[num] = data;
}

//test remove a random element
static void testremove(struct lruhash *table, testdata *ref[])
{
    int num = random() % MAXHASH;
    testkey *key = newkey(num);
    lruhash_remove(table, simplehash(num), key);
    if (ref)
        ref[num] = NULL;
    delkey(key);
}

//test lookup a random element
static void testlookup(struct lruhash *table, testdata *ref[])
{
    int num = random() % MAXHASH;
    testkey *key = newkey(num);
    struct lruhash_entry *e = lruhash_lookup(table, simplehash(num), key);
    testdata *data = e ? (testdata *)e->data : NULL;

    if(e) {
        unit_assert(e->key);
        unit_assert(e->data);
        lock_basic_unlock(&e->lock);
    }
    if (ref)
        unit_assert(data == ref[num]);

    delkey(key);
}

//check table
static void check_table(struct lruhash *table)
{
    struct lruhash_entry *p;
    size_t c = 0;
    lock_basic_lock(&table->lock);

    unit_assert(table->num <= table->size);
    unit_assert(table->size_mask == (int)table->size - 1);
    unit_assert((table->lru_head && table->lru_tail) ||
        (!table->lru_head && !table->lru_tail));
    unit_assert(table->space_used <= table->space_max);

    if(table->lru_head)
        unit_assert(table->lru_head->prev == NULL);
    if(table->lru_tail)
        unit_assert(table->lru_tail->next == NULL);

    p = table->lru_head;
    while(p) {
        if(p->prev) {
            unit_assert(p->prev->next == p);
        }
        if(p->next) {
            unit_assert(p->next->prev == p);
        }
        c++;
        p = p->next;
    }
    unit_assert(c == table->num);
    unit_assert(table->space_used == table->num * sizefunc(NULL, NULL));

    lock_basic_unlock(&table->lock);
}

static void test_long_table(struct lruhash* table) 
{
    testdata *ref[MAXHASH * 100];
    size_t i;
    memset(ref, 0, sizeof(ref));

    unit_assert(sizefunc(NULL, NULL)*MAXHASH < table->space_max);

    srandom(48);
    for(i = 0; i < 1000; i++) {
        if(i == 500) {
            lruhash_clear(table);
            memset(ref, 0, sizeof(ref));
            continue;
        }
        switch(random() % 4) {
            case 0:
            case 3:
                testadd(table, ref);
                break;
            case 1:
                testremove(table, ref);
                break;
            case 2:
                testlookup(table, ref);
                break;
            default:
                unit_assert(0);
        }
        check_table(table);
        unit_assert(table->num <= MAXHASH);
    }
}

//threaded test
struct test_thr {
    int num;
    pthread_t id;
    struct lruhash *table;
};

static void *test_thr_main(void *arg)
{
    struct test_thr *t = (struct test_thr *)arg;
    int i;
    for(i = 0; i < 1000; i++) {
        switch(random() % 4) {
            case 0:
            case 3:
                testadd(t->table, NULL);
                break;
            case 1:
                testremove(t->table, NULL);
                break;
            case 2:
                testlookup(t->table, NULL);
                break;
            default:
                unit_assert(0);
        }
        if(i % 100 == 0)
            check_table(t->table);
    }
    check_table(t->table);
    return NULL;
}

//test hash table access by multiple threads
static void test_threaded_table(struct lruhash* table)
{
    int numth = 10;
    struct test_thr t[100];
    int i;

    for(i = 1; i < numth; i++) {
        t[i].num = i;
        t[i].table = table;
        pthread_create(&t[i].id, NULL, test_thr_main, &t[i]);
    }

    for(i = 1; i < numth; i++) {
        pthread_join(t[i].id, NULL);
    }
}

void lruhash_test(void)
{
    struct lruhash *table;
    printf("test lruhash functions\n");

    table = lruhash_create(2, 8192, sizefunc, compfunc, delkey, deldata);
    test_bucket_find_entry(table);
    test_lru(table);
    test_short_table(table);
    test_long_table(table);
    lruhash_delete(table);

    table = lruhash_create(2, 8192, sizefunc, compfunc, delkey, deldata);
    test_threaded_table(table);
    lruhash_delete(table);
}
