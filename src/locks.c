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

#include "locks.h"

#ifdef WIN32

void lock_basic_init(lock_basic_t *lock)
{
    (void)InterlockedExchange(lock, 0);
}

void lock_basic_destroy(lock_basic_t *lock)
{
    (void)InterlockedExchange(lock, 0);
}

void lock_basic_lock(lock_basic_t *lock)
{
    LONG wait = 1;

    while (InterlockedExchange(lock, 1)) {
        Sleep(wait);
        wait *= 2;
    }
}

void lock_basic_unlock(lock_basic_t *lock)
{
    (void)InterlockedExchange(lock, 0);
}

void dp_thread_create(dp_thread_t *thr, void *(*func)(void*), void *arg)
{
    *thr = (dp_thread_t)_beginthreadex(NULL, 0, (void*)func, arg, 0, NULL);
    if (*thr == NULL) {
        fprintf(stderr, "CreateThread failed");
        exit(1);
    }
}

void dp_thread_detach(dp_thread_t thr)
{
    CloseHandle(thr);
}

dp_thread_t dp_thread_self(void)
{
    return GetCurrentThread();
}

void dp_thread_join(dp_thread_t thr)
{
    WaitForSingleObject(thr, INFINITE);
    CloseHandle(thr);
}

#endif

/** global lock list for openssl locks */
static lock_basic_t *dp_openssl_locks = NULL;

static void dp_openssl_lock_cb(int mode, int type, const char *file, int line)
{
    if((mode&CRYPTO_LOCK)) {
        lock_basic_lock(&dp_openssl_locks[type]);
    } else {
        lock_basic_unlock(&dp_openssl_locks[type]);
    }
}

/** callback that gets thread id for openssl */
#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_0_0
    static int openssl_set_id_callback(void (*threadid_func)(CRYPTO_THREADID *))
    {
        return CRYPTO_THREADID_set_callback(threadid_func);
    }
    static void dp_openssl_id_cb(CRYPTO_THREADID * id)
    {
        CRYPTO_THREADID_set_numeric(id, (unsigned long)dp_thread_self());
    }
#else
    static void openssl_set_id_callback(unsigned long (func)(void))
    {
        CRYPTO_set_id_callback(func);
    }
    static unsigned long dp_openssl_id_cb(void)
    {
        return (unsigned long)dp_thread_self();
    }
#endif

int dp_openssl_lock_init(void)
{
    int i;
    dp_openssl_locks = (lock_basic_t*)malloc(
        sizeof(lock_basic_t)*CRYPTO_num_locks());
    if(!dp_openssl_locks)
        return 0;
    for(i=0; i<CRYPTO_num_locks(); i++) {
        lock_basic_init(&dp_openssl_locks[i]);
    }

    //openssl 1.0.0 CRYPTO_set_id_callback was replaced by CRYPTO_THREADID_set_callback
    openssl_set_id_callback(dp_openssl_id_cb);

    CRYPTO_set_locking_callback(&dp_openssl_lock_cb);
    return 1;
}

void dp_openssl_lock_delete(void)
{
    int i;
    if(!dp_openssl_locks)
        return;
    openssl_set_id_callback(NULL);
    CRYPTO_set_locking_callback(NULL);
    for(i=0; i<CRYPTO_num_locks(); i++) {
        lock_basic_destroy(&dp_openssl_locks[i]);
    }
    free(dp_openssl_locks);
}
