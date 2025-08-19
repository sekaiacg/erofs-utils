/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
#ifndef __EROFS_LOCK_H
#define __EROFS_LOCK_H

#include "defs.h"

#if defined(HAVE_PTHREAD_H) && defined(EROFS_MT_ENABLED)
#include <pthread.h>

typedef pthread_mutex_t erofs_mutex_t;

static inline void erofs_mutex_init(erofs_mutex_t *lock)
{
	pthread_mutex_init(lock, NULL);
}
#define erofs_mutex_lock	pthread_mutex_lock
#define erofs_mutex_unlock	pthread_mutex_unlock

#define EROFS_DEFINE_MUTEX(lock)	\
	erofs_mutex_t lock = PTHREAD_MUTEX_INITIALIZER

typedef pthread_rwlock_t erofs_rwsem_t;

static inline void erofs_init_rwsem(erofs_rwsem_t *lock)
{
	pthread_rwlock_init(lock, NULL);
}
#define erofs_down_read		pthread_rwlock_rdlock
#define erofs_down_write	pthread_rwlock_wrlock
#define erofs_up_read		pthread_rwlock_unlock
#define erofs_up_write		pthread_rwlock_unlock
#else
typedef struct {} erofs_mutex_t;

static inline void erofs_mutex_init(erofs_mutex_t *lock) {}
static inline void erofs_mutex_lock(erofs_mutex_t *lock) {}
static inline void erofs_mutex_unlock(erofs_mutex_t *lock) {}

#define EROFS_DEFINE_MUTEX(lock)	\
	erofs_mutex_t lock = {}

typedef struct {} erofs_rwsem_t;
static inline void erofs_init_rwsem(erofs_rwsem_t *lock) {}
static inline void erofs_down_read(erofs_rwsem_t *lock) {}
static inline void erofs_down_write(erofs_rwsem_t *lock) {}
static inline void erofs_up_read(erofs_rwsem_t *lock) {}
static inline void erofs_up_write(erofs_rwsem_t *lock) {}

#endif
#endif
