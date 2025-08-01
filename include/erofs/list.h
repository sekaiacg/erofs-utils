/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
/*
 * Copyright (C) 2018 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#ifndef __EROFS_LIST_HEAD_H
#define __EROFS_LIST_HEAD_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "defs.h"

struct list_head {
	struct list_head *prev;
	struct list_head *next;
};

#define LIST_HEAD_INIT(name)                                                   \
	{                                                                      \
		&(name), &(name)                                               \
	}

#define LIST_HEAD(name) struct list_head name = LIST_HEAD_INIT(name)

static inline void init_list_head(struct list_head *list)
{
	list->prev = list;
	list->next = list;
}

static inline void __list_add(struct list_head *entry,
			      struct list_head *prev,
			      struct list_head *next)
{
	entry->prev = prev;
	entry->next = next;
	prev->next  = entry;
	next->prev  = entry;
}

static inline void list_add(struct list_head *entry, struct list_head *head)
{
	__list_add(entry, head, head->next);
}

static inline void list_add_tail(struct list_head *entry,
				 struct list_head *head)
{
	__list_add(entry, head->prev, head);
}

static inline void __list_del(struct list_head *prev, struct list_head *next)
{
	prev->next = next;
	next->prev = prev;
}

static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	entry->prev = entry->next = NULL;
}

static inline int list_empty(struct list_head *head)
{
	return head->next == head;
}

static inline void __list_splice(struct list_head *list,
		struct list_head *prev, struct list_head *next)
{
	struct list_head *first = list->next;
	struct list_head *last = list->prev;

	first->prev = prev;
	prev->next = first;

	last->next = next;
	next->prev = last;
}

static inline void list_splice_tail(struct list_head *list,
				    struct list_head *head)
{
	if (!list_empty(list))
		__list_splice(list, head->prev, head);
}

#define list_entry(ptr, type, member) container_of(ptr, type, member)

#define list_first_entry(ptr, type, member)                                    \
	list_entry((ptr)->next, type, member)

#define list_last_entry(ptr, type, member)                                     \
	list_entry((ptr)->prev, type, member)

#define list_next_entry(pos, member)                                           \
	list_entry((pos)->member.next, typeof(*(pos)), member)

#define list_prev_entry(pos, member)                                           \
	list_entry((pos)->member.prev, typeof(*(pos)), member)

#define list_for_each(pos, head)                                               \
	for (pos = (head)->next; pos != (head); pos = pos->next)

#define list_for_each_safe(pos, n, head)                                       \
	for (pos = (head)->next, n = pos->next; pos != (head);                 \
	     pos = n, n = pos->next)

#define list_for_each_entry(pos, head, member)                                 \
	for (pos = list_first_entry(head, typeof(*pos), member);               \
	     &pos->member != (head);                                           \
	     pos = list_next_entry(pos, member))

#define list_for_each_entry_reverse(pos, head, member)                         \
	for (pos = list_last_entry(head, typeof(*pos), member);               \
	     &pos->member != (head);                                           \
	     pos = list_prev_entry(pos, member))

#define list_for_each_entry_from(pos, head, member)                            \
	for (; &pos->member != (head); pos = list_next_entry(pos, member))

#define list_for_each_entry_safe(pos, n, head, member)                         \
	for (pos = list_first_entry(head, typeof(*pos), member),               \
	    n    = list_next_entry(pos, member);                               \
	     &pos->member != (head);                                           \
	     pos = n, n = list_next_entry(n, member))

#define list_for_each_entry_safe_from(pos, n, head, member)		\
	for (n = list_next_entry(pos, member);				\
	     &pos->member != (head);					\
	     pos = n, n = list_next_entry(n, member))

#ifdef __cplusplus
}
#endif

#endif
