/*
 * Copyright (c) 2009 Intel Corporation. All rights reserved.
 *
 * This software is available to you under the OpenIB.org BSD license
 * below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AWV
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _DLIST_H_
#define _DLIST_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _DLIST_ENTRY {
	struct _DLIST_ENTRY	*Next;
	struct _DLIST_ENTRY	*Prev;

}	DLIST_ENTRY;

static void DListInit(DLIST_ENTRY *pHead)
{
	pHead->Next = pHead;
	pHead->Prev = pHead;
}

static int DListEmpty(DLIST_ENTRY *pHead)
{
	return pHead->Next == pHead;
}

static void DListInsertAfter(DLIST_ENTRY *pNew, DLIST_ENTRY *pHead)
{
	pNew->Next = pHead->Next;
	pNew->Prev = pHead;
	pHead->Next->Prev = pNew;
	pHead->Next = pNew;
}

static void DListInsertBefore(DLIST_ENTRY *pNew, DLIST_ENTRY *pHead)
{
	DListInsertAfter(pNew, pHead->Prev);
}

#define DListInsertHead DListInsertAfter
#define DListInsertTail DListInsertBefore

static void DListRemove(DLIST_ENTRY *pEntry)
{
	pEntry->Prev->Next = pEntry->Next;
	pEntry->Next->Prev = pEntry->Prev;
}

#ifdef __cplusplus
}
#endif

#endif // _DLIST_H_
