/*
 * Copyright (c) 2009 Intel Corporation.  All rights reserved.
 *
 * This software is available to you under the OpenFabrics.org BSD license
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

#if !defined(OSD_H)
#define OSD_H

#include <windows.h>
#include <process.h>
#include <malloc.h>
#include <winsock2.h>

#define __func__ __FUNCTION__
#define LIB_DESTRUCTOR
#define CDECL_FUNC __cdecl

typedef struct { volatile LONG val; } atomic_t;
#define atomic_inc(v) InterlockedIncrement(&(v)->val)
#define atomic_dec(v) InterlockedDecrement(&(v)->val)
#define atomic_get(v) ((v)->val)
#define atomic_set(v, s) ((v)->val = s)
#define atomic_init(v) ((v)->val = 0)

#define event_t          HANDLE
#define event_init(e)    *(e) = CreateEvent(NULL, FALSE, FALSE, NULL)
#define event_signal(e)  SetEvent(*(e))
#define event_wait(e, t) WaitForSingleObject(*(e), t)	

#define lock_t       CRITICAL_SECTION
#define lock_init    InitializeCriticalSection
#define lock_acquire EnterCriticalSection
#define lock_release LeaveCriticalSection

static __inline int osd_init()
{
	WSADATA wsadata;
	return WSAStartup(MAKEWORD(2, 2), &wsadata);
}

static __inline void osd_close()
{
	WSACleanup();
}

#define stricmp  _stricmp
#define strnicmp _strnicmp

#define socket_errno WSAGetLastError
#define SHUT_RDWR SD_BOTH

static __inline UINT64 time_stamp_us(void)
{
	LARGE_INTEGER cnt, freq;
	QueryPerformanceFrequency(&freq);
	QueryPerformanceCounter(&cnt);
	return (UINT64) cnt.QuadPart / freq.QuadPart * 1000000;
}

#define time_stamp_ms() (time_stamp_us() * 1000)

#define getpid() ((int) GetCurrentProcessId())
#define PER_THREAD __declspec(thread)
#define beginthread(func, arg)	(int) _beginthread(func, 0, arg)
#define container_of CONTAINING_RECORD

#endif /* OSD_H */
