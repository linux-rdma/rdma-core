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

#include "..\..\..\..\etc\user\getopt.c"
#include "..\src\acme.c"
#include "..\..\..\..\etc\user\inet.c"
#include <rdma/winverbs.h>

extern struct ibv_context **verbs;
extern int dev_cnt;
extern int verbose;

int gen_addr_ip(FILE *f)
{
	WV_DEVICE_ADDRESS devaddr;
	IWVProvider *prov;
	HRESULT hr;
	struct addrinfo *res, hint, *ai;
	char ip[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];
	int i;

	hr = WvGetObject(&IID_IWVProvider, (LPVOID *) &prov);
	if (FAILED(hr))
		return hr;

	memset(&hint, 0, sizeof hint);
	hint.ai_protocol = IPPROTO_TCP;

	hr = getaddrinfo("..localmachine", NULL, &hint, &res);
	if (hr) {
		printf("getaddrinfo error %d\n", hr);
		goto release;
	}

	for (ai = res; ai; ai = ai->ai_next) {
		switch (ai->ai_family) {
		case AF_INET:
			inet_ntop(ai->ai_family,
				&((struct sockaddr_in *) ai->ai_addr)->sin_addr, ip, sizeof ip);
			break;
		case AF_INET6:
			inet_ntop(ai->ai_family,
				&((struct sockaddr_in6 *) ai->ai_addr)->sin6_addr, ip, sizeof ip);
			break;
		default:
			continue;
		}

		hr = prov->lpVtbl->TranslateAddress(prov, ai->ai_addr, &devaddr);
		if (FAILED(hr))
			continue;

		for (i = 0; i < dev_cnt; i++) {
			if (devaddr.DeviceGuid == ibv_get_device_guid(verbs[i]->device)) {
				if (verbose) {
					printf("%s %s %d 0x%x\n", ip, verbs[i]->device->name,
					       devaddr.PortNumber, ntohs(devaddr.Pkey));
				}
				fprintf(f, "%s %s %d 0x%x\n", ip, verbs[i]->device->name,
					devaddr.PortNumber, ntohs(devaddr.Pkey));
			}
		}
	}

	hr = 0;
	freeaddrinfo(res);
release:
	prov->lpVtbl->Release(prov);
	return hr;
}
