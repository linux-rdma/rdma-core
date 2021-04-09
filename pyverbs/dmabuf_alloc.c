// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright 2020 Intel Corporation. All rights reserved. See COPYING file
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <drm.h>
#include <i915_drm.h>
#include <amdgpu_drm.h>
#include "dmabuf_alloc.h"

/*
 * Abstraction of the buffer allocation mechanism using the DRM interface.
 * The interface is accessed by ioctl() calls over the '/dev/dri/renderD*'
 * device. Successful access usually requires the effective user id being
 * in the 'render' group.
 */

struct drm {
	int fd;
	int (*alloc)(struct drm *drm, uint64_t size, uint32_t *handle, int gtt);
	int (*mmap_offset)(struct drm *drm, uint32_t handle, uint64_t *offset);
};

static int i915_alloc(struct drm *drm, uint64_t size, uint32_t *handle, int gtt)
{
	struct drm_i915_gem_create gem_create = {};
	int err;

	gem_create.size = size;
	err = ioctl(drm->fd, DRM_IOCTL_I915_GEM_CREATE, &gem_create);
	if (err)
		return err;

	*handle = gem_create.handle;
	return 0;
}

static int amdgpu_alloc(struct drm *drm, size_t size, uint32_t *handle, int gtt)
{
	union drm_amdgpu_gem_create gem_create = {{}};
	int err;

	gem_create.in.bo_size = size;
	if (gtt) {
		gem_create.in.domains = AMDGPU_GEM_DOMAIN_GTT;
		gem_create.in.domain_flags = AMDGPU_GEM_CREATE_CPU_GTT_USWC;
	} else {
		gem_create.in.domains = AMDGPU_GEM_DOMAIN_VRAM;
		gem_create.in.domain_flags =
			AMDGPU_GEM_CREATE_CPU_ACCESS_REQUIRED;
	}
	err = ioctl(drm->fd, DRM_IOCTL_AMDGPU_GEM_CREATE, &gem_create);
	if (err)
		return err;

	*handle = gem_create.out.handle;
	return 0;
}

static int i915_mmap_offset(struct drm *drm, uint32_t handle, uint64_t *offset)
{
	struct drm_i915_gem_mmap_gtt gem_mmap = {};
	int err;

	gem_mmap.handle = handle;
	err = ioctl(drm->fd, DRM_IOCTL_I915_GEM_MMAP_GTT, &gem_mmap);
	if (err)
		return err;

	*offset = gem_mmap.offset;
	return 0;
}

static int amdgpu_mmap_offset(struct drm *drm, uint32_t handle,
			      uint64_t *offset)
{
	union drm_amdgpu_gem_mmap gem_mmap = {{}};
	int err;

	gem_mmap.in.handle = handle;
	err = ioctl(drm->fd, DRM_IOCTL_AMDGPU_GEM_MMAP, &gem_mmap);
	if (err)
		return err;

	*offset = gem_mmap.out.addr_ptr;
	return 0;
}

static struct drm *drm_open(int gpu)
{
	char path[32];
	struct drm_version version = {};
	char name[16] = {};
	int err;
	struct drm *drm;

	drm = malloc(sizeof(*drm));
	if (!drm)
		return NULL;

	snprintf(path, sizeof(path), "/dev/dri/renderD%d", gpu + 128);

	drm->fd = open(path, O_RDWR);
	if (drm->fd < 0)
		goto out_free;

	version.name = name;
	version.name_len = 16;
	err = ioctl(drm->fd, DRM_IOCTL_VERSION, &version);
	if (err)
		goto out_close;

	if (!strcmp(name, "amdgpu")) {
		drm->alloc = amdgpu_alloc;
		drm->mmap_offset = amdgpu_mmap_offset;
	} else if (!strcmp(name, "i915")) {
		drm->alloc = i915_alloc;
		drm->mmap_offset = i915_mmap_offset;
	} else {
		errno = EOPNOTSUPP;
		goto out_close;
	}
	return drm;

out_close:
	close(drm->fd);

out_free:
	free(drm);
	return NULL;
}

static void drm_close(struct drm *drm)
{
	if (!drm || drm->fd < 0)
		return;

	close(drm->fd);
	free(drm);
}

static void drm_free_buf(struct drm *drm, uint32_t handle)
{
	struct drm_gem_close close = {};

	close.handle = handle;
	ioctl(drm->fd, DRM_IOCTL_GEM_CLOSE, &close);
}

static int drm_alloc_buf(struct drm *drm, size_t size, uint32_t *handle,
			 int *fd, int gtt)
{
	struct drm_prime_handle prime_handle = {};
	int err;

	if (!drm || drm->fd < 0)
		return -EINVAL;

	err = drm->alloc(drm, size, handle, gtt);
	if (err)
		return err;

	prime_handle.handle = *handle;
	prime_handle.flags = O_RDWR;
	err = ioctl(drm->fd, DRM_IOCTL_PRIME_HANDLE_TO_FD, &prime_handle);
	if (err) {
		drm_free_buf(drm, *handle);
		return err;
	}

	*fd = prime_handle.fd;
	return 0;
}

static int drm_map_buf(struct drm *drm, uint32_t handle, uint64_t *offset)
{
	if (!drm || drm->fd < 0)
		return -EINVAL;

	return drm->mmap_offset(drm, handle, offset);
}

/*
 * Abstraction of dmabuf object, allocated using the DRI abstraction defined
 * above.
 */

struct dmabuf {
	struct drm *drm;
	int fd;
	uint32_t handle;
	uint64_t map_offset;
};

/*
 * dmabuf_alloc - allocate a dmabuf from GPU
 * @size - byte size of the buffer to allocate
 * @gpu - the GPU unit to use
 * @gtt - if true, allocate from GTT (Graphics Translation Table) instead of VRAM
 */
struct dmabuf *dmabuf_alloc(uint64_t size, int gpu, int gtt)
{
	struct dmabuf *dmabuf;
	int err;

	dmabuf = malloc(sizeof(*dmabuf));
	if (!dmabuf)
		return NULL;

	dmabuf->drm = drm_open(gpu);
	if (!dmabuf->drm)
		goto out_free;

	err = drm_alloc_buf(dmabuf->drm, size, &dmabuf->handle, &dmabuf->fd, gtt);
	if (err)
		goto out_close;

	err = drm_map_buf(dmabuf->drm, dmabuf->handle, &dmabuf->map_offset);
	if (err)
		goto out_free_buf;

	return dmabuf;

out_free_buf:
	drm_free_buf(dmabuf->drm, dmabuf->handle);

out_close:
	drm_close(dmabuf->drm);

out_free:
	free(dmabuf);
	return NULL;
}

void dmabuf_free(struct dmabuf *dmabuf)
{
	if (!dmabuf)
		return;

	close(dmabuf->fd);
	drm_free_buf(dmabuf->drm, dmabuf->handle);
	drm_close(dmabuf->drm);
	free(dmabuf);
}

int dmabuf_get_drm_fd(struct dmabuf *dmabuf)
{
	if (!dmabuf || !dmabuf->drm)
		return -1;

	return dmabuf->drm->fd;
}

int dmabuf_get_fd(struct dmabuf *dmabuf)
{
	if (!dmabuf)
		return -1;

	return dmabuf->fd;
}

uint64_t dmabuf_get_offset(struct dmabuf *dmabuf)
{
	if (!dmabuf)
		return -1;

	return dmabuf->map_offset;
}

