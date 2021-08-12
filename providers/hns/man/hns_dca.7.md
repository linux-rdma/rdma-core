---
layout: page
title: DCA
section: 7
tagline: DCA
date: 2021-07-13
header: "HNS DCA Manual"
footer: hns
---

# NAME

DCA - Dynamic Context Attachment

This allows all WQEs to share a memory pool that belongs to the user context.

# DESCRIPTION

The DCA feature aims to reduce memory consumption by sharing WQE memory for QPs working in sparse traffic scenarios.

The DCA memory pool consists of multiple umem objects. Each umem object is a buffer allocated in user driver and register into kernel driver. The ULP need to setup the memory pool's parameter by calling hnsdv_open_device() and the driver will expand or shrink the memory pool based on this parameter.

When a QP's DCA was enabled by setting create flags through ibv_create_qp_ex(), the WQE buffer will not be allocated directly until the ULP invokes the ibv_post_xxx(). If the memory in the pool is insufficient and the capacity expansion conditions are met, the driver will add new umem objects to the pool.

When all WQEs of a QP are not used by the ROCEE after ibv_poll_cq() or ibv_modify_qp() are invoked, the WQE buffer will be reclaimed to the DCA memory pool. If the free memory in the pool meets the shrink conditions, the driver will delete the unused umem object.

# SEE ALSO

*hnsdv_open_device(3)*, *hnsdv_create_qp(3)*

# AUTHORS

Xi Wang <wangxi11@huawei.com>

Weihang Li <liweihang@huawei.com>
