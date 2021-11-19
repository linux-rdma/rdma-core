---
layout: page
title: mlx5dv_wr_set_mkey_sig_block
section: 3
tagline: Verbs
---

# NAME

mlx5dv_wr_set_mkey_sig_block -  Configure a MKEY for block signature (data integrity) operation.

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

static inline void mlx5dv_wr_set_mkey_sig_block(struct mlx5dv_qp_ex *mqp,
                                                const struct mlx5dv_sig_block_attr *attr)
```

# DESCRIPTION

Configure a MKEY with block-level data protection properties. With this,
the device can add/modify/strip/validate integrity fields per block when
transmitting data from memory to network and when receiving data from network
to memory.

This setter can be optionally called after a MKEY configuration work request
posting has started using **mlx5dv_wr_mkey_configure**(3). Configuring block
signature properties to a MKEY is done by describing what kind of signature is
required (or expected) in two domains: the wire domain and the memory domain.

The MKEY represents a virtually contiguous memory, by configuring a layout to it.
The memory signature domain describes whether data in this virtually contiguous
memory includes integrity fields, and if so, what kind and what block size.

The wire signature domain describes the same kind of properties for the data as
it is seen on the wire. Now, depending on the actual operation that happens (TX
or RX), the device will do the "right thing" based on the signature
configurations of the two domains.

## Example 1:

Memory signature domain is configured for CRC32 every 512B block.

Wire signature domain is configured for no signature.

A SEND is issued using the MKEY as a local key.

Result: device will gather the data with the CRC32 fields from the MKEY (using
whatever layout configured to the MKEY to locate the actual memory), validate
each CRC32 against the previous 512 bytes of data, strip the CRC32 field, and
transmit only 512 bytes of data to the wire.

### Example 1.1:

Same as above, but a RECV is issued with the same key, and RX happens.

Result: device will receive the data from the wire, scatter it to the MKEY
(using whatever layout configured to the MKEY to locate the actual memory),
generating and scattering additional CRC32 field after every 512 bytes that
are scattered.

## Example 2:

Memory signature domain is configured for no signature.

Wire signature domain is configured for T10DIF every 4K block.

The MKEY is sent to a remote node that issues a RDMA_READ to this MKEY.

Result: device will gather the data from the MKEY (using whatever layout
configured to the MKEY to locate the actual memory), transmit it to the wire
while generating an additional T10DIF field every 4K of data.

### Example 2.1:

Same as above, but remote node issues a RDMA_WRITE to this MKEY.

Result: Device will receive the data from the wire, validate each T10DIF field
against the previous 4K of data, strip the T10DIF field, and scatter the data
alone to the MKEY (using whatever layout configured to the MKEY to locate the
actual memory).

# ARGUMENTS

*mqp*

:       The QP where an MKEY configuration work request was created by
	**mlx5dv_wr_mkey_configure()**.

*attr*

:	Block signature attributes to set for the MKEY.

## Block signature attributes

Block signature attributes describe the input and output data structures in
memory and wire domains.

```c
struct mlx5dv_sig_block_attr {
	const struct mlx5dv_sig_block_domain *mem;
	const struct mlx5dv_sig_block_domain *wire;
	uint32_t flags;
	uint8_t check_mask;
	uint8_t copy_mask;
	uint64_t comp_mask;
};
```

*mem*

:	A pointer to the signature configuration for the memory domain or NULL
	if the domain does not have a signature.

*wire*

:	A pointer to the signature configuration for the wire domain or NULL
	if the domain does not have a signature.

*flags*

:	A bitwise OR of the various values described below.

	**MLX5DV_SIG_BLOCK_ATTR_FLAG_COPY_MASK**

	:	If the bit is not set then *copy_mask* is ignored. See details
		in the *copy_mask* description.

*check_mask*

:	Each bit of *check_mask* corresponds to a byte of the signature field in
	input domain. Byte of the input signature is checked if corresponding
	bit in *check_mask* is set. Bits not relevant to the signature type are
	ignored.

	Table: Layout of *check_mask*.

	| check_mask (bits)    |    7     |    6     |    5     |    4     |    3     |    2     |    1     |    0     |
	| -----------------    | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
	| T10-DIF (bytes)      | GUARD[1] | GUARD[0] |  APP[1]  |  APP[0]  |  REF[3]  |  REF[2]  |  REF[1]  |  REF[0]  |
	| CRC32C/CRC32 (bytes) |   3      |    2     |    1     |    0     |          |          |          |          |
	| CRC64_XP10 (bytes)   |   7      |    6     |    5     |    4     |    3     |    2     |    1     |    0     |

	Common used masks are defined in **enum mlx5dv_sig_mask**. Other
	masks are also supported. Follow the above table to define a custom
	mask. For example, this can be useful for the application tag field of
	the T10DIF signature. Using the application tag is out of the scope
	of the T10DIF specification and depends on the implementation.
	*check_mask* allows validating a part of the application tag if needed.

*copy_mask*

:	A mask to specify what part of the signature is copied from the source
	domain to the destination domain. The copy mask is usually calculated
	automatically. The signature is copied if the same signature type is
	configurted on both domains. The parts of the T10-DIF are compared and
	handled independetly.

	If **MLX5DV_SIG_BLOCK_ATTR_FLAG_COPY_MASK** is set the
	*copy_mask* attribute overrides the calculated value of the copy mask.
	Otherwise, *copy_mask* is ignored.

	Each bit of *copy_mask* corresponds to a byte of the signature field.
	If corresponding bit in *copy_mask* is set, byte of the signature is
	copied from the input domain to the output domain. Calculation
	according to the output domain configuration is not performed in this
	case. Bits not relevant to the signature type are ignored. *copy_mask*
	may be used only if input and output domains have the same structure,
	i.e. same block size and signature type. The MKEY configuration will
	fail if **MLX5DV_SIG_BLOCK_ATTR_FLAG_COPY_MASK** is set but the domains
	have different signature structures.

	The predefined masks are available in **enum mlx5dv_sig_mask**. It is
	also supported to specify a user-defined mask. Follow the table in
	*check_mask* description to define a custom mask.

	*copy_mask* can be useful when some bytes of the signature are not
	known in advance, hence can't be checked, but shall be preserved.
	In this case corresponding bits should be cleared in *check_mask*
	and set in *copy_mask*.

*comp_mask*
:	Reserved for future extension, must be 0 now.

## Block signature domain

```c
struct mlx5dv_sig_block_domain {
	enum mlx5dv_sig_type sig_type;
	union {
		const struct mlx5dv_sig_t10dif *dif;
		const struct mlx5dv_sig_crc *crc;
	} sig;
	enum mlx5dv_block_size block_size;
	uint64_t comp_mask;
};

```
*sig_type*

:	The signature type for this domain, one of the following

	**MLX5DV_SIG_TYPE_T10DIF**

	:	The block-level data protection defined in the T10
		specifications (T10 SBC-3).

	**MLX5DV_SIG_TYPE_CRC**

	:	The block-level data protection based on cyclic redundancy
		check (CRC). The specific type of CRC is defined in *sig*.

*sig*

:	Depending on *sig_type*, this is the per signature type specific
	configuration.

*block_size*

:	The block size for this domain, one of **enum mlx5dv_sig_block_size**.

*comp_mask*

:	Reserved for future extension, must be 0 now.

## CRC signature

```c
struct mlx5dv_sig_crc {
	enum mlx5dv_sig_crc_type type;
	uint64_t seed;
};
```

*type*

:	The specific CRC type, one of the following.

	**MLX5DV_SIG_CRC_TYPE_CRC32**

	:	CRC32 signature is created by calculating a 32-bit CRC defined
		in Fibre Channel Physical and Signaling Interface (FC-PH),
		ANSI X3.230:1994.

	**MLX5DV_SIG_CRC_TYPE_CRC32C**

	:	CRC32C signature is created by calculating a 32-bit CRC called
		the Castagnoli CRC, defined in the Internet Small Computer
		Systems Interface (iSCSI) rfc3720.

	**MLX5DV_SIG_CRC_TYPE_CRC64_XP10**

	:	CRC64_XP10 signature is created by calculating a 64-bit CRC
		defined in Microsoft XP10 compression standard.

*seed*

:	A seed for the CRC calculation per block. Bits not relevant to the
	CRC type are ignored. For example, all bits are used for CRC64_XP10,
	but only the 32 least significant bits are used for CRC32/CRC32C.

	Only the following values are supported as a seed:
	CRC32/CRC32C - 0, 0xFFFFFFFF(UINT32_MAX);
	CRC64_XP10 - 0, 0xFFFFFFFFFFFFFFFF(UINT64_MAX).

## T10DIF signature

T10DIF signature is defined in the T10 specifications (T10 SBC-3) for
block-level data protection. The size of data block protected by T10DIF must be
modulo 8bytes as required in the T10DIF specifications. Note that when setting
the initial LBA value to *ref_tag*, it should be the value of the first block
to be transmitted.

```c
struct mlx5dv_sig_t10dif {
	enum mlx5dv_sig_t10dif_bg_type bg_type;
	uint16_t bg;
	uint16_t app_tag;
	uint32_t ref_tag;
	uint16_t flags;
};
```

*bg_type*

:	The block guard type to be used, one of the following.

	**MLX5DV_SIG_T10DIF_CRC**

	:	Use CRC in the block guard field as required in the T10DIF
		specifications.

	**MLX5DV_SIG_T10DIF_CSUM**

	:	Use IP checksum instead of CRC in the block guard field.

*bg*

:	A seed for the block guard calculation per block.

	The following values are supported as a seed: 0, 0xFFFF(UINT16_MAX).

*app_tag*

:	An application tag to generate or validate.

*ref_tag*

:	A reference tag to generate or validate.

*flags*

:	Flags for the T10DIF attributes, one of the following.

	**MLX5DV_SIG_T10DIF_FLAG_REF_REMAP**

	:	Increment reference tag per block.

	**MLX5DV_SIG_T10DIF_FLAG_APP_ESCAPE**

	:	Do not check block guard if application tag is 0xFFFF.

	**MLX5DV_SIG_T10DIF_FLAG_APP_REF_ESCAPE**

	:	Do not check block guard if application tag is 0xFFFF and
		reference tag is 0xFFFFFFFF.

# RETURN VALUE

This function does not return a value.

In case of error, user will be notified later when completing the DV WRs chain.

# Notes

A DEVX context should be opened by using **mlx5dv_open_device**(3).

MKEY must be created with **MLX5DV_MKEY_INIT_ATTR_FLAGS_BLOCK_SIGNATURE** flag.

The last operation posted on the supplied QP should be
**mlx5dv_wr_mkey_configure**(3), or one of its related setters, and the
operation must still be open (no doorbell issued).

In case of **ibv_wr_complete()** failure or calling to **ibv_wr_abort()**, the
MKey may be left in an unknown state. The next configuration of it should not
assume any previous state of the MKey, i.e. signature/crypto should be
re-configured or reset, as required. For example, assuming
**mlx5dv_wr_set_mkey_sig_block()** and then **ibv_wr_abort()** were called,
then on the next configuration of the MKey, if signature is not needed, it
should be reset using **MLX5DV_MKEY_CONF_FLAG_RESET_SIG_ATTR**.

# SEE ALSO

**mlx5dv_wr_mkey_configure**(3), **mlx5dv_create_mkey**(3),
**mlx5dv_destroy_mkey**(3)

# AUTHORS

Oren Duer  <oren@nvidia.com>

Sergey Gorenko <sergeygo@nvidia.com>
