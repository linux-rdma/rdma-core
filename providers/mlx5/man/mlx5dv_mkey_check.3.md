---
layout: page
title: mlx5dv_mkey_check
section: 3
tagline: Verbs
---

# NAME

mlx5dv_mkey_check -  Check a MKEY for errors

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

int mlx5dv_mkey_check(struct mlx5dv_mkey *mkey,
		      struct mlx5dv_mkey_err *err_info);
```

# DESCRIPTION

Checks *mkey* for errors and provides the result in *err_info* on success.

This should be called after using a MKEY configured with signature validation
in a transfer operation. While the transfer operation itself may be completed
successfully (i.e. no transport related errors occurred), there still may be
errors related to the integrity of the data. The first of these errors is
reported to the MKEY and kept there until application software queries it by
calling this API.

The type of error indicates which part of the signature was bad (guard, reftag
or apptag). Also provided is the actual calculated value based on the
transferred data, and the expected value based on the signature fields. Last
part provided is the offset in the transfer that caused the error.

# ARGUMENTS

*mkey*

:	The MKEY to check for errors.

*err_info*

:	The result of the MKEY check, information about the errors detected,
	if any.

	```c
	struct mlx5dv_mkey_err {
		enum mlx5dv_mkey_err_type err_type;
		union {
			struct mlx5dv_sig_err sig;
		} err;
	};
	```
	*err_type*

	:	What kind of error happened. If several errors are found,
		only a single error is reported in this priority:
		**MLX5DV_MKEY_SIG_BLOCK_BAD_GUARD**,
		**MLX5DV_MKEY_SIG_BLOCK_BAD_APPTAG**,
		**MLX5DV_MKEY_SIG_BLOCK_BAD_REFTAG**.

		**MLX5DV_MKEY_NO_ERR**

		:	No error is detected for the MKEY.

		**MLX5DV_MKEY_SIG_BLOCK_BAD_GUARD**

		:	A signature error was detected in CRC/CHECKSUM for
			T10-DIF or CRC32/CRC32C/CRC64_XP10 (depends on the
			configured signature type). Additional information
			about the error is provided in **struct mlx5dv_sig_err**
			of *err*.

		**MLX5DV_MKEY_SIG_BLOCK_BAD_REFTAG**

		:	A signature error was detected in the reference tag.
			This kind of signature error is relevant for T10-DIF
			only. Additional information about the error is provided
			in **struct mlx5dv_sig_err** of *err*.

		**MLX5DV_MKEY_SIG_BLOCK_BAD_APPTAG**

		:	A signature error was detected in the application tag.
			This kind of signature error is relevant for T10-DIF
			only. Additional information about the error is provided
			in **struct mlx5dv_sig_err** of *err*.

	*err*

	:	Information about the detected error if *err_type* is not
		**MLX5DV_MKEY_NO_ERR**. Otherwise, its value is not defined.

## Signature error

```c
struct mlx5dv_sig_err {
	uint64_t actual_value;
	uint64_t expected_value;
	uint64_t offset;
};
```

*actual_value*

:	The actual value that was calculated from the transferred data.

*expected_value*

:	The expected value based on what appears in the signature respected
	field.

*offset*

:	The offset within the transfer where the error happened. In block
	signature, this is guaranteed to be a block boundary offset.

# RETURN VALUE
0 on success or the value of errno on failure (which indicates the failure reason).

# NOTES
A DEVX context should be opened by using **mlx5dv_open_device**(3).

Checking the MKEY for errors should be done after the application knows the data
transfer that was using the MKEY has finished. Application should wait for the
respected completion (if this was a local MKEY) or wait for a received message
from a peer (if this was a remote MKEY).

# SEE ALSO
**mlx5dv_wr_mkey_configure**(3),  **mlx5dv_wr_set_mkey_sig_block**(3),
**mlx5dv_create_mkey**(3), **mlx5dv_destroy_mkey**(3)

# AUTHORS

Oren Duer <oren@nvidia.com>

Sergey Gorenko <sergeygo@nvidia.com>
