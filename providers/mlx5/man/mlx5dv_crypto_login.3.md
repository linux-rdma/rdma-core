---
layout: page
title: mlx5dv_crypto_login / mlx5dv_crypto_login_query_state / mlx5dv_crypto_logout
section: 3
tagline: Verbs
---

# NAME

mlx5dv_crypto_login - Creates a crypto login session

mlx5dv_crypto_login_query_state - Queries the state of the current crypto login session

mlx5dv_crypto_logout - Logs out from the current crypto login session

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

int mlx5dv_crypto_login(struct ibv_context *context,
			struct mlx5dv_crypto_login_attr *login_attr);

int mlx5dv_crypto_login_query_state(struct ibv_context *context,
				    enum mlx5dv_crypto_login_state *state);

int mlx5dv_crypto_logout(struct ibv_context *context);
```

# DESCRIPTION

When using a crypto engine that is in wrapped import method, an active crypto
login session must be present in order to create and query Data Encryption Keys
(DEKs).

**mlx5dv_crypto_login()** Creates a crypto login session with the credential
given in *login_attr* and associates it with *context*. Only one active crypto
login session can be associated per device context.

**mlx5dv_crypto_login_query_state()** queries the state of the crypto login
session associated with *context* and returns the state in *state*, which
indicates whether it is valid, invalid or doesn't exist.
A valid crypto login session can become invalid if the credential or the import
KEK used in the crypto login session were deleted during the login session
(for example by a crypto officer).
In this case, **mlx5dv_crypto_logout()** should be called to destroy the current
invalid crypto login session and if still necessary, **mlx5dv_crypto_login()**
should be called to create a new crypto login session with valid credential and
import KEK.

**mlx5dv_crypto_logout()** logs out from the current crypto login session
associated with *context*.

Existing DEKs that were previously loaded to the device during a crypto login
session don't need an active crypto login session in order to be used (in MKey
or during traffic).

# ARGUMENTS

## context

The device context to associate the crypto login session with.

## login_attr

Crypto login attributes specify the credential to login with and the import KEK
to be used for secured communications during the crypto login session.

```c
struct mlx5dv_crypto_login_attr {
	uint32_t credential_id;
	uint32_t import_kek_id;
	char credential[48];
	uint64_t comp_mask;
};
```

*credential_id*

:	An ID of a credential, from the credentials stored on the device,
	that indicates the credential that should be validated against the
	credential provided in *credential*.

*import_kek_id*

:	An ID of an import KEK, from the import KEKs stored on the device,
	that indicates the import KEK that will be used for unwrapping the
	credential provided in *credential* and also for all other secured
	communications during the crypto login session.

*credential*

:	The credential to login with. Must be provided wrapped by the AES key
	wrap algorithm using the import KEK indicated by *import_kek_id*.

*comp_mask*

:	Reserved For future extension, must be 0 now.

## state

Indicates the state of the current crypto login session. can be one of
MLX5DV_CRYPTO_LOGIN_STATE_VALID, MLX5DV_CRYPTO_LOGIN_STATE_NO_LOGIN and
MLX5DV_CRYPTO_LOGIN_STATE_INVALID.

# RETURN VALUE

**mlx5dv_crypto_login()** returns 0 on success and errno value on error.

**mlx5dv_crypto_login_query_state()** returns 0 on success and updates *state*
with the queried state. On error, errno value is returned.

**mlx5dv_crypto_logout()** returns 0 on success and errno value on error.

# ERRORS

EEXIST

:	A crypto login session already exists.

EINVAL

:	Invalid attributes were provided, or one or more of *credential*,
	*credential_id* and *import_kek_id* are invalid.

ENOENT

:	No crypto login session exists.

# AUTHORS

Avihai Horon <avihaih@nvidia.com>
