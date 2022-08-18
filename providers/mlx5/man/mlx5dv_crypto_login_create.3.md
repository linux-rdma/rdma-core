---
layout: page
title: mlx5dv_crypto_login_create / mlx5dv_crypto_login_query / mlx5dv_crypto_login_destroy
section: 3
tagline: Verbs
---

# NAME

mlx5dv_crypto_login_create - Creates a crypto login object

mlx5dv_crypto_login_query - Queries the given crypto login object

mlx5dv_crypto_login_destroy - Destroys the given crypto login object

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

struct mlx5dv_crypto_login_obj *
mlx5dv_crypto_login_create(struct ibv_context *context,
			   struct mlx5dv_crypto_login_attr_ex *login_attr);

int mlx5dv_crypto_login_query(struct mlx5dv_crypto_login_obj *crypto_login,
			      struct mlx5dv_crypto_login_query_attr *query_attr);

int mlx5dv_crypto_login_destroy(struct mlx5dv_crypto_login_obj *crypto_login);
```

# DESCRIPTION

When using a crypto engine that is in wrapped import method, a valid crypto
login object must be provided in order to create and query wrapped Data
Encryption Keys (DEKs).

A valid crypto login object is necessary only to create and query wrapped DEKs.
Existing DEKs that were previously created don't need a valid crypto login
object in order to be used (in MKey or during traffic).

**mlx5dv_crypto_login_create()** creates and returns a crypto login object with
the credential given in *login_attr*. Only one crypto login object can be
created per device context. The created crypto login object must be provided to
**mlx5dv_dek_create()** in order to create wrapped DEKs.

**mlx5dv_crypto_login_query()** queries the crypto login object *crypto_login*
and returns the queried attributes in *query_attr*.

**mlx5dv_crypto_login_destroy()** destroys the given crypto login object.

# ARGUMENTS

## context

The device context that will be associated with the crypto login object.

## login_attr

Crypto extended login attributes specify the credential to login with and
the import KEK to be used for secured communications done with the crypto
login object.

```c
struct mlx5dv_crypto_login_attr_ex {
	uint32_t credential_id;
	uint32_t import_kek_id;
	const void *credential;
	size_t credential_len;
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
	communications done with the crypto login object.

*credential*

:	The credential to login with. Credential is a piece of data used to
	authenticate the user for crypto login. The credential in *credential*
	is validated against the credential indicated by *credential_id*, which
	is stored on the device. The credentials must match in order for the
	crypto login to succeed.
	*credential* must be provided wrapped by the AES key wrap algorithm
	using the import KEK indicated by *import_kek_id*.
	*credential* format is ENC(iv_64b + plaintext_credential) where ENC()
	is AES key wrap algorithm and iv_64b is 0xA6A6A6A6A6A6A6A6 as per the
	NIST SP 800-38F AES key wrap spec, and plaintext_credential is the
	credential value stored on the device.

*credential_len*

:	The length of the provided *credential* value in bytes.

*comp_mask*

:	Reserved for future extension, must be 0 now.

## query_attr

	Crypto login attributes to be populated when querying a crypto login
	object.

```c
struct mlx5dv_crypto_login_query_attr {
	enum mlx5dv_crypto_login_state state;
	uint64_t comp_mask;
};
```

*state*

:	The state of the crypto login object, can be one of the following

	**MLX5DV_CRYPTO_LOGIN_STATE_VALID**

	:	The crypto login object is valid and can be used.

	**MLX5DV_CRYPTO_LOGIN_STATE_INVALID**

	:	The crypto login object is invalid and cannot be used. A valid
		crypto login object can become invalid if the credential or the
		import KEK used in the crypto login object were deleted while in
		use (for example by a crypto officer). In this case,
		**mlx5dv_crypto_login_destroy()** should be called to destroy
		the invalid crypto login object and if still necessary,
		**mlx5dv_crypto_login_create()** should be called to create a
		new crypto login object with valid credential and import KEK.

*comp_mask*

:	Reserved for future extension, must be 0 now.

# RETURN VALUE

**mlx5dv_crypto_login_create()** returns a pointer to a new valid
*struct mlx5dv_crypto_login_obj* on success. On error NULL is returned and errno
is set.

**mlx5dv_crypto_login_query()** returns 0 on success and fills *query_attr* with
the queried attributes. On error, errno is returned.

**mlx5dv_crypto_login_destroy()** returns 0 on success and errno on error.

# SEE ALSO

**mlx5dv_dek_create**(3), **mlx5dv_query_device**(3)

# AUTHORS

Avihai Horon <avihaih@nvidia.com>
