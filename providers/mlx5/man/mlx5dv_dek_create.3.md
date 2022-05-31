---
layout: page
title: mlx5dv_dek_create / mlx5dv_dek_query / mlx5dv_dek_destroy
section: 3
tagline: Verbs
---

# NAME

mlx5dv_dek_create - Creates a DEK

mlx5dv_dek_query - Queries a DEK's attributes

mlx5dv_dek_destroy - Destroys a DEK

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

struct mlx5dv_dek *mlx5dv_dek_create(struct ibv_context *context,
				     struct mlx5dv_dek_init_attr *init_attr);

int mlx5dv_dek_query(struct mlx5dv_dek *dek, struct mlx5dv_dek_attr *attr);

int mlx5dv_dek_destroy(struct mlx5dv_dek *dek);
```

# DESCRIPTION

Data Encryption Keys (DEKs) are used to encrypt and decrypt transmitted data.
After a DEK is created, it can be configured in MKeys for crypto offload
operations.
DEKs are not persistent and are destroyed upon process exit. Therefore,
software process needs to re-create all needed DEKs on startup.

**mlx5dv_dek_create()** creates a new DEK with the attributes specified in
*init_attr*. A pointer to the newly created dek is returned, which can be used
for DEK query, DEK destruction and when configuring a MKey for crypto offload
operations.

The DEK can be either wrapped or in plaintext and the format that should be used
is determined by the specified crypto_login object.

To create a wrapped DEK, the application must have a valid crypto login object
prior to creating the DEK. Creating a wrapped DEK can be performed in two
ways:
1. Call **mlx5dv_crypto_login_create()** to obtain a crypto login object.
Indicate that the DEK is wrapped by setting
**MLX5DV_DEK_INIT_ATTR_CRYPTO_LOGIN** value in *comp_mask* and passing the
crypto login object in *crypto_login* field of *init_attr*. Fill the other DEK
attributes and create the DEK.

2. Call **mlx5dv_crypto_login()** i.e., the old API.
Supply credential, import_kek_id

To create a plaintext DEK, the application must indicate that the DEK is in
plaintext by setting **MLX5DV_DEK_INIT_ATTR_CRYPTO_LOGIN** value in *comp_mask*
and passing NULL value in *crypto_login* field of *init_attr*, fill the other
DEK attributes and create the DEK.

To use the created DEK (either wrapped or plaintext) in a MKey, a valid crypto
login object or session is not needed. Revoking the import KEK or credential
that were used for the crypto login object or session (and therefore rendering
the crypto login invalid) does not prevent using a created DEK.

**mlx5dv_dek_query()** queries the DEK specified by *dek* and returns the
queried attributes in *attr*. A valid crypto login object or session is not
required to query a plaintext DEK. On the other hand, to query a wrapped DEK a
valid crypto login object or session must be present.

**mlx5dv_dek_destroy()** destroys the DEK specified by *dek*.

# ARGUMENTS

## context

The device context to create the DEK with.

## init_attr

```c
enum mlx5dv_dek_init_attr_mask {
	MLX5DV_DEK_INIT_ATTR_CRYPTO_LOGIN = 1 << 0,
};

struct mlx5dv_dek_init_attr {
	enum mlx5dv_crypto_key_size key_size;
	bool has_keytag;
	enum mlx5dv_crypto_key_purpose key_purpose;
	struct ibv_pd *pd;
	char opaque[8];
	char key[128];
	uint64_t comp_mask; /* Use enum mlx5dv_dek_init_attr_mask */
	struct mlx5dv_crypto_login_obj *crypto_login;
};
```
*key_size*

:	The size of the key, can be one of the following

	**MLX5DV_CRYPTO_KEY_SIZE_128**

	:	Key size is 128 bit.

	**MLX5DV_CRYPTO_KEY_SIZE_256**

	:	Key size is 256 bit.

*has_keytag*

:	Whether the DEK has a keytag or not. If set, the key should include a
	8 Bytes keytag.
	Keytag is used to verify that the DEK being used by a MKey is the
	expected DEK. This is done by comparing the keytag that was defined
	during DEK creation with the keytag provided in the MKey crypto
	configuration, and failing the operation if they are different.

*key_purpose*

:	The purpose of the key, currently can only be the following value

	**MLX5DV_CRYPTO_KEY_PURPOSE_AES_XTS**

	:	The key will be used for AES-XTS crypto engine.

*pd*

:	The protection domain to be associated with the DEK.

*opaque*

:	Plaintext metadata to describe the key.

*key*

:	The key that will be used for encryption and decryption of transmitted
	data.
	For plaintext DEK *key* must be provided in plaintext.
	For wrapped DEK *key* must be provided wrapped by the import KEK that
	was specified in the crypto login.
	Actual size and layout of this field depend on the provided *key_size*
	and *has_keytag* fields, as well as on the format of the key (plaintext
	or wrapped).
	*key* should be constructed according to the following table.

	Table: DEK *key* Field Construction.

	|  Import Method  |  Has Keytag  |   Key size   |                     Key Layout                   |
	| --------------- | ------------ | ------------ | ------------------------------------------------ |
	|    Plaintext    |      No      |    128 Bit   |              key1_128b + key2_128b               |
	|                 |              |              |                                                  |
	|    Plaintext    |      No      |    256 Bit   |              key1_256b + key2_256b               |
	|                 |              |              |                                                  |
	|    Plaintext    |     Yes      |    128 Bit   |        key1_128b + key2_128b + keytag_64b        |
	|                 |              |              |                                                  |
	|    Plaintext    |     Yes      |    256 Bit   |        key1_256b + key2_256b + keytag_64b        |
	|                 |              |              |                                                  |
	|     Wrapped     |      No      |    128 Bit   |        ENC(iv_64b + key1_128b + key2_128b)       |
	|                 |              |              |                                                  |
	|     Wrapped     |      No      |    256 Bit   |        ENC(iv_64b + key1_256b + key2_256b)       |
	|                 |              |              |                                                  |
	|     Wrapped     |     Yes      |    128 Bit   | ENC(iv_64b + key1_128b + key2_128b + keytag_64b) |
	|                 |              |              |                                                  |
	|     Wrapped     |     Yes      |    256 Bit   | ENC(iv_64b + key1_256b + key2_256b + keytag_64b) |

	Where ENC() is AES key wrap algorithm and iv_64b is 0xA6A6A6A6A6A6A6A6
	as per the NIST SP 800-38F AES key wrap spec.

	The following example shows how to wrap a 128 bit key that has keytag
	using a 128 bit import KEK in OpenSSL:

	```c
	#include <openssl/evp.h>

	unsigned char import_kek[16]; /* 128 bit import KEK in plaintext for wrapping */
	unsigned char iv[8] = {0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6};

	/*
	 * Indexes 0-15 are key1 in plaintext, indexes 16-31 are key2 in plaintext,
	 * and indexes 32-39 are key_tag in plaintext.
	 */
	unsigned char key[40];

	unsigned char wrapped_key[48];
	EVP_CIPHER_CTX *ctx;
	int len;

	ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
	EVP_EncryptInit_ex(ctx, EVP_aes_128_wrap(), NULL, import_kek, iv);
	EVP_EncryptUpdate(ctx, wrapped_key, &len, key, sizeof(key));
	EVP_EncryptFinal_ex(ctx, wrapped_key + len, &len);
	EVP_CIPHER_CTX_free(ctx);
	```

*comp_mask*

:	Currently can be the following value:

	**MLX5DV_DEK_INIT_ATTR_CRYPTO_LOGIN**, which indicates that *crypto_login*
	field is applicable.


*crypto_login*

:	Pointer to a crypto login object. If set to a valid crypto login object,
	indicates that this is a wrapped DEK that will be created using the
	given crypto login object. If set to NULL, indicates that this is a
	plaintext DEK. Must be NULL if **MLX5DV_DEK_INIT_ATTR_CRYPTO_LOGIN** is
	not set.
	Only relevant when comp_mask is set with *MLX5DV_DEK_INIT_ATTR_CRYPTO_LOGIN*


## dek

	Pointer to an existing DEK to query or to destroy.

## attr

	DEK attributes to be populated when querying a DEK.

```c
struct mlx5dv_dek_attr {
	enum mlx5dv_dek_state state;
	char opaque[8];
	uint64_t comp_mask;
};
```

*state*

:	The state of the DEK, can be one of the following

	**MLX5DV_DEK_STATE_READY**

	:	The key is ready for use. This is the state of the key when it
		is first created.

	**MLX5DV_DEK_STATE_ERROR**

	:	The key is unusable. The key needs to be destroyed and
		re-created in order to be used. This can happen, for example,
		due to DEK memory corruption.

*opaque*

:	Plaintext metadata to describe the key.

*comp_mask*

:	Reserved for future extension, must be 0 now.

# RETURN VALUE

**mlx5dv_dek_create()** returns a pointer to a new *struct mlx5dv_dek* on
success. On error NULL is returned and errno is set.

**mlx5dv_dek_query()** returns 0 on success and updates *attr* with the queried
DEK attributes. On error errno value is returned.

**mlx5dv_dek_destroy()** returns 0 on success and errno value on error.

# SEE ALSO

**mlx5dv_crypto_login**(3), **mlx5dv_crypto_login_create**(3),
**mlx5dv_query_device**(3)

# AUTHORS

Avihai Horon <avihaih@nvidia.com>
