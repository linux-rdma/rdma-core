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
operations. An active crypto login session must be present in order to create
a DEK.

To use the created DEK in a MKey, a valid or active crypto login session is not
needed. Revoking the import KEK or credential that were used during the login
(and therefore rendering the login session invalid) does not prevent using a
created DEK.

**mlx5dv_dek_query()** queries the DEK specified by *dek* and returns the
queried attributes in *attr*. An active crypto login session must be present
in order to query a DEK.

**mlx5dv_dek_destroy()** destroys the DEK specified by *dek*.

# ARGUMENTS

## context

The device context to create the DEK with. *context* must have an active crypto
login session associated with in order to create the DEK.

## init_attr

```c
struct mlx5dv_dek_init_attr {
	enum mlx5dv_crypto_key_size key_size;
	bool has_keytag;
	enum mlx5dv_crypto_key_purpose key_purpose;
	struct ibv_pd *pd;
	char opaque[8];
	char key[128];
	uint64_t comp_mask;
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
	data. Must be provided wrapped by the import KEK that was specified
	for the crypto login session.
	Actual size and layout of this field depend on the provided *key_size*
	and *has_keytag* fields.
	*key* should be constructed according to the following table.

	Table: DEK *key* Field Construction.

	|   Key size   |  Has Keytag  |                      Key Layout                    |
	| ------------ | ------------ | -------------------------------------------------- |
	|    128 Bit   |      No      |         ENC(iv_64b + key1_128b + key2_128b)        |
	|              |              |                                                    |
	|    256 Bit   |      No      |         ENC(iv_64b + key1_256b + key2_256b)        |
	|              |              |                                                    |
	|    128 Bit   |     Yes      |  ENC(iv_64b + key1_128b + key2_128b + 64b_keytag)  |
	|              |              |                                                    |
	|    256 Bit   |     Yes      |  ENC(iv_64b + key1_256b + key2_256b + 64b_keytag)  |

	Where ENC() is AES key wrap algorithm and iv_64b is 0xA6A6A6A6A6A6A6A6
	as per the AES key wrap spec.

	The following example shows how to wrap a 128 bit key that has keytag
	using a 128 bit import KEK in OpenSSL:

	```c
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

:	Reserved for future extension, must be 0 now.

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

**mlx5dv_crypto_login**(3)

# AUTHORS

Avihai Horon <avihaih@nvidia.com>
