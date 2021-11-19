---
layout: page
title: mlx5dv_wr_set_mkey_crypto
section: 3
tagline: Verbs
---

# NAME

mlx5dv_wr_set_mkey_crypto - Configure a MKey for crypto operation.

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

static inline void
mlx5dv_wr_set_mkey_crypto(struct mlx5dv_qp_ex *mqp,
			  const struct mlx5dv_crypto_attr *attr);
```
# DESCRIPTION

Configure a MKey with crypto properties. With this, the device will
encrypt/decrypt data when transmitting data from memory to network and when
receiving data from network to memory.

In order to configure MKey with crypto properties, the MKey should be created
with **MLX5DV_MKEY_INIT_ATTR_FLAGS_CRYPTO**. MKey that was created with
**MLX5DV_MKEY_INIT_ATTR_FLAGS_CRYPTO** must have crypto properties
configured to it before it can be used, i.e. this setter must be called before
the MKey can be used or else traffic will fail, generating a CQE with error.
A call to this setter on a MKey that already has crypto properties configured
to it will override existing crypto properties.

Configuring crypto properties to a MKey is done by specifying the crypto
standard that should be used and its attributes, and also by providing the Data
Encryption Key (DEK) to be used for the encryption/decryption itself.

The MKey represents a virtually contiguous memory, by configuring a layout to
it. The crypto properties of the MKey describe whether data in this virtually
contiguous memory is encrypted or in plaintext, and whether it should be
encrypted/decrypted before transmitting it or after receiving it. Depending on
the actual operation that happens (TX or RX), the device will do the "right
thing" based on the crypto properties configured in the MKey.

MKeys can be configured with both crypto and signature properties at the same
time by calling both **mlx5dv_wr_set_mkey_crypto()**(3) and
**mlx5dv_wr_set_mkey_sig_block()**(3). In this case, both crypto and signature
operations will be performed according to the crypto and signature properties
configured in the MKey, and the order of operations will be determined by the
*signature_crypto_order* property.

## Example 1 (corresponds to row F in the table below):

Memory signature domain is not configured, and memory data is encrypted.

Wire signature domain is not configured, and wire data is in plaintext.

*encrypt_on_tx* is set to false, and because signature is not configured,
*signature_crypto_order* value doesn't matter.

A SEND is issued using the MKey as a local key.

Result: device will gather the encrypted data from the MKey (using whatever
layout configured to the MKey to locate the actual memory), decrypt it using
the supplied DEK and transmit the decrypted data to the wire.

## Example 1.1:

Same as above, but a RECV is issued with the same MKey, and RX happens.

Result: device will receive the data from the wire, encrypt it using the
supplied DEK and scatter it to the MKey (using whatever layout configured to
the MKey to locate the actual memory).

## Example 2 (corresponds to row C in the table below):

Memory signature domain is configured for no signature, and memory data is in
plaintext.

Wire signature domain is configured for T10DIF every 512 Bytes block, and wire
data (including the T10DIF) is encrypted.

*encrypt_on_tx* is set to true and *signature_crypto_order* is set to be
**MLX5DV_SIGNATURE_CRYPTO_ORDER_SIGNATURE_BEFORE_CRYPTO_ON_TX**.
*data_unit_size* is set to **MLX5DV_BLOCK_SIZE_520**.

The MKey is sent to a remote node that issues a RDMA_READ to this MKey.

Result: device will gather the data from the MKey (using whatever layout
configured to the MKey to locate the actual memory), generate an additional
T10DIF field every 512B of data, encrypt the data and the newly generated
T10DIF field using the supplied DEK, and transmit it to the wire.

## Example 2.1:

Same as above, but remote node issues a RDMA_WRITE to this MKey.

Result: device will receive the data from the wire, decrypt the data using the
supplied DEK, validate each T10DIF field against the previous 512B of data,
strip the T10DIF field, and scatter the data alone to the MKey (using whatever
layout configured to the MKey to locate the actual memory).

# ARGUMENTS

*mqp*
:	The QP where an MKey configuration work request was created by
	**mlx5dv_wr_mkey_configure()**.

*attr*
:	Crypto attributes to set for the MKey.

## Crypto Attributes

Crypto attributes describe the format (encrypted or plaintext) and layout of
the input and output data in memory and wire domains, the crypto standard
that should be used and its attributes.

```c
struct mlx5dv_crypto_attr {
	enum mlx5dv_crypto_standard crypto_standard;
	bool encrypt_on_tx;
	enum mlx5dv_signature_crypto_order signature_crypto_order;
	enum mlx5dv_block_size data_unit_size;
	char initial_tweak[16];
	struct mlx5dv_dek *dek;
	char keytag[8];
	uint64_t comp_mask;
};
```

*crypto_standard*

:	The encryption standard that should be used, currently can only be the
	following value

	**MLX5DV_CRYPTO_STANDARD_AES_XTS**

	:	The AES-XTS encryption standard defined in IEEE Std 1619-2007.

*encrypt_on_tx*

:	If set, memory data will be encrypted during TX and wire data will be
	decrypted during RX.
	If not set, memory data will be decrypted during TX and wire data will
	be encrypted during RX.

*signature_crypto_order*

:	Controls the order between crypto and signature operations (Please see
	detailed table below). Relevant only if signature is configured.
	Can be one of the following values

	**MLX5DV_SIGNATURE_CRYPTO_ORDER_SIGNATURE_AFTER_CRYPTO_ON_TX**

	:	During TX, first perform crypto operation (encrypt/decrypt based
		on *encrypt_on_tx*) and then signature operation on memory data.
		During RX, first perform signature operation and then crypto
		operation (encrypt/decrypt based on *encrypt_on_tx*) on wire
		data.

	**MLX5DV_SIGNATURE_CRYPTO_ORDER_SIGNATURE_BEFORE_CRYPTO_ON_TX**

	:	During TX, first perform signature operation and then crypto
		operation (encrypt/decrypt based on *encrypt_on_tx*) on memory
		data.
		During RX, first perform crypto operation (encrypt/decrypt based
		on *encrypt_on_tx*) and then signature operation on wire data.

	Table: *signature_crypto_order* and *encrypt_on_tx* Meaning.

	The table describes the possible data layouts in memory and wire
	domains, and the order in which crypto and signature operations are
	performed according to *signature_crypto_order*, *encrypt_on_tx*
	and signature configuration.

	Memory column represents the data layout in the memory domain.

	Wire column represents the data layout in the wire domain.

	There are three possible operations that can be performed by the device
	on the data when processing it from memory to wire and from wire to
	memory:

	1. Crypto operation.
	2. Signature operation in memory domain.
	3. Signature operation in wire domain.

	Op1, Op2 and Op3 columns represent these operations. On TX, Op1, Op2
	and Op3 are performed on memory data to produce the data layout that is
	specified in Wire column. On RX, Op3, Op2 and Op1 are performed on wire
	data to produce the data layout specified in Memory column. "SIG.mem"
	and "SIG.wire" represent the signature operation that is performed in
	memory and wire domains respectively. None means no operation is
	performed. The exact signature operations are determined by the
	signature attributes configured by **mlx5dv_wr_set_mkey_sig_block()**.

	encrypt_on_tx and signature_crypto_order columns represent the values
	that *encrypt_on_tx* and *signature_crypto_order* should have in order
	to achieve such behavior.

	|     |      Memory      |        Op1       |        Op2       |        Op3       |       Wire       | encrypt_on_tx |     signature_crypto_order     |
	|-----| ---------------- | ---------------- | ---------------- | ---------------- | ---------------- |---------------|--------------------------------|
	|  A  | data             | Encrypt on TX    | SIG.mem = none   | SIG.wire = none  | enc(data)        |     True      | Doesn't matter                 |
	|     |                  |                  |                  |                  |                  |               |                                |
	|  B  | data             | Encrypt On TX    | SIG.mem = none   | SIG.wire = SIG   | enc(data)+SIG    |     True      | SIGNATURE_AFTER_CRYPTO_ON_TX   |
	|     |                  |                  |                  |                  |                  |               |                                |
	|  C  | data             | SIG.mem = none   | SIG.wire = SIG   | Encrypt on TX    | enc(data+SIG)    |     True      | SIGNATURE_BEFORE_CRYPTO_ON_TX  |
	|     |                  |                  |                  |                  |                  |               |                                |
	|  D  | data+SIG         | SIG.mem = SIG    | SIG.wire = none  | Encrypt on TX    | enc(data)        |     True      | SIGNATURE_BEFORE_CRYPTO_ON_TX  |
	|     |                  |                  |                  |                  |                  |               |                                |
	|  E  | data+SIG1        | SIG.mem = SIG1   | SIG.wire = SIG2  | Encrypt on TX    | enc(data+SIG2)   |     True      | SIGNATURE_BEFORE_CRYPTO_ON_TX  |
	|     |                  |                  |                  |                  |                  |               |                                |
	|  F  | enc(data)        | Decrypt on TX    | SIG.mem = none   | SIG.wire = none  | data             |     False     | Doesn't matter                 |
	|     |                  |                  |                  |                  |                  |               |                                |
	|  G  | enc(data)        | Decrypt on TX    | SIG.mem = none   | SIG.wire = SIG   | data+SIG         |     False     | SIGNATURE_AFTER_CRYPTO_ON_TX   |
	|     |                  |                  |                  |                  |                  |               |                                |
	|  H  | enc(data+SIG)    | Decrypt on TX    | SIG.mem = SIG    | SIG.wire = none  | data             |     False     | SIGNATURE_AFTER_CRYPTO_ON_TX   |
	|     |                  |                  |                  |                  |                  |               |                                |
	|  I  | enc(data+SIG1)   | Decrypt on TX    | SIG.mem = SIG1   | SIG.wire = SIG2  | data+SIG2        |     False     | SIGNATURE_AFTER_CRYPTO_ON_TX   |
	|     |                  |                  |                  |                  |                  |               |                                |
	|  J  | enc(data)+SIG    | SIG.mem = SIG    | SIG.wire = none  | Decrypt on TX    | data             |     False     | SIGNATURE_BEFORE_CRYPTO_ON_TX  |

	Notes:

	- "Encrypt on TX" also means "Decrypt on RX", and "Decrypt on TX"
	  also means "Encrypt on RX".

	- When signature properties are not configured in the MKey, only crypto
	  operations will be performed. Thus, *signature_crypto_order* has no
	  meaning in this case (rows A and F), and it can be set to either one
	  of its values.

*data_unit_size*

:	For storage, this will normally be the storage block size. The tweak is
	incremented after each *data_unit_size* during the encryption. can be
	one of **enum mlx5dv_block_size**.

*initial_tweak*

:	A value to be used during encryption of each data unit. This value is
	incremented by the device for every data unit in the message. For
	storage encryption, this will normally be the LBA of the first block
	in the message, so that the increments represent the LBAs of the rest
	of the blocks in the message.

*dek*

:	The DEK to be used for the crypto operations. This DEK must be
	pre-loaded to the device using **mlx5dv_dek_create()**.

*key_tag*

:	A tag that verifies that the correct DEK is being used. *key_tag* is
	optional and is valid only if the DEK was created with **has_keytag**
	set to true. If so, it must match the key tag that was provided when
	the DEK was created. Supllied in plaintext.

*comp_mask*

:	Reserved for future extension, must be 0 now.

# RETURN VALUE

This function does not return a value.

In case of error, user will be notified later when completing the DV WRs chain.

# NOTES

MKey must be created with **MLX5DV_MKEY_INIT_ATTR_FLAGS_CRYPTO** flag.

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

**mlx5dv_wr_mkey_configure**(3), **mlx5dv_wr_set_mkey_sig_block**(3),
**mlx5dv_create_mkey**(3), **mlx5dv_destroy_mkey**(3),
**mlx5dv_crypto_login**(3), **mlx5dv_dek_create**(3)

# AUTHORS

Oren Duer  <oren@nvidia.com>

Avihai Horon <avihaih@nvidia.com>
