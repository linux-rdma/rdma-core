/*
* SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
* SPDX-License-Identifier: LicenseRef-NvidiaProprietary
*
* NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
* property and proprietary rights in and to this material, related
* documentation and any modifications thereto. Any use, reproduction,
* disclosure or distribution of this material and related documentation
* without an express license agreement from NVIDIA CORPORATION or
* its affiliates is strictly prohibited.
*/


#ifndef SMI_GSI_DB_H_
#define SMI_GSI_DB_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief represents pair of SMI and GSI IDs as double linked list in db.
 *
 */
typedef struct _ports_record {
	int smi_port_id;
	int gsi_port_id;
	struct _ports_record* next;
	struct _ports_record* prev;
} ports_record_t;

/**
 * @brief find pair of SMI and GSI IDs in DB
 *
 * @param port_id - ID of SMI port
 *
 * @return pointer of ports record.
 */
ports_record_t * smi_gsi_record_find(int port_id);


/**
 * @brief add new record of pair SMI and GSI IDs into DB
 *
 * @param smi_port_id - SMI port ID
 * @param gsi_port_id - GSI port ID
 *
 * @return pointer of ports record.
 */
ports_record_t * smi_gsi_record_add(int smi_port_id, int gsi_port_id);


/**
 * @brief remove current record from DB
 *
 * @param x - pointer to the ports record
 *
 * @return void
 */
void smi_gsi_record_ptr_remove(ports_record_t * x);


/**
 * @brief remove current record from DB
 *
 * @param port_id - SMI port ID
 *
 * @return void
 */
void smi_gsi_record_remove(int id);

/**
 * @brief remove current record from DB
 *
 * @param port_id - SMI port ID
 * @param class   - Management class
 *
 * @return port_id
 */
int smi_gsi_port_by_class(int port_id, int mgmt);

/**
 * @brief Open SMI & GSI ports pair
 *
 * @param ca_name - Device name (SMI or GSI)
 * @param portnum - Device port number
 *
 * @return SMI port_id
 */
int smi_gsi_port_open(char *ca_name, int portnum);

/**
 * @brief Close SMI & GSI ports pair
 *
 * @param port_id - SMI port ID
 *
 * @return void
 */
void smi_gsi_port_close(int port_id);


#ifdef __cplusplus
}
#endif

#endif    /* SMI_GSI_DB_H_ */
