/* Copyright (c) 2019 Mellanox Technologies. All rights reserved.
 *
 * Connect to opensm's cl_nodenamemap.h if it is available.
 */
#ifndef __LIBUTIL_NODE_NAME_MAP_H__
#define __LIBUTIL_NODE_NAME_MAP_H__

#include <stdint.h>

struct nn_map;
typedef struct nn_map nn_map_t;

nn_map_t *open_node_name_map(const char *node_name_map);
void close_node_name_map(nn_map_t *map);
/* NOTE: parameter "nodedesc" may be modified here. */
char *remap_node_name(nn_map_t *map, uint64_t target_guid, char *nodedesc);
char *clean_nodedesc(char *nodedesc);

#endif
