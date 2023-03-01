#if !defined( LOAD_WHITELIST_H )
#define LOAD_WHITELIST_H

#include "common.h"

int getIndexFromDigest(u_int8_t *ak_digest, WHITELIST_TABLE *whitelist_table, int nodes_number);
bool read_and_save_whitelist(WAM_channel *ch_read_whitelist, WHITELIST_TABLE *whitelist_table, int node_number);

#endif