#ifndef __LL_MAP_H__
#define __LL_MAP_H__

#include "util_net.h"

const char *ll_index_to_name(unsigned int idx);
int ll_index_to_type(unsigned int idx);
unsigned int ll_name_to_index(const char *name);
void ll_init_map(struct rtnl_handle *rth);
int ll_remember_index(struct nlmsghdr *n, void *arg);

#endif  /* __LL_MAP_H__ */
