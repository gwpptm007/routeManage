#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <net/if.h>

#include "ll_map.h"
#include "ilist.h"
#include "log.h"

struct ll_cache
{
    struct hlist_node idx_hash;
    struct hlist_node name_hash;
    unsigned	flags;
    unsigned 	index;
    unsigned short type;
    char		name[];
};

#define IDXMAP_SIZE	1024
static struct hlist_head g_idx_head[IDXMAP_SIZE];
static struct hlist_head g_name_head[IDXMAP_SIZE];

static struct ll_cache *ll_get_by_index(unsigned index)
{
    struct hlist_node *n;
    unsigned h = index & (IDXMAP_SIZE - 1);

    hlist_for_each(n, &g_idx_head[h])
    {
        struct ll_cache *im = container_of(n, struct ll_cache, idx_hash);
        if (im->index == index)
            return im;
    }

    return NULL;
}

unsigned namehash(const char *str)
{
    unsigned hash = 5381;

    while (*str)
        hash = ((hash << 5) + hash) + *str++; /* hash * 33 + c */

    return hash;
}

struct ll_cache *ll_get_by_name(const char *name)
{
    struct hlist_node *n;
    unsigned h = namehash(name) & (IDXMAP_SIZE - 1);

    hlist_for_each(n, &g_name_head[h])
    {
        struct ll_cache *im = container_of(n, struct ll_cache, name_hash);

        if (strncmp(im->name, name, IFNAMSIZ) == 0)
            return im;
    }

    return NULL;
}

int ll_remember_index(struct nlmsghdr *n, void *arg)
{
    unsigned int h;
    const char *ifname;
    struct ifinfomsg *ifi = NLMSG_DATA(n);
    struct ll_cache *im;
    struct rtattr *tb[IFLA_MAX+1];

    if (n->nlmsg_type != RTM_NEWLINK && n->nlmsg_type != RTM_DELLINK)
        return 0;

    if (n->nlmsg_len < NLMSG_LENGTH(sizeof(*ifi)))
        return -1;

    im = ll_get_by_index(ifi->ifi_index);
    if (n->nlmsg_type == RTM_DELLINK)
    {
        if (im)
        {
            hlist_del(&im->name_hash);
            hlist_del(&im->idx_hash);
            free(im);
        }
        return 0;
    }

    parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), IFLA_PAYLOAD(n));
    ifname = (const char *)RTA_DATA(tb[IFLA_IFNAME]);
    if (ifname == NULL)
        return 0;

    if (im)
    {
        /* change to existing entry */
        if (strcmp(im->name, ifname) != 0)
        {
            hlist_del(&im->name_hash);
            h = namehash(ifname) & (IDXMAP_SIZE - 1);
            hlist_add_head(&im->name_hash, &g_name_head[h]);
        }

        im->flags = ifi->ifi_flags;
        return 0;
    }

    im = malloc(sizeof(*im) + strlen(ifname) + 1);
    if (im == NULL)
        return 0;
    im->index = ifi->ifi_index;
    strcpy(im->name, ifname);
    im->type = ifi->ifi_type;
    im->flags = ifi->ifi_flags;

    h = ifi->ifi_index & (IDXMAP_SIZE - 1);
    hlist_add_head(&im->idx_hash, &g_idx_head[h]);

    h = namehash(ifname) & (IDXMAP_SIZE - 1);
    hlist_add_head(&im->name_hash, &g_name_head[h]);

    return 0;
}

static int ll_link_get(const char *name, int index)
{
    struct {
        struct nlmsghdr		n;
        struct ifinfomsg	ifm;
        char			buf[1024];
    } req = {
        .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
        .n.nlmsg_flags = NLM_F_REQUEST,
        .n.nlmsg_type = RTM_GETLINK,
        .ifm.ifi_index = index,
    };
    __u32 filt_mask = RTEXT_FILTER_VF; // | RTEXT_FILTER_SKIP_STATS;
    struct rtnl_handle rth = {};
    struct nlmsghdr *answer;
    int rc = 0;

    if (rtnl_open(&rth) < 0)
        return 0;

    addattr32(&req.n, sizeof(req), IFLA_EXT_MASK, filt_mask);
    if (name)
        addattr_l(&req.n, sizeof(req), IFLA_IFNAME, name, strlen(name) + 1);

    if (rtnl_talk(&rth, &req.n, &answer) < 0)
        goto out;

    /* add entry to cache */
    //rc  = ll_remember_index(answer, NULL);
    //if (!rc)
    {
        struct ifinfomsg *ifm = NLMSG_DATA(answer);

        rc = ifm->ifi_index;
    }

    free(answer);
out:
    rtnl_close(&rth);
    return rc;
}

const char *ll_index_to_name(unsigned int idx)
{
    static char buf[IFNAMSIZ];
    const struct ll_cache *im;

    if (idx == 0)
        return "*";

    im = ll_get_by_index(idx);
    if (im)
        return im->name;

    if (ll_link_get(NULL, idx) == idx)
    {
        im = ll_get_by_index(idx);
        if (im)
            return im->name;
    }

    if (if_indextoname(idx, buf) == NULL)
        snprintf(buf, IFNAMSIZ, "if%u", idx);

    return buf;
}

int ll_index_to_type(unsigned int idx)
{
    const struct ll_cache *im;

    if (idx == 0)
        return -1;

    im = ll_get_by_index(idx);
    return im ? im->type : -1;
}

unsigned int ll_name_to_index(const char *name)
{
    //const struct ll_cache *im;
    unsigned idx;

    if (name == NULL)
        return 0;

    //im = ll_get_by_name(name);
    //if (im)
    //    return im->index;

    idx = ll_link_get(name, 0);
    if (idx == 0)
        idx = if_nametoindex(name);
    return idx;
}

static void ll_map_destroy(void)
{
    struct hlist_node *n, *tmp;
    unsigned h;

    for (h = 0; h < IDXMAP_SIZE; h++)
    {
        hlist_for_each_safe(n, tmp, &g_name_head[h])
        {
            struct ll_cache *im = container_of(n, struct ll_cache, name_hash);
            hlist_del(&im->name_hash);
            hlist_del(&im->idx_hash);
            free(im);
        }
    }
}

void ll_init_map(struct rtnl_handle *rth)
{
    ll_map_destroy();

    if (rtnl_linkdump_req(rth, AF_INET) < 0)
    {
        log_msg(L_ERR, "[LINK] Cannot send dump request");
        return;
    }

    if (rtnl_dump_filter(rth, ll_remember_index, NULL) < 0)
    {
        log_msg(L_ERR, "[LINK] Dump terminated\n");
        return;
    }
}

