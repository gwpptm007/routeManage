#ifndef _UTIL_NET_H_
#define _UTIL_NET_H_

#include <stddef.h>
#include <inttypes.h>
#include <netdb.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>

#include "queue.h"

#define NL_ERR_NOT_EXIST    3
#define NL_ERR_FILE_EXIST   17
#define NL_PKT_BUF_SIZE     1024
#define NL_RCV_BUF_SIZE     (1 * 1024 * 1024)

#define ARPHRD_TUNNEL       768
#define ARPHRD_TUNNEL6      769
#define ARPHRD_SIT          776
#define ARPHRD_IPGRE        778
#define ARPHRD_IP6GRE       823

#define MAX_RT_NAME_LEN     32
#define RT_XFRMI_NAME       "xfrm"
#define RT_XFRMI_ID         90
#define RT_MAIN_ID          254
#define RT_LOCAL_ID         255
#define RT_ID_MAX           256

#define IP_LINK_STATS       0
#define IP_LINK_STATS64     1

#define GRE_WITH_KEY    (0x0001)
#define GRE_WITH_CKSUM  (0x0002)

#ifndef NDA_RTA
#define NDA_RTA(r) \
	((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#endif
#ifndef NDA_PAYLOAD
#define NDA_PAYLOAD(n)	NLMSG_PAYLOAD(n, sizeof(struct ndmsg))
#endif

#ifndef IP_DF
#define IP_DF 0x4000  /* Flag: "Don't Fragment"	*/
#endif

struct rtnl_handle
{
    int fd;
    struct sockaddr_nl local;
    struct sockaddr_nl peer;
    unsigned int  seq;
    unsigned int  dump;
};

struct nlmsg_list
{
    struct nlmsg_list *next;
    struct nlmsghdr   h;
};

struct nlmsg_chain
{
    struct nlmsg_list *head;
    struct nlmsg_list *tail;
};
typedef int (*req_filter_fn_t)(struct nlmsghdr *nlh, int reqlen, void *);
typedef int (*rtnl_dump_cb)(struct nlmsghdr *nlh, void *);

typedef struct _iplink_stats
{
    int type;    /* 0: rtnl_link_stats, 1: rtnl_link_stats */
    union {
        struct rtnl_link_stats stats;
        struct rtnl_link_stats64 stats64;
    };
} iplink_stats_t;

const char * safe_error_text(uint32_t num);
const char * safe_strerror(int errnum);

const char *igw_inet_ntop(struct addrinfo *addr, char *buffer);

typedef struct _if_addr
{
    uint32_t ip;
    TAILQ_ENTRY(_if_addr) next;
} if_addr_t;

typedef TAILQ_HEAD(_if_addr_list, _if_addr) if_addr_list_t;

int if_addr_list_get(if_addr_list_t *addr_list);
void if_addr_list_destroy(if_addr_list_t *addr_list);

int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data, int alen);
int addattr32 (struct nlmsghdr *n, size_t maxlen, int type, int data);
int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len);

int rtnl_open(struct rtnl_handle *rth);
void rtnl_close(struct rtnl_handle *rth);
int rtnl_talk(struct rtnl_handle *rth, struct nlmsghdr *n, struct nlmsghdr **answer);
int rtnl_linkdump_req(struct rtnl_handle *rth, int family);

int rtnl_neigh_dump_req(struct rtnl_handle *rth, int family, req_filter_fn_t filter_fn, void *arg);
int rtnl_dump_filter(struct rtnl_handle *rth, rtnl_dump_cb cb, void *arg);

int rtnl_rule_dump_req(struct rtnl_handle *rth, int family);

int rtnl_route_dump_req(struct rtnl_handle *rth, int family, req_filter_fn_t filter_fn, void *arg);

unsigned int get_ip_subnet_mask(const unsigned int mask_length);
int mask2prefix(uint32_t mask);
int maskstr2prefix(const char *str);
int is_valid_ipv4(const char *str);
int is_valid_ipv6(const char *str);
int is_same_subnet(const char *ip1, const char *ip2, const char *netmask);
int get_interface_ip(char *name, char *ip, char *netmask);
struct addrinfo * get_numeric_address(char *address, char *port);

int ll_addr_a2n(char *lladdr, int len, const char *arg);
const char * ll_addr_n2a(const unsigned char *addr, int alen, int type, char *buf, int blen);
const char *rt_addr_n2a(int af, int len, const void *addr);

void rtnl_table_init(void);
void rtnl_table_add(int id, const char *name);
void rtnl_table_del(int id, const char *name);
const char * rtnl_table_n2a(uint32_t id);

int ip_link_del(const char *name);
int ip_link_set(const char *name, int updown);

int iplink_stats_get(char *ifname, iplink_stats_t *stats);

/*
 * ip tunnel add gre1 local 1.1.1.1 remote 2.2.2.2 mode gre key 42 dev eth0
 *
 * @param name - tunnel name
 * @param dev - bind the tunnel to the device so that tunneled packets will only
 *              routed via this device and will not be able to escape to another
 *              device when the route to endpoint changes.
 * @param saddr - the local address for tunneled packets, it must be an address on another interface of this host.
 * @param daddr - the remote endpoint of the tunnel
 * @param proto - IPPROTO_IPIP/IPPROTO_GRE/IPPROTO_IPV6
 * @param key - either a number or an IP address-like dotted quad.
 * @param flags - the flags of key and csum
 * @retval 0 on success, otherwise -1.
 */
int ip_tunnel_add(const char *name, const char *dev, const char *saddr, const char *daddr,
                  unsigned int proto, unsigned int key, unsigned int flags);

/*
 * ip tunnel change gre1 local 1.1.1.1 remote 2.2.2.2 mode gre key 42 dev eth0
 *
 * @param name - tunnel name
 * @param dev - bind the tunnel to the device so that tunneled packets will only
 *              routed via this device and will not be able to escape to another
 *              device when the route to endpoint changes.
 * @param saddr - the local address for tunneled packets, it must be an address on another interface of this host.
 * @param daddr - the remote endpoint of the tunnel
 * @param proto - IPPROTO_IPIP/IPPROTO_GRE/IPPROTO_IPV6
 * @param key - either a number or an IP address-like dotted quad.
 * @param flags - the flags of key and csum
 * @retval 0 on success, otherwise -1.
 */
int ip_tunnel_change(const char *name, const char *dev, const char *saddr,
                  const char *daddr, unsigned int proto, unsigned int key, unsigned int flags);

/*
 * ip tunnel del gre1
 *
 * @param name - tunnel name
 * @retval 0 on success, otherwise -1.
 */
int ip_tunnel_del(const char *name);

/**
 * Add new protocol address to a network device.
 * ip address add 1.1.1.1/24 peer 1.1.1.2/24 dev gre1
 *
 * @param dev - the network device name
 * @param local - the local address
 * @param local_prefixlen - the prefix length of local address
 * @param peer - the remote address
 * @param peer_prefixlen - the prefix length of peer address
 * @retval 0 on success, otherwise -1.
 */
int ip_address_add(const char *dev, const char *local, uint8_t local_prefixlen, const char *peer, uint8_t peer_prefixlen);

/**
 * Delete a protocol address.
 * ip address del 1.1.1.1/24 peer 1.1.1.2/24 dev gre1
 *
 * @param dev - the network device name
 * @param local - the local address
 * @param local_prefixlen - the prefix length of local address
 * @param peer - the remote address
 * @param peer_prefixlen - the prefix length of peer address
 * @retval 0 on success, otherwise -1.
 */
int ip_address_del(const char *dev, const char *local, uint8_t local_prefixlen, const char *peer, uint8_t peer_prefixlen);

#endif /* _UTIL_NET_H_ */
