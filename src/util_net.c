#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <linux/ip.h>
#include <linux/if_arp.h>
#include <linux/if_tunnel.h>
#include <linux/sockios.h>
#include <linux/netlink.h>
#include <linux/fib_rules.h>
#include <sys/ioctl.h>

#include "i_public.h"
#include "ll_map.h"
#include "log.h"
#include "ilist.h"

#define RT_TABLES_FILE      "/etc/iproute2/rt_tables"
#define RT_TABLES_TMP_FILE  "/etc/iproute2/rt_tables.tmp"
#define RT_NAME_LEN_MAX     512

typedef struct _iplink_req
{
    struct nlmsghdr n;
    struct ifinfomsg i;
    char buf[NL_PKT_BUF_SIZE];
} iplink_req_t;

static char *g_rtnl_name[RT_ID_MAX] = {0};

typedef struct _error_text
{
    uint32_t code;  /* error code */
    char *str;      /* error string */
} error_text_t;

const static error_text_t g_error_text[] = {
    { 0               /*0*/,    "成功" },
    { EPERM           /*1*/,    "操作不允许" },
    { ENOENT          /*2*/,    "文件/路径不存在" },
    { ESRCH           /*3*/,    "进程不存在" },
    { EINTR           /*4*/,    "中断的系统调用" },
    { EIO             /*5*/,    "I/O错误" },
    { ENXIO           /*6*/,    "设备/地址不存在" },
    { E2BIG           /*7*/,    "参数列表过长" },
    { ENOEXEC         /*8*/,    "执行格式错误" },
    { EBADF           /*9*/,    "错误文件编号" },
    { ECHILD          /*10*/,   "子进程不存在" },
    { EAGAIN          /*11*/,   "重试" },
    { ENOMEM          /*12*/,   "内存不足" },
    { EACCES          /*13*/,   "无权限" },
    { EFAULT          /*14*/,   "地址错误" },
    { ENOTBLK         /*15*/,   "需要块设备" },
    { EBUSY           /*16*/,   "设备或资源忙" },
    { EEXIST          /*17*/,   "文件已存在" },
    { EXDEV           /*18*/,   "跨设备链路" },
    { ENODEV          /*19*/,   "设备不存在" },
    { ENOTDIR         /*20*/,   "路径不存在" },
    { EISDIR          /*21*/,   "是路径" },
    { EINVAL          /*22*/,   "无效参数" },
    { ENFILE          /*23*/,   "文件表溢出 " },
    { EMFILE          /*24*/,   "打开的文件过多" },
    { ENOTTY          /*25*/,   "非打字机" },
    { ETXTBSY         /*26*/,   "文本文件忙" },
    { EFBIG           /*27*/,   "文件太大" },
    { ENOSPC          /*28*/,   "设备无空间" },
    { ESPIPE          /*29*/,   "非法查询" },
    { EROFS           /*30*/,   "只读文件系统" },
    { EMLINK          /*31*/,   "链接太多" },
    { EPIPE           /*32*/,   "管道破裂" },
    { EDOM            /*33*/,   "参数超出函数域" },
    { ERANGE          /*34*/,   "结果无法表示" },
    { EDEADLK         /*35*/,   "资源将发生死锁" },
    { ENAMETOOLONG    /*36*/,   "文件名太长" },
    { ENOLCK          /*37*/,   "没有可用的记录锁" },
    { ENOSYS          /*38*/,   "函数未实现" },
    { ENOTEMPTY       /*39*/,   "目录非空" },
    { ELOOP           /*40*/,   "遇到太多符号链接" },
    { EWOULDBLOCK     /*41*/,   "操作会阻塞" },
    { ENOMSG          /*42*/,   "没有符合需求类型的消息" },
    { EIDRM           /*43*/,   "标识符已删除" },
    { ECHRNG          /*44*/,   "通道编号超出范围" },
    { EL2NSYNC        /*45*/,   "Level2不同步" },
    { EL3HLT          /*46*/,   "3级停止" },
    { EL3RST          /*47*/,   "3级重置" },
    { ELNRNG          /*48*/,   "链接编号超出范围" },
    { EUNATCH         /*49*/,   "协议驱动程序没有连接" },
    { ENOCSI          /*50*/,   "没有可用的CSI结构" },
    { EL2HLT          /*51*/,   "2级停止" },
    { EBADE           /*52*/,   "无效交换" },
    { EBADR           /*53*/,   "无效请求描述" },
    { EXFULL          /*54*/,   "交换完全" },
    { ENOANO          /*55*/,   "无阳极" },
    { EBADRQC         /*56*/,   "无效请求码" },
    { EBADSLT         /*57*/,   "无效插槽" },
    { EDEADLOCK       /*58*/,   "操作会阻塞" },
    { EBFONT          /*59*/,   "错误的字体文件格式" },
    { ENOSTR          /*60*/,   "设备不是流" },
    { ENODATA         /*61*/,   "无数据" },
    { ETIME           /*62*/,   "计时器到期" },
    { ENOSR           /*63*/,   "流资源不足" },
    { ENONET          /*64*/,   "机器不在网络上" },
    { ENOPKG          /*65*/,   "包未安装" },
    { EREMOTE         /*66*/,   "对象是远程" },
    { ENOLINK         /*67*/,   "链接正在服务中" },
    { EADV            /*68*/,   "广告错误" },
    { ESRMNT          /*69*/,   "源文件挂载错误" },
    { ECOMM           /*70*/,   "发送过程中通讯错误" },
    { EPROTO          /*71*/,   "协议错误" },
    { EMULTIHOP       /*72*/,   "多跳尝试" },
    { EDOTDOT         /*73*/,   "RFS特定错误" },
    { EBADMSG         /*74*/,   "不是数据类型消息" },
    { EOVERFLOW       /*75*/,   "对指定的数据类型来说值太大" },
    { ENOTUNIQ        /*76*/,   "网络上名字不唯一" },
    { EBADFD          /*77*/,   "文件描述符状态错误" },
    { EREMCHG         /*78*/,   "远程地址改变" },
    { ELIBACC         /*79*/,   "无法访问需要的共享库" },
    { ELIBBAD         /*80*/,   "访问损坏的共享库" },
    { ELIBSCN         /*81*/,   "库部分在a.out损坏" },
    { ELIBMAX         /*82*/,   "试图链接太多的共享库" },
    { ELIBEXEC        /*83*/,   "不能直接运行共享库" },
    { EILSEQ          /*84*/,   "非法字节序" },
    { ERESTART        /*85*/,   "应重新启动被中断的系统调用" },
    { ESTRPIPE        /*86*/,   "流管错误" },
    { EUSERS          /*87*/,   "用户太多" },
    { ENOTSOCK        /*88*/,   "在非套接字上进行套接字操作" },
    { EDESTADDRREQ    /*89*/,   "需要目的地址" },
    { EMSGSIZE        /*90*/,   "消息太长" },
    { EPROTOTYPE      /*91*/,   "错误协议类型" },
    { ENOPROTOOPT     /*92*/,   "协议不可用" },
    { EPROTONOSUPPORT /*93*/,   "不支持协议" },
    { ESOCKTNOSUPPORT /*94*/,   "不支持套接字类型" },
    { EOPNOTSUPP      /*95*/,   "操作上不支持传输端点" },
    { EPFNOSUPPORT    /*96*/,   "不支持协议族" },
    { EAFNOSUPPORT    /*97*/,   "协议不支持地址群" },
    { EADDRINUSE      /*98*/,   "地址已被使用" },
    { EADDRNOTAVAIL   /*99*/,   "无法分配请求的地址" },
    { ENETDOWN        /*100*/,  "网络已关闭" },
    { ENETUNREACH     /*101*/,  "网络不可达" },
    { ENETRESET       /*102*/,  "网络由于复位断开连接" },
    { ECONNABORTED    /*103*/,  "软件导致连接终止" },
    { ECONNRESET      /*104*/,  "连接被对方复位" },
    { ENOBUFS         /*105*/,  "没有可用的缓存空间" },
    { EISCONN         /*106*/,  "传输端点已连接" },
    { ENOTCONN        /*107*/,  "传输端点未连接" },
    { ESHUTDOWN       /*108*/,  "传输端点关闭后不能在发送" },
    { ETOOMANYREFS    /*109*/,  "太多的引用：无法接合" },
    { ETIMEDOUT       /*110*/,  "连接超时" },
    { ECONNREFUSED    /*111*/,  "连接被拒绝" },
    { EHOSTDOWN       /*112*/,  "主机已关闭" },
    { EHOSTUNREACH    /*113*/,  "无法路由到主机" },
    { EALREADY        /*114*/,  "操作已在进程中" },
    { EINPROGRESS     /*115*/,  "进程中正在进行的操作" },
    { ESTALE          /*116*/,  "NFS文件句柄无效" },
    { EUCLEAN         /*117*/,  "结构需要清理" },
    { ENOTNAM         /*118*/,  "没有XENIX类型的文件" },
    { ENAVAIL         /*119*/,  "没有有效的XENIX信号量" },
    { EISNAM          /*120*/,  "有名类型文件" },
    { EREMOTEIO       /*121*/,  "远端io错误" },
    { EDQUOT          /*122*/,  "超出配额" },
    { ENOMEDIUM       /*123*/,  "没有发现介质" },
    { EMEDIUMTYPE     /*124*/,  "错误的介质类型" },
};
    
const char * safe_error_text(uint32_t num)
{
    if (num > EMEDIUMTYPE)
        return "Unknow error";
    return g_error_text[num].str;
}

/* Wrapper around strerror to handle case where it returns NULL. */
const char * safe_strerror(int errnum)
{
    const char *s = strerror(errnum);
    return (s != NULL) ? s : "Unknown error";
}

/*
 * A more sensible inet_ntop that can figure out what to do for different
 * address families on its own. Takes an addrinfo structure (rather than a
 * in_addr or in6_addr), and a buffer to return the result in. Internally it
 * uses this information to call inet_ntop with sensible arguments.
 */
/*const char *igw_inet_ntop(struct addrinfo *addr, char *buffer)
{
    void *addrptr;

    ASSERT(addr);
    ASSERT(buffer);

    switch (addr->ai_family)
    {
    case AF_INET:
        addrptr = &((struct sockaddr_in*)addr->ai_addr)->sin_addr;
        break;
    case AF_INET6:
        addrptr = &((struct sockaddr_in6*)addr->ai_addr)->sin6_addr;
        break;
    default:
        snprintf(buffer, INET6_ADDRSTRLEN, "unknown");
        return buffer;
    }

    return inet_ntop(addr->ai_family, addrptr, buffer, INET6_ADDRSTRLEN);
}
*/

int rtnl_open(struct rtnl_handle *rth)
{
    int namelen, ret;
    int sndbuf_len = 32768;
    int rcvbuf_len = NL_RCV_BUF_SIZE;

    rth->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (rth->fd < 0)
    {
        log_msg(L_ERR, "Can't open netlink socket: %s", safe_strerror(errno));
        return -1;
    }

    if (setsockopt(rth->fd, SOL_SOCKET, SO_SNDBUF, &sndbuf_len, sizeof(sndbuf_len)) < 0)
    {
        log_msg(L_ERR, "set SO_SNDBUF failed");
        return -1;
    }
    if (setsockopt(rth->fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf_len, sizeof(rcvbuf_len)) < 0)
    {
        log_msg(L_ERR, "set SO_RCVBUF failed");
        return -1;
    }

    /* Older kernels may not support extended ACK reporting */
    //setsockopt(rth.fd, SOL_NETLINK, NETLINK_EXT_ACK, &one, sizeof(one));

    rth->local.nl_family = AF_NETLINK;
    rth->local.nl_groups = 0;

    /* Bind the socket to the netlink structure for anything. */
    ret = bind(rth->fd, (struct sockaddr *)&rth->local, sizeof(rth->local));
    if (ret < 0)
    {
        log_msg(L_ERR, "Can't bind netlink socket: %s\n", safe_strerror(errno));
        close (rth->fd);
        return -1;
    }

    /* multiple netlink sockets will have different nl_pid */
    namelen = sizeof(rth->local);
    ret = getsockname(rth->fd, (struct sockaddr *)&rth->local, (socklen_t *)&namelen);
    if (ret < 0 || namelen != sizeof(rth->local))
    {
        log_msg(L_ERR, "Can't get netlink socket name: %s\n", safe_strerror(errno));
        close (rth->fd);
        return -1;
    }

    rth->seq = 0;

    return 0;
}

void rtnl_close(struct rtnl_handle *rth)
{
    if (rth->fd >= 0)
    {
        close(rth->fd);
        rth->fd = -1;
    }
}

static int rtnl_recvmsg(int fd, struct msghdr *msg, int flags)
{
    int len;

    len = recvmsg(fd, msg, flags);
    if (len < 0)
    {
        log_msg(L_ERR, "netlink receive error %s (%d)\n", strerror(errno), errno);
        return -errno;
    }
    if (len == 0)
    {
        log_msg(L_ERR, "EOF on netlink\n");
        return -ENODATA;
    }

    return len;
}

static int rtnl_recvmsg_iov(int fd, struct msghdr *msg, char **answer)
{
    struct iovec *iov = msg->msg_iov;
    char *buf;
    int len;

    iov->iov_base = NULL;
    iov->iov_len = 0;

    len = rtnl_recvmsg(fd, msg, MSG_PEEK | MSG_TRUNC);
    if (len < 0)
    {
        return len;
    }

    buf = malloc(len);
    if (!buf)
    {
        log_msg(L_ERR, "malloc error: not enough buffer, len %d\n", len);
        return -1;
    }

    memset(buf, 0, len);
    iov->iov_base = buf;
    iov->iov_len = len;

    len = rtnl_recvmsg(fd, msg, 0);
    if (len < 0)
    {
        free(buf);
        return len;
    }

    if (answer)
        *answer = buf;
    else
        free(buf);

    return len;
}


static int rtnl_talk_iov(struct rtnl_handle *rth, struct iovec *iov, size_t iovlen, struct nlmsghdr **answer)
{
    struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
    struct iovec riov;
    struct msghdr msg = {
        .msg_name = &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov = iov,
        .msg_iovlen = iovlen,
    };
    struct nlmsghdr *h;
    int i, status;
    unsigned int seq = 0;
    char *buf;

    for (i = 0; i < iovlen; i++)
    {
        h = iov[i].iov_base;
        h->nlmsg_seq = seq = ++rth->seq;
        if (answer == NULL)
            h->nlmsg_flags |= NLM_F_ACK;
    }

    status = sendmsg(rth->fd, &msg, 0);
    if (status < 0)
    {
        log_msg(L_ERR, "Cannot talk to rtnetlink: %s\n", safe_strerror(errno));
        return -1;
    }

    /* change msg to use the response iov */
    msg.msg_iov = &riov;
    msg.msg_iovlen = 1;
    i = 0;

next:
    status = rtnl_recvmsg_iov(rth->fd, &msg, &buf);
    ++i;

    if (status < 0)
    {
        return status;
    }
    if (msg.msg_namelen != sizeof(nladdr))
    {
        log_msg(L_ERR, "sender address length == %d\n", msg.msg_namelen);
        return -1;
    }
    for (h = (struct nlmsghdr *)buf; status >= sizeof(*h); )
    {
        int len = h->nlmsg_len;
        int l = len - sizeof(*h);

        if (l < 0 || len > status)
        {
            if (msg.msg_flags & MSG_TRUNC)
            {
                log_msg(L_ERR, "Truncated message\n");
            }
            else
            {
                log_msg(L_ERR, "!!!malformed message: len=%d\n", len);
            }
            free(buf);
            return -1;
        }

        if (nladdr.nl_pid != 0 ||
            h->nlmsg_pid != rth->local.nl_pid ||
            h->nlmsg_seq > seq || h->nlmsg_seq < seq - iovlen)
        {
            status -= NLMSG_ALIGN(len);
            h = (struct nlmsghdr *)((char *)h + NLMSG_ALIGN(len));
            continue;
        }

        if (h->nlmsg_type == NLMSG_ERROR)
        {
            struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(h);

            if (l < sizeof(struct nlmsgerr))
            {
                log_msg(L_ERR, "ERROR truncated\n");
            }
            else if (!err->error)
            {
                if (answer)
                    *answer = (struct nlmsghdr *)buf;
                else
                    free(buf);
                if (h->nlmsg_seq == seq)
                    return 0;
                else if (i < iovlen)
                    goto next;
                return 0;
			}

            errno = -err->error;
            free(buf);
            return -1;
        }

        if (answer)
        {
            *answer = (struct nlmsghdr *)buf;
            return 0;
        }

        status -= NLMSG_ALIGN(len);
        h = (struct nlmsghdr *)((char *)h + NLMSG_ALIGN(len));
    }
    free(buf);

    if (msg.msg_flags & MSG_TRUNC)
    {
        log_msg(L_ERR, "Message truncated\n");
        return -1;
    }
    if (status)
    {
        log_msg(L_ERR, "!!!Remnant of size %d\n", status);
        return -1;
    }
    return 0;
}

int rtnl_talk(struct rtnl_handle *rth, struct nlmsghdr *n, struct nlmsghdr **answer)
{
    struct iovec iov = {
        .iov_base = n,
        .iov_len = n->nlmsg_len
    };

    return rtnl_talk_iov(rth, &iov, 1, answer);
}

int rtnl_linkdump_req(struct rtnl_handle *rth, int family)
{
    struct {
        struct nlmsghdr nlh;
        struct ifinfomsg ifm;
    } req = {
        .nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
        .nlh.nlmsg_type = RTM_GETLINK,
        .nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
        .nlh.nlmsg_seq = rth->dump = ++rth->seq,
        .ifm.ifi_family = family,
    };

    return send(rth->fd, &req, sizeof(req), 0);
}

int rtnl_dump_filter(struct rtnl_handle *rth, rtnl_dump_cb cb, void *arg)
{
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	char *buf;

    while (1)
    {
        int status;
        int msglen;
        int found_done = 0;
        struct nlmsghdr *h;

        status = rtnl_recvmsg_iov(rth->fd, &msg, &buf);
        if (status < 0)
            return status;

        h = (struct nlmsghdr *)buf;
        msglen = status;

        while (NLMSG_OK(h, msglen))
        {
            int err = 0;

            h->nlmsg_flags &= ~0;

            if (nladdr.nl_pid != 0 ||
                h->nlmsg_pid != rth->local.nl_pid ||
                h->nlmsg_seq != rth->dump)
                goto skip_it;

            if (h->nlmsg_type == NLMSG_DONE)
            {
#if 0
                err = rtnl_dump_done(h);
                if (err < 0)
                {
                    free(buf);
                    return -1;
                }
#endif
                found_done = 1;
                break; /* process next filter */
            }

            if (h->nlmsg_type == NLMSG_ERROR)
            {
                //rtnl_dump_error(rth, h);
                free(buf);
                return -1;
            }

            err = cb(h, arg);
            if (err < 0)
            {
                free(buf);
                return err;
            }

skip_it:
            h = NLMSG_NEXT(h, msglen);
        }
        free(buf);

        if (found_done)
        {
            return 0;
        }

        if (msg.msg_flags & MSG_TRUNC)
        {
            log_msg(L_ERR, "Message truncated\n");
            continue;
        }
        if (msglen)
        {
            log_msg(L_ERR, "!!!Remnant of size %d\n", msglen);
            return -1;
        }
    }

    return 0;
}

int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data, int alen)
{
    int len = RTA_LENGTH(alen);
    struct rtattr *rta;

    if (NLMSG_ALIGN(n->nlmsg_len) + len > maxlen)
    {
        return -1;
    }
    rta = (struct rtattr*)(((char*)n) + NLMSG_ALIGN(n->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = len;
    memcpy(RTA_DATA(rta), data, alen);
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);

    return 0;
}

int addattr32 (struct nlmsghdr *n, size_t maxlen, int type, int data)
{
    return addattr_l(n, maxlen, type,  &data, 4);
}


int parse_rtattr_flags(struct rtattr *tb[], int max, struct rtattr *rta,
		       int len, unsigned short flags)
{
    unsigned short type;

    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
    while (RTA_OK(rta, len))
    {
        type = rta->rta_type & ~flags;
        if ((type <= max) && (!tb[type]))
        tb[type] = rta;
        rta = RTA_NEXT(rta, len);
    }
    if (len)
        fprintf(stderr, "!!!Deficit %d, rta_len=%d\n", len, rta->rta_len);
    return 0;
}
               
int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
    return parse_rtattr_flags(tb, max, rta, len, 0);
}


unsigned int get_ip_subnet_mask(const unsigned int mask_length)
{
    static const unsigned int masks[33] = {
        0x00000000,
        0x80000000, 0xc0000000, 0xe0000000, 0xf0000000,
        0xf8000000, 0xfc000000, 0xfe000000, 0xff000000,
        0xff800000, 0xffc00000, 0xffe00000, 0xfff00000,
        0xfff80000, 0xfffc0000, 0xfffe0000, 0xffff0000,
        0xffff8000, 0xffffc000, 0xffffe000, 0xfffff000,
        0xfffff800, 0xfffffc00, 0xfffffe00, 0xffffff00,
        0xffffff80, 0xffffffc0, 0xffffffe0, 0xfffffff0,
        0xfffffff8, 0xfffffffc, 0xfffffffe, 0xffffffff,
    };

    if (mask_length > 32)
    {
        return 0;
    }

    return masks[mask_length];
}

int mask2prefix(uint32_t mask)
{
    int count = 0;
    uint32_t seen_one = 0;

    while (mask > 0)
    {
        if (mask & 1)
        {
            seen_one = 1;
            count++;
        }
        else
        {
            if (seen_one)
                return -1;
        }
        mask >>= 1;
    }

    return count;
}

int maskstr2prefix(const char *str)
{
    if (!str)
        return 0;

    struct in_addr addr;
    if (inet_aton(str, &addr) == 0)
        return 0;
    addr.s_addr = htonl(addr.s_addr);

    return mask2prefix(addr.s_addr);
}

/** 
 * determine if a string is a valid ipv4 address
 *
 * @param str
 *  Pointer to a character string containing an IPV4 address.
 *  A valid IPV4 address is a character string containing a dotted format of "ddd.ddd.ddd.ddd"
 *
 * @return
 *  - 1: valid.
 *  - 0: invalid.
 */
static bool is_valid_ipv4_str(const char *str)
{
    int alen = 0;
    char addr[4][4];
    int x, dots = 0;

    memset(&addr, 0, sizeof(addr));

    uint32_t len = strlen(str);
    uint32_t i = 0;
    for (i = 0; i < len; i++)
    {
        if (!(str[i] == '.' || isdigit(str[i])))
        {
            return 0;
        }
        if (str[i] == '.')
        {
            if (dots == 3)
            {
                return 0;
            }
            addr[dots][alen] = '\0';
            dots++;
            alen = 0;
        }
        else
        {
            if (alen >= 4)
            {
                return 0;
            }
            addr[dots][alen++] = str[i];
        }
    }
    if (dots != 3)
        return 0;

    addr[dots][alen] = '\0';
    for (x = 0; x < 4; x++)
    {
        int a = atoi(addr[x]);
        if (a < 0 || a >= 256)
        {
            return 0;
        }
    }
    return 1;
}

/**
 * Validates an IPV4 address
 *
 * @param str
 *  Pointer to a character string containing an IPV4 address.
 *
 * @return
 *  an in_addr containing the network endian format of the IPv4 address.
 *  0 if the IPV4 address is invalid
 */
static in_addr_t inet_addr_safe(const char *str)
{
    struct in_addr addr;

    if (!str)
        return INADDR_ANY;

    if (!inet_aton(str, &addr))
        return INADDR_ANY;
    else
        return addr.s_addr;
}

/**
 * Validates an IPV4 address
 *
 * @param str
 *  Pointer to a character string containing an IPV4 address.
 *  A valid IPV4 address is a character string containing a dotted format of "ddd.ddd.ddd.ddd"
 *
 * @return
 *  1: if the IPv4 address is valid.
 *  0: if the IPV4 address is invalid
 */
int is_valid_ipv4(const char *str)
{
    if (!is_valid_ipv4_str(str))
        return 0;

    return (inet_addr_safe(str) != INADDR_ANY) ? 1 : 0;
}

int is_valid_ipv6(const char *ipv6_str) {
    struct in6_addr addr;
    int result = inet_pton(AF_INET6, ipv6_str, &addr);
    return result == 1;
}

/**
 * Check if 2 IPv4 addresses fall in the same subnet.
 *
 * @param ip1
 *  Pointer to a character string containing an IPV4 address.
 * @param ip2
 *  Pointer to a character string containing an IPV4 address.
 * @param netmask
 *  Pointer to a character string containing an IPV4 address netmask.
 *
 * @return
 *  1 if the 2 IPv4 addresses belong to the same network segment.
 *  otherwise 0.
 */
int is_same_subnet(const char *ip1, const char *ip2, const char *netmask)
{
    unsigned int addr1, addr2, mask;

    addr1 = ntohl(inet_addr(ip1));
    addr2 = ntohl(inet_addr(ip2));
    mask  = ntohl(inet_addr(netmask));

    return (addr1 & mask) == (addr2 & mask);
}

/**
 * Get interface ip address by name
 *
 * @param name  interface name.
 * @param ip returned ip address of interface.
 * @param netmask returned netmask of interface.
 *
 * @retval 0 on success, otherwise -1.
 */
int get_interface_ip(char *name, char *ip, char *netmask)
{
    struct ifaddrs *if_addrs = NULL, *tmp_addr = NULL;
    void *addr_ptr;
    int rc;

    rc = getifaddrs(&if_addrs);
    if (rc == 0)
    {
        for (tmp_addr = if_addrs; tmp_addr != NULL; tmp_addr = tmp_addr->ifa_next)
        {
            if (tmp_addr->ifa_addr &&
                (tmp_addr->ifa_addr->sa_family == AF_INET) &&
                (0 == strcmp(tmp_addr->ifa_name, name)))
            {
                addr_ptr = &((struct sockaddr_in *)tmp_addr->ifa_addr)->sin_addr;
                inet_ntop(AF_INET, addr_ptr, ip, INET_ADDRSTRLEN);
                if (netmask)
                {
                    addr_ptr = &((struct sockaddr_in *)tmp_addr->ifa_netmask)->sin_addr;
                    inet_ntop(AF_INET, addr_ptr, netmask, INET_ADDRSTRLEN);
                }
                break;
            }
        }

        if (!tmp_addr)
        {
            rc = -1;
        }

        /* free ifaddrs */
        freeifaddrs(if_addrs);
    }

    return rc;
}

/*
 * Perform a call to getaddrinfo expecting a numeric host of any family.
 */
struct addrinfo * get_numeric_address(char *address, char *port)
{
    struct addrinfo hints, *result;

    if (!address)
    {
        return NULL;
    }

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_NUMERICHOST;

    /* check if the given string is one of our addresses */
    if (getaddrinfo(address, port, &hints, &result) == 0)
    {
        return result;
    }

    return NULL;
}

int ll_addr_a2n(char *lladdr, int len, const char *arg)
{
    int i;

    for (i = 0; i < len; i++)
    {
        int temp;
        char *cp = strchr(arg, ':');
        if (cp)
        {
            *cp = 0;
            cp++;
        }
        if (sscanf(arg, "%x", &temp) != 1)
        {
            log_msg(L_ERR, "[ARP] %s is invalid lladdr", arg);
            return -1;
        }
        if (temp < 0 || temp > 255)
        {
            log_msg(L_ERR, "[ARP] %s is invalid lladdr", arg);
            return -1;
        }
        lladdr[i] = temp;
        if (!cp)
            break;
        arg = cp;
    }
    return i + 1;
}

const char * ll_addr_n2a(const unsigned char *addr, int alen, int type, char *buf, int blen)
{
    int i, l;

    if (alen == 4 && (type == ARPHRD_TUNNEL || type == ARPHRD_SIT || type == ARPHRD_IPGRE))
        return inet_ntop(AF_INET, addr, buf, blen);

    if (alen == 16 && (type == ARPHRD_TUNNEL6 || type == ARPHRD_IP6GRE))
        return inet_ntop(AF_INET6, addr, buf, blen);

    snprintf(buf, blen, "%02x", addr[0]);
    for (i = 1, l = 2; i < alen && l < blen; i++, l += 3)
        snprintf(buf + l, blen - l, ":%02x", addr[i]);
    return buf;
}

const char *rt_addr_n2a(int af, int len, const void *addr)
{
    static char buf[256];

    switch (af)
    {
    case AF_INET:
    case AF_INET6:
        return inet_ntop(af, addr, buf, 256);
    case AF_PACKET:
        return ll_addr_n2a(addr, len, ARPHRD_VOID, buf, 256);
    case AF_BRIDGE:
    {
        const union {
        struct sockaddr sa;
        struct sockaddr_in sin;
        struct sockaddr_in6 sin6;
        } *sa = addr;

        switch (sa->sa.sa_family)
        {
        case AF_INET:
            return inet_ntop(AF_INET, &sa->sin.sin_addr, buf, 256);
        case AF_INET6:
            return inet_ntop(AF_INET6, &sa->sin6.sin6_addr, buf, 256);
        }

        /* fallthrough */
    }
    default:
        return "???";
    }
}

static int check_ifname(const char *name)
{
    /* These checks mimic kernel checks in dev_valid_name */
    if (*name == '\0')
    {
        return -1;
    }
    if (strlen(name) >= IFNAMSIZ)
    {
        return -1;
    }

    while (*name)
    {
        if (*name == '/' || isspace(*name))
        {
            return -1;
        }
        ++name;
    }
    return 0;
}

static const char *tnl_defname(const struct ip_tunnel_parm *p)
{
    switch (p->iph.protocol)
    {
    case IPPROTO_IPIP:
        if (p->i_flags & VTI_ISVTI)
            return "ip_vti0";
        else
            return "tunl0";
    case IPPROTO_GRE:
        return "gre0";
    case IPPROTO_IPV6:
        return "sit0";
    }
    return NULL;
}

int tnl_get_ioctl(const char *basedev, void *p)
{
    struct ifreq ifr;
    int fd;
    int err;

    strncpy(ifr.ifr_name, basedev, IFNAMSIZ);
    ifr.ifr_ifru.ifru_data = (void *)p;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        log_msg(L_ERR, "[IP TUNNEL] Create socket failed: %s", strerror(errno));
        return -1;
    }

    err = ioctl(fd, SIOCGETTUNNEL, &ifr);
    if (err)
        log_msg(L_ERR, "[IP TUNNEL] get tunnel \"%s\" failed: %s", basedev, strerror(errno));

    close(fd);
    return err;
}

static int tnl_add_ioctl(int cmd, const char *basedev, const char *name, void *p)
{
    struct ifreq ifr;
    int fd;
    int err;

    if (cmd == SIOCCHGTUNNEL && name[0])
        strncpy(ifr.ifr_name, name, IFNAMSIZ);
    else
        strncpy(ifr.ifr_name, basedev, IFNAMSIZ);
    ifr.ifr_ifru.ifru_data = p;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        log_msg(L_ERR, "[IP TUNNEL] create socket failed: %s", strerror(errno));
        return -1;
    }

    err = ioctl(fd, cmd, &ifr);
    if (err)
    {
        log_msg(L_ERR, "[IP TUNNEL] add tunnel \"%s\" failed: %s", ifr.ifr_name, strerror(errno));
    }
    close(fd);
    return err;
}

static int tnl_del_ioctl(const char *basedev, const char *name, void *p)
{
    struct ifreq ifr;
    int fd;
    int err;

    if (name[0])
        strncpy(ifr.ifr_name, name, IFNAMSIZ);
    else
        strncpy(ifr.ifr_name, basedev, IFNAMSIZ);

    ifr.ifr_ifru.ifru_data = p;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        log_msg(L_ERR, "[IP TUNNEL] create socket failed: %s", strerror(errno));
        return -1;
    }

    err = ioctl(fd, SIOCDELTUNNEL, &ifr);
    if (err)
    {
        log_msg(L_ERR, "[IP TUNNEL] delete tunnel \"%s\" failed: %s\n", ifr.ifr_name, strerror(errno));
    }   
    close(fd);
    return err;
}

/*
 * ip tunnel add gre1 local 1.1.1.1 remote 2.2.2.2 mode gre key 123456 csum dev eth0
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
                  unsigned int proto, unsigned int key, unsigned int flags)
{
	struct ip_tunnel_parm p;
    const char *basedev;

    if (!name || check_ifname(name) != 0)
    {
        log_msg(L_ERR, "[IP TUNNEL] \"%s\" is not a valid ifname", name);
        return -1;
    }

    memset(&p, 0, sizeof(p));
    p.iph.version = 4;
    p.iph.ihl = 5;
    p.iph.frag_off = htons(IP_DF);
    strncpy(p.name, name, IFNAMSIZ);
    p.iph.saddr = inet_addr(saddr);
    p.iph.daddr = inet_addr(daddr);
    p.iph.protocol = proto;

    if (flags & GRE_WITH_KEY)
    {
        p.i_flags |= GRE_KEY;
        p.o_flags |= GRE_KEY;
        p.i_key = p.o_key = htonl(key);
    }
    if (flags & GRE_WITH_CKSUM)
    {
        p.i_flags |= GRE_CSUM;
        p.o_flags |= GRE_CSUM;
    }
    if (dev)
    {
        p.link = ll_name_to_index(dev);
    }

    basedev = tnl_defname(&p);
    if (!basedev)
    {
        log_msg(L_ERR, "[IP TUNNEL] cannot detemine tunnel mode");
        return -1;
    }

    return tnl_add_ioctl(SIOCADDTUNNEL, basedev, p.name, &p);
}

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
                  const char *daddr, unsigned int proto, unsigned int key, unsigned int flags)
{
    const char *basedev;
	struct ip_tunnel_parm p;
    struct ip_tunnel_parm old_p = {};

    if (!name || check_ifname(name) != 0)
    {
        log_msg(L_ERR, "[IP TUNNEL] \"%s\" is not a valid ifname", name);
        return -1;
    }

    if (tnl_get_ioctl(name, &old_p))
    {
        return -1;
    }
    p = old_p;

    p.iph.version = 4;
    p.iph.ihl = 5;
    p.iph.frag_off = htons(IP_DF);
    strncpy(p.name, name, IFNAMSIZ);
    p.iph.saddr = inet_addr(saddr);
    p.iph.daddr = inet_addr(daddr);
    p.iph.protocol = proto;

    if (flags & GRE_WITH_KEY)
    {
        p.i_flags |= GRE_KEY;
        p.o_flags |= GRE_KEY;
        p.i_key = p.o_key = htonl(key);
    }
    if (flags & GRE_WITH_CKSUM)
    {
        p.i_flags |= GRE_CSUM;
        p.o_flags |= GRE_CSUM;
    }
    if (dev)
    {
        p.link = ll_name_to_index(dev);
    }

    basedev = tnl_defname(&p);
    if (!basedev)
    {
        log_msg(L_ERR, "[IP TUNNEL] cannot detemine tunnel mode");
        return -1;
    }

    return tnl_add_ioctl(SIOCCHGTUNNEL, basedev, p.name, &p);
}

/*
 * ip tunnel del gre1
 *
 * @param name - tunnel name
 * @retval 0 on success, otherwise -1.
 */
int ip_tunnel_del(const char *name)
{
	struct ip_tunnel_parm p;

    if (!name || check_ifname(name) != 0)
    {
        log_msg(L_ERR, "[IP TUNNEL] \"%s\" is not a valid ifname", name);
        return -1;
    }

    memset(&p, 0, sizeof(p));
    p.iph.version = 4;
    p.iph.ihl = 5;
    p.iph.frag_off = htons(IP_DF);
    strncpy(p.name, name, IFNAMSIZ);

    return tnl_del_ioctl(tnl_defname(&p) ? : p.name, p.name, &p);
}

void rtnl_table_init(void)
{
    FILE *fp;
    int id;
    char buf[RT_NAME_LEN_MAX] = {0};
    char namebuf[RT_NAME_LEN_MAX] = {0};

    fp  = fopen(RT_TABLES_FILE, "r");
    if (!fp)
    {
        return;
    }

    while (fgets(buf, sizeof(buf), fp))
    {
        char *p = buf;

        while (*p == ' ' || *p == '\t')
            p++;

        if (*p == '#' || *p == '\n' || *p == 0)
            continue;

        if (sscanf(p, "0x%x %s\n", &id, namebuf) != 2 &&
            sscanf(p, "0x%x %s #", &id, namebuf) != 2 &&
            sscanf(p, "%d %s\n", &id, namebuf) != 2 &&
            sscanf(p, "%d %s #", &id, namebuf) != 2)
        {
            continue;
        }

        if (id < 0 || id >= RT_ID_MAX)
        {
            continue;
        }
        g_rtnl_name[id] = strdup(namebuf);
    }

    fclose(fp);
}

int rtnl_table_a2n(uint32_t *id, const char *name)
{
    uint32_t i;

    for (i = 0; i < RT_ID_MAX; i++)
    {
        if (g_rtnl_name[i] && !strcmp(g_rtnl_name[i], name))
        {
            *id = i;
            return 0;
        }
    }

    return -1;
}

const char * rtnl_table_n2a(uint32_t id)
{
    if (id < RT_ID_MAX)
    {
        return g_rtnl_name[id];
    }
    return NULL;
}

void rtnl_table_add(int id, const char *name)
{
    FILE *fp;

    if (id < 0 || id >= RT_ID_MAX)
    {
        log_msg(L_ERR, "Route table id %d is invalid", id);
        return;
    }

    if (g_rtnl_name[id] != NULL)
    {
        return;
    }

    fp  = fopen(RT_TABLES_FILE, "a+");
    if (!fp)
    {
        return;
    }

    fprintf(fp, "%d\t%s\n", id, name);

    g_rtnl_name[id] = strdup(name);

    fclose(fp);
}

void rtnl_table_del(int id, const char *name)
{
    char buf[RT_NAME_LEN_MAX];
    char namebuf[RT_NAME_LEN_MAX] = {0};
    FILE *fp, *fpt;
    int tmp_id;

    if (id < 0 || id >= RT_ID_MAX)
    {
        log_msg(L_ERR, "Route table id %d is invalid", id);
        return;
    }

    if (g_rtnl_name[id] == NULL)
    {
        return;
    }

    fp  = fopen(RT_TABLES_FILE, "r");
    if (!fp)
    {
        return;
    }
    fpt  = fopen(RT_TABLES_TMP_FILE, "w");
    if (!fpt)
    {
        fclose(fp);
        return;
    }

    while (fgets(buf, sizeof(buf), fp))
    {
        char *p = buf;

        while (*p == ' ' || *p == '\t')
            p++;

        if (*p == '#' || *p == '\n' || *p == 0)
        {
            fprintf(fpt, "%s", buf);
            continue;
        }

        if (sscanf(p, "0x%x %s\n", &tmp_id, namebuf) != 2 &&
            sscanf(p, "0x%x %s #", &tmp_id, namebuf) != 2 &&
            sscanf(p, "%d %s\n", &tmp_id, namebuf) != 2 &&
            sscanf(p, "%d %s #", &tmp_id, namebuf) != 2)
        {
            fprintf(fpt, "%s", buf);
            continue;
        }

        if (id == tmp_id && !strcmp(name, namebuf))
        {
            continue;
        }
        fprintf(fpt, "%s", buf);
    }
    fclose(fp);
    fclose(fpt);

    fp  = fopen(RT_TABLES_FILE, "wb");
    if (!fp)
    {
        return;
    }
    fpt  = fopen(RT_TABLES_TMP_FILE, "r");
    if (!fpt)
    {
        fclose(fp);
        return;
    }

    while(!feof(fpt))
    {
        buf[0] = '\0';
        fgets(buf, sizeof(buf), fpt);
        fprintf(fp, "%s", buf);
    }
    fclose(fp);
    fclose(fpt);

    free(g_rtnl_name[id]);
    g_rtnl_name[id] = NULL;

}

int rtnl_neigh_dump_req(struct rtnl_handle *rth, int family, req_filter_fn_t filter_fn, void *arg)
{
    struct {
        struct nlmsghdr nlh;
        struct ndmsg ndm;
        char buf[256];
    } req = {
        .nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg)),
        .nlh.nlmsg_type = RTM_GETNEIGH,
        .nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
        .nlh.nlmsg_seq = rth->dump = ++rth->seq,
        .ndm.ndm_family = family,
    };

    if (filter_fn)
    {
        int err = filter_fn(&req.nlh, sizeof(req), arg);
        if (err)
            return err;
    }

    return send(rth->fd, &req, sizeof(req), 0);
}

/**
 * list ip rules request
 * ip rule show
 */
int rtnl_rule_dump_req(struct rtnl_handle *rth, int family)
{
    struct {
        struct nlmsghdr nlh;
		struct fib_rule_hdr frh;
    } req = {
        .nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct fib_rule_hdr)),
        .nlh.nlmsg_type = RTM_GETRULE,
        .nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
        .nlh.nlmsg_seq = rth->dump = ++rth->seq,
        .frh.family = family
    };

    return send(rth->fd, &req, sizeof(req), 0);
}

int rtnl_route_dump_req(struct rtnl_handle *rth, int family, req_filter_fn_t filter_fn, void *arg)
{
    struct {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
        char buf[128];
    } req = {
        .nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
        .nlh.nlmsg_type = RTM_GETROUTE,
        .nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
        .nlh.nlmsg_seq = rth->dump = ++rth->seq,
        .rtm.rtm_family = AF_INET,
    };

    if (filter_fn)
    {
        int err = filter_fn(&req.nlh, sizeof(req), arg);
        if (err)
            return err;
    }

    return send(rth->fd, &req, sizeof(req), 0);
}

/**
 * delete a network interface
 * ip link del name
 */
int ip_link_del(const char *name)
{
	iplink_req_t req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
		.n.nlmsg_flags = NLM_F_REQUEST,
		.n.nlmsg_type = RTM_DELLINK,
		.i.ifi_family = AF_INET,
	};
    struct rtnl_handle rth;
    int ret;

    if (!name)
    {
        log_msg(L_ERR, "network interface is null.");
        return -1;
    }
    if (check_ifname(name))
    {
        log_msg(L_ERR, "\"%s\" is not a valid ifname", name);
        return -1;
    }

    memset(&rth, 0, sizeof(rth));
    if (rtnl_open(&rth) < 0)
    {
        log_msg(L_ERR, "open netlink failed");
        return -1;
    }

    addattr_l(&req.n, sizeof(req), IFLA_IFNAME, name, strlen(name) + 1);

    /* sending the message to the kernel. */
    ret = rtnl_talk(&rth, &req.n, NULL);
    if (ret < 0)
    {
        if (errno == NL_ERR_FILE_EXIST)
        {
            ret = 0;
        }
        else
        {
            log_msg(L_ERR, "Failed talk to rtnetlink: %s\n", safe_strerror(errno));
        }
    }
    rtnl_close(&rth);

    return ret;
}

/* 
 * ip link set vti0 up/down
 * @param updown  1: up, 0: down
 */
int ip_link_set(const char *name, int updown)
{
    struct ifreq ifr;
    int fd, err;
    unsigned int mask, flags;

    if (updown == 1)
    {
        /* up */
        mask = IFF_UP;
        flags = IFF_UP;
    }
    else
    {
        /* down */
        mask = IFF_UP;
        flags = ~IFF_UP;
    }

    strncpy(ifr.ifr_name, name, IFNAMSIZ);
    fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        fd = socket(PF_PACKET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    err = ioctl(fd, SIOCGIFFLAGS, &ifr);
    if (err)
    {
        close(fd);
        return -1;
    }
    if ((ifr.ifr_flags^flags) & mask)
    {
        ifr.ifr_flags &= ~mask;
        ifr.ifr_flags |= mask&flags;
        err = ioctl(fd, SIOCSIFFLAGS, &ifr);
    }
    close(fd);
    return err;
}

int iplink_stats_get(char *ifname, iplink_stats_t *stats)
{
    struct rtnl_handle rth;
	iplink_req_t req = {
        .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
        .n.nlmsg_flags = NLM_F_REQUEST,
        .n.nlmsg_type = RTM_GETLINK,
        .i.ifi_family = AF_INET,
	};
	struct nlmsghdr *answer = NULL;
    struct rtattr *tb[IFLA_MAX+1];
    struct ifinfomsg *ifi;
    int len, ret;

    memset(&rth, 0, sizeof(rth));
    if (rtnl_open(&rth) < 0)
    {
        log_msg(L_ERR, "open netlink failed");
        return -1;
    }

    addattr_l(&req.n, sizeof(req), IFLA_IFNAME, ifname, strlen(ifname) + 1);
    addattr32(&req.n, sizeof(req), IFLA_EXT_MASK, RTEXT_FILTER_VF);

    ret = rtnl_talk(&rth, &req.n, &answer);
    if (ret < 0 || !answer)
    {
        rtnl_close(&rth);
        return -1;
    }

    ifi = NLMSG_DATA(answer);
    if (answer->nlmsg_type != RTM_NEWLINK && answer->nlmsg_type != RTM_DELLINK)
        return 0;
    len = answer->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));
    if (len < 0)
        return -1;

    parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);
    if (tb[IFLA_IFNAME] == NULL)
        log_msg(L_ERR, "device with ifindex %d has nil ifname", ifi->ifi_index);

    if (tb[IFLA_STATS64])
    {
        //struct rtnl_link_stats64 stats = { 0 };
        stats->type = IP_LINK_STATS64;
        memcpy(&stats->stats64, RTA_DATA(tb[IFLA_STATS64]), MIN(RTA_PAYLOAD(tb[IFLA_STATS64]), sizeof(stats->stats64)));
    }
    else if (tb[IFLA_STATS])
    {
        stats->type = IP_LINK_STATS;
        memcpy(&stats->stats, RTA_DATA(tb[IFLA_STATS]), MIN(RTA_PAYLOAD(tb[IFLA_STATS]), sizeof(stats->stats)));
    }

    free(answer);
    rtnl_close(&rth);
    return 0;
}

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
int ip_address_add(const char *dev, const char *local, uint8_t local_prefixlen, const char *peer, uint8_t peer_prefixlen)
{
    struct rtnl_handle rth;
    uint32_t addr;
    int ret;

    if (!dev)
    {
        log_msg(L_ERR, "[IP] Network interface is null.");
        return -1;
    }
    if (check_ifname(dev))
    {
        log_msg(L_ERR, "[IP] \"%s\" is not a valid interface name", dev);
        return -1;
    }

    struct {
        struct nlmsghdr n;
        struct ifaddrmsg ifa;
        char buf[256];
    } req = {
        .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg)),
        .n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL,
        .n.nlmsg_type = RTM_NEWADDR,
        .ifa.ifa_family = AF_INET,
    };

    addr = inet_addr(local);
    addattr_l(&req.n, sizeof(req), IFA_LOCAL, &addr, 4);

    if (peer)
    {
        addr = inet_addr(peer);
        addattr_l(&req.n, sizeof(req), IFA_ADDRESS, &addr, 4);
        req.ifa.ifa_prefixlen = peer_prefixlen;
    }

    if (req.ifa.ifa_prefixlen == 0)
    {
        req.ifa.ifa_prefixlen = local_prefixlen;
    }

    req.ifa.ifa_index = ll_name_to_index(dev);
    if (!req.ifa.ifa_index)
    {
        log_msg(L_ERR, "[IP] Cannot find device \"%s\"", dev);
        return -1;
    }

    memset(&rth, 0, sizeof(rth));
    if (rtnl_open(&rth) < 0)
    {
        log_msg(L_ERR, "[IP] Open netlink error.");
        return -1;
    }

    /* sending the message to the kernel. */
    ret = rtnl_talk(&rth, &req.n, NULL);
    if (ret < 0)
    {
        if (errno == NL_ERR_FILE_EXIST)
        {
            ret = 0;
        }
        else
        {
            log_msg(L_ERR, "[IP] Failed talk to rtnetlink: %s\n", safe_strerror(errno));
        }
    }
    rtnl_close(&rth);

    return ret;
}

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
int ip_address_del(const char *dev, const char *local, uint8_t local_prefixlen, const char *peer, uint8_t peer_prefixlen)
{
    struct rtnl_handle rth;
    uint32_t addr;
    int ret;

    if (!dev)
    {
        log_msg(L_ERR, "[IP] Network interface is null.");
        return -1;
    }
    if (check_ifname(dev))
    {
        log_msg(L_ERR, "[IP] \"%s\" is not a valid interface name", dev);
        return -1;
    }

    struct {
        struct nlmsghdr n;
        struct ifaddrmsg ifa;
        char buf[256];
    } req = {
        .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg)),
        .n.nlmsg_flags = NLM_F_REQUEST,
        .n.nlmsg_type = RTM_DELADDR,
        .ifa.ifa_family = AF_INET,
    };

    addr = inet_addr(local);
    addattr_l(&req.n, sizeof(req), IFA_LOCAL, &addr, 4);

    if (peer)
    {
        addr = inet_addr(peer);
        addattr_l(&req.n, sizeof(req), IFA_ADDRESS, &addr, 4);
        req.ifa.ifa_prefixlen = peer_prefixlen;
    }

    if (req.ifa.ifa_prefixlen == 0)
    {
        req.ifa.ifa_prefixlen = local_prefixlen;
    }

    req.ifa.ifa_index = ll_name_to_index(dev);
    if (!req.ifa.ifa_index)
    {
        log_msg(L_ERR, "[IP] Cannot find device \"%s\"", dev);
        return -1;
    }

    memset(&rth, 0, sizeof(rth));
    if (rtnl_open(&rth) < 0)
    {
        log_msg(L_ERR, "[IP] Open netlink error.");
        return -1;
    }

    /* sending the message to the kernel. */
    ret = rtnl_talk(&rth, &req.n, NULL);
    if (ret < 0)
    {
        if (errno == NL_ERR_FILE_EXIST)
        {
            ret = 0;
        }
        else
        {
            log_msg(L_ERR, "[IP] Failed talk to rtnetlink: %s\n", safe_strerror(errno));
        }
    }
    rtnl_close(&rth);

    return ret;
}

