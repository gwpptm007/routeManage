#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <execinfo.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>


#include "zrouter.h"
#include "log.h"
#include "router.h"
#include "util_net.h"
#include "wq_route.h"

#define ZROUTER_ROUTER_ITEM_NUM  (200000)

#define IPv4   (4)
#define IPv6   (6)
//#define INET6_ADDRSTRLEN  64

#define ZROUTER_LOCK_FILE  "/var/run/zrouter.pid"
#define ZROUTER_LOCK_MODE  (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

zrouter_context_t g_zrouter_ctx;
static route_list_t g_static_route_list;

/*======================================================================
 * 函数名: sdpd_version_str
 * 功能: 返回版本号
 * 入参:
 * 出参: 
 * 返回值: 
 * 作者:
 * 时间:
 * 说明: 
 * ======================================================================*/
const char* zrouter_version_str(void)
{
#ifdef ZROUTER_DEBUG
		return "ZROUTER "ZROUTER_VERSION" Debug";
#else 
		return "ZROUTER "ZROUTER_VERSION" Release";
#endif

}

int zrouter_set_file_owner(char* fileName, char* username)  
{  

    struct passwd * pw;
    pw = getpwnam(username);
    if (!pw) 
    {
        printf("%s is not exist,please use cmd : useradd usrname to add a user.\n", username);
        return -1;
    }
    
    if (chown(fileName, pw->pw_uid, pw->pw_gid) == -1) {
        printf("chown %s to user %s failed!\n",fileName,username);
        return -1;
    }
    
    return 0;
}

/*
 * Dump the current stack trace using glibc's backtrace().
 * Output memory addresses can be translated by 'addr2line'.
 */
void dump_stack(void)
{
    int i, nptrs;
    void *buffer[100];
    char **strings;

    nptrs = backtrace(buffer, 100);

    strings = backtrace_symbols(buffer, nptrs);
    if (strings == NULL)
    {
        log_msg(L_FATAL, "backtrace_symbols error");
    }

    for (i = 0; i < nptrs; i++)
    {
        log_msg(L_INFO, "  %s", strings[i]);
    }

    free(strings);
}

/*
 * Set the coredump size of current process.
 */
void core_dump_config(void)
{
    int unlimited = 1;
    rlim_t max_dump = 0;

    /* Linux specific core dump configuration; set dumpable flag if needed. */
    int dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    if (dumpable == -1)
    {
        log_msg(L_WARN, "can't get core dump configuration.");
    }
    else if (unlimited || max_dump > 0)
    {
        /* Try to enbale core dump for this process. */
        if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == -1)
        {
            log_msg(L_ERR, "unable to make this process dumpable.");
            return;
        }
        log_msg(L_INFO, "process is dumpable.");
    }

    struct rlimit lim, new_lim;

    if (getrlimit(RLIMIT_CORE, &lim) == -1)
    {
        log_msg(L_WARN, "can't read core dump limit.");
        return;
    }

    if (unlimited)
    {
        if (lim.rlim_max == RLIM_INFINITY && lim.rlim_cur == RLIM_INFINITY)
        {
            /* already unlimited */
            log_msg(L_INFO, "Core dump size is unlimited.");
            return;
        }
        else
        { /* try set to unlimited */
            new_lim.rlim_max = RLIM_INFINITY;
            new_lim.rlim_cur = RLIM_INFINITY;
            if (setrlimit(RLIMIT_CORE, &new_lim) == 0)
            {
                log_msg(L_INFO, "Core dump size set to unlimited.");
                return;
            }
            if (errno == EPERM)
            { /* try increasing the soft limit to the hard limit instead. */
                if (lim.rlim_cur < lim.rlim_max)
                {
                    log_msg(L_INFO, "lim.rlim_cur < lim.rlim_max");
                    return;
                }
                new_lim.rlim_cur = lim.rlim_max;
                if (setrlimit(RLIMIT_CORE, &new_lim) == 0)
                {
                    log_msg(L_INFO, "Could not set core dump size to unlimited;"
                            "set to the hard limit instead.");
                    return;
                }
            }
            log_msg(L_ERR, "could not set core dump size to unlimited or hard limit.");
            return;
        }
    }

    /* we want a non-infinite soft limit */
    new_lim.rlim_cur = max_dump;

    /* check whether the hard limit needs to be adjusted */
    if (lim.rlim_max == RLIM_INFINITY
            || lim.rlim_max == RLIM_SAVED_MAX
            || lim.rlim_max >= max_dump)
    {
        /* keep the current value */
        new_lim.rlim_max = lim.rlim_max;
    }
    else
    { 
        /* not ample, adjust it */
        new_lim.rlim_max = max_dump;
    }

    if (setrlimit(RLIMIT_CORE, &new_lim) == 0)
    {
        log_msg(L_INFO, "Core dump attempted: %llu.", (uint64_t) new_lim.rlim_cur);
        struct rlimit actual_lim;
        if (getrlimit(RLIMIT_CORE, &actual_lim) != 0)
        {
            log_msg(L_ERR, "getrlimit error!");
            return;
        }
        if (actual_lim.rlim_cur == RLIM_INFINITY)
        {
            log_msg(L_INFO, "Core dump size set to unlimited.");
        }
        else if (actual_lim.rlim_cur == RLIM_SAVED_CUR)
        {
            log_msg(L_INFO, "Core dump size set to soft limit.");
        }
        else
        {
            log_msg(L_INFO, "Core dump size set to %llu.", (uint64_t) new_lim.rlim_cur);
        }
        return;
    }

    if (errno == EINVAL || errno == EPERM)
    {
        /* try increasing the soft limit to the hard limit instead. */
        if ((lim.rlim_cur < max_dump && lim.rlim_cur < lim.rlim_max)
                || (lim.rlim_cur == RLIM_SAVED_CUR))
        {
            new_lim.rlim_max = lim.rlim_max;
            new_lim.rlim_cur = lim.rlim_max;
            if (setrlimit(RLIMIT_CORE, &new_lim) == 0) 
            {
                log_msg(L_INFO, "Core dump size set to the hard limit.");
                return; 
            }
        }
    }

    return;
}

/*
 * Init debug environment.
 */
void init_debug(void)
{
    //atomic_set(&dump_cnt, 1);
    core_dump_config();
}

/*====================================================
函数名: signal_handler
功能:  消息处理函数
入参: int sig: 消息号
出参: 
返回值: 无
作者:  
时间:
说明:
======================================================*/
static void signal_handler(int sig)
{
    switch (sig) 
	{
        case SIGQUIT:
            log_msg(L_INFO, "QUIT signal ended program.");
            break;
        case SIGKILL:
            log_msg(L_INFO, "KILL signal ended program.");
            break;
        case SIGTERM:
            log_msg(L_INFO, "TERM signal ended program.");
            break;
        case SIGINT:
            log_msg(L_INFO, "INT signal ended program.");
            break;
        case SIGHUP:
            log_msg(L_WARN, "Program hanged up.");
            break;
        case SIGSEGV:
            log_msg(L_ERR, "Segmentation fault!");
            dump_stack();
            abort();
			break;
        case SIGPIPE:
            log_msg(L_INFO, "Receive SIGPIPE.");
            return;
        case SIGCHLD:   // 避免僵尸进程
            //log_msg(L_INFO, "Receive SIGCHLD.");
            return;
        case SIGURG:
            log_msg(L_INFO, "Receive SIGURG.");
            break;
        case SIGUSR2:
            log_msg(L_INFO, "Receive SIGUSR2.");
            return;
        default:
            log_msg(L_ERR, "Unknown signal(%d) ended program!", sig);
    }

    g_zrouter_ctx.quit = true;
	//exit(-1);
}

/*===========================================================================
函数名:  init_signals
功能:  初始化信号
入参:  
出参:
返回值: 无
作者:   
时间:  
说明: 
=============================================================================*/
static void init_signals()
{
  	struct sigaction sigact;
    memset(&sigact, 0, sizeof(struct sigaction));
    sigact.sa_handler = signal_handler;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = 0;
    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGQUIT, &sigact, NULL);
    sigaction(SIGKILL, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);
    sigaction(SIGHUP, &sigact, NULL);
    sigaction(SIGSEGV, &sigact, NULL);
    sigaction(SIGPIPE, &sigact, NULL);
    sigaction(SIGCHLD, &sigact, NULL);  // 避免僵尸进程
    sigaction(SIGURG, &sigact, NULL);
    sigaction(SIGUSR2, &sigact, NULL);
	return;
}


#define no_argument        0
#define required_argument  1
#define optional_argument  2

static const struct option long_options[] = {
		{"daemon mode",no_argument,NULL,'d'},
		{"add mode",no_argument,NULL,'A'},
		{"remove mode",no_argument,NULL,'R'}
	
};

/*====================================================
函数名: parse_cmds
功能: 解析命令行参数
入参: 
出参: 
返回值: I_R_OK: 成功
		I_R_ERROR: 失败
作者:  
时间:
说明: 这个函数中未判断参数, 如果设置了-d 并建立守护进程
======================================================*/
static int parse_cmds(INT32 argc, INT8 **argv)
{
    /* 暂时只支持以下几个参数的解析 */
    char optstr[128] = "ADn:d:g:i:m:t:h";
    int opt;


	opt = getopt(argc, argv, optstr);
	while( opt != -1 ) 
	{
		switch( opt )
		{
			case 'A':	
				g_zrouter_ctx.add = true;		/* 添加 */
				break;	
			case 'D':	
				g_zrouter_ctx.del = true;		/* 添加 */
				break;				 
			case 'n':				
				g_zrouter_ctx.num = atoi(optarg);
				break;
			case 'd':
				if ((strlen(optarg)) > 0 /*&& (is_valid_ipv4(optarg) == 0)*/)
				{
                    if( (is_valid_ipv4(optarg) == 0) &&  (!is_valid_ipv6(optarg)) )
                    {
					    printf("the -d destip is not a valid IPv4 or IPv6 address\n");
					    exit(0);
                    }
				}
				g_zrouter_ctx.destip = strdup(optarg);
				break;
			case 'g':
				if ((strlen(optarg)) > 0 )
				{
                    if( (is_valid_ipv4(optarg) == 0) && (!is_valid_ipv6(optarg)) )
                    {
					    printf("the -g gatewayip is not a valid IPv4 or IPv6 address\n");
					    exit(0);
                    }
				}
				g_zrouter_ctx.gatewayip = strdup(optarg);
				break;				
			case 'i':
				
				g_zrouter_ctx.ifname = strdup(optarg);
				break;
			case 'm':
				if ( (strlen(optarg)) > 0 )
				{
                    // if( (is_valid_ipv4(optarg) == 0) &&  (!is_valid_ipv6(optarg)) )
                    // {
					//     printf("the -m netmask is not a valid IPv4 or IPv6 address\n");
					//     exit(0);
                    // }

				}
				g_zrouter_ctx.netmask = strdup(optarg);
				break;
			case 't':
				//g_zrouter_ctx.table = strdup(optarg);
				break;

			case 'h':	  
			default:
				//非法参数处理，也可以使用case来处理，？表示无效的选项，：表示选项缺少参数
				//printf("%s(build time: %s)\n", zrouter_version_str(), ZROUTER_BUILD_TIME);	/* 打印版本号 */
				printf("\t-A : run in ADD mode\n");
				printf("\t-R : run in RM mode\n");
				printf("\t-h : print version and this help\n"
                       "-----------------------------------------------IPv4---------------------------------------\n"
					   "\t./zrouter -A -n 100 -d 172.16.50.165 -g 172.16.30.168 -m 255.255.255.255 -i eth0\n"
				       "\t./zrouter -D -n 100 -d 172.16.50.165 -g 172.16.30.168 -m 255.255.255.255 -i eth0\n"
                       "-----------------------------------------------IPv6---------------------------------------\n"
					   "\t./zrouter -A -n 1 -d 2001:db8::777 -g fe80::7 -m 64 -i eth1\n"
					   "\t./zrouter -D -n 1 -d 2001:db8::777 -g fe80::7 -m 64 -i eth1\n"
                       );
				exit(0);
				break;
		}
		opt = getopt(argc, argv, optstr);
	}

    return I_R_OK;
}



static void zrouter_cleanup(void)
{
    log_msg(L_INFO, "[ZROUTER] cleanup at exit!");

}

/**
 * 判断IP地址是IPv4还是IPv6
 * 返回值:
 *  4 - IPv4
 *  6 - IPv6
 *  0 - neither ... nor ...
 */
int ip_version(const char *ip) {
    char buf[sizeof(struct in6_addr)];

    if (inet_pton(AF_INET, ip, buf)) {
        return IPv4; 
    } else if (inet_pton(AF_INET6, ip, buf)) {
        return IPv6; 
    } else {
        return 0; 
    }
}

int route_init(UINT32 num, char* destip,char* gateway, char* netmask, char* ifname)
{
	if(!destip || !ifname ||!gateway || !netmask)
    {
        log_msg(L_ERR, "[ZROUTER] One or more required parameters are NULL. PLEASE CHECK");
		return -1;
    }

    int af = ip_version(destip);
    if(af == 0)
    {
        log_msg(L_ERR, "[ZROUTER] %s is not a valid IP address!", destip);
        return -1;          
    }

    TAILQ_INIT(&g_static_route_list);

	// printf("----------------start------------------\n");
    // printf("route_init_num=%d\n", num);
    // printf("route_init_destip=%s\n", destip);
    // printf("route_init_gateway=%s\n", gateway);
    // printf("route_init_netmask=%s\n", netmask);
    // printf("route_init_ifname=%s\n", ifname);
    // printf("---------------------------------------\n");
    int i=0;
    for( i=0; i < num; i++)
    {
	    route_entry_t *re = (route_entry_t*)malloc(sizeof(route_entry_t));
        if (!re) {
            log_msg(L_ERR,"Failed to allocate memory for route_entry");
            continue;
        }
	    memset(re, 0, sizeof(route_entry_t));

        if (IPv4 == af)
        {
            struct in_addr addr;
            inet_pton(AF_INET, destip, &addr);
            addr.s_addr = htonl(ntohl(addr.s_addr) + i); // Increment IP
            inet_ntop(AF_INET, &addr, re->dst, sizeof(re->dst)/*MAX_IP_STR_LEN*/);

        } else if (IPv6 == af) {

            strcpy(re->dst, destip);
        }

        strcpy(re->ifname, ifname);
        strcpy(re->gateway, gateway);
        strcpy(re->netmask, netmask);
        // 对于IPv4: 转换子网掩码"255.255.255.0"到前缀长度24
        // 对于IPv6: 假设netmask直接是前缀长度，例如"64"
        re->dst_len = (af == IPv4) ? maskstr2prefix(re->netmask) : atoi(re->netmask);
        re->enable = 1;

        // printf("re->dst=%s\n", re->dst);
        // printf("re->netmask=%s\n", re->netmask);
        // printf("re->gateway=%s\n", re->gateway);
        // printf("re->ifname=%s\n", re->ifname);
        // printf("re->dst_len=%d\n", re->dst_len);
        // printf("re->enable=%d\n", re->enable);
        // printf("----------------end------------------\n");
	    TAILQ_INSERT_TAIL(&g_static_route_list, re, next);
	}

    return I_R_OK;
}

void route_cleanup(void)
{
    /* Delete all the ip routes */
    ip_route_list_destroy(&g_static_route_list);
}


void route_add(int iptype)
{
	struct timeval tpstart,tpend;
    float timeuse;
    gettimeofday(&tpstart,NULL); 

    if ( IPv4 == iptype )
    {
	    ipv4_route_add_all(&g_static_route_list);
    } else if (IPv6 == iptype) 
    {
	    ipv6_route_add_all(&g_static_route_list);
    }

	gettimeofday(&tpend,NULL);
	timeuse=1000000*(tpend.tv_sec-tpstart.tv_sec)+tpend.tv_usec-tpstart.tv_usec;
	timeuse/=1000000;
	
	log_msg(L_INFO, "Add/Del %d route items cost time =%f s", g_zrouter_ctx.num, timeuse);

}


void route_del(int iptype)
{
	struct timeval tpstart,tpend;
    float timeuse;
    gettimeofday(&tpstart,NULL); 

    if( IPv4 == iptype )
    {
	    ipv4_route_del_all(&g_static_route_list);
    } else if (IPv6 == iptype) 
    {
	    ipv6_route_del_all(&g_static_route_list);
    }

	gettimeofday(&tpend,NULL);
	timeuse=1000000*(tpend.tv_sec-tpstart.tv_sec)+tpend.tv_usec-tpstart.tv_usec;
	timeuse/=1000000;
	
	log_msg(L_INFO, "Add/Del %d route items cost time =%f s", g_zrouter_ctx.num, timeuse);

}

int main(int argc, char **argv)
{
    memset(&g_zrouter_ctx, 0, sizeof(g_zrouter_ctx));
  
    /* Parsing parameters */
    if(I_R_OK != parse_cmds(argc, argv))
    {
        printf("parsing args failed.\n");
        return I_R_ERROR;
    }

	g_zrouter_ctx.log_level = L_INFO;
	printf("g_sdpd_ctx.log_level =%d.\n",g_zrouter_ctx.log_level);
    /* Initialize log */
    if (init_log(ZROUTER_LOG_DIR, ZROUTER_LOG_NAME, ZROUTER_LOG_MODE, g_zrouter_ctx.log_level) != I_R_OK)
    {
        printf("Initialize log failed!\n");
        return I_R_ERROR;
    }

    /* Initialize signal */
    init_signals();

    /* Initialize debug environment */
    init_debug();

    //log_msg(L_INFO, "%s(build time: %s)", zrouter_version_str(), ZROUTER_BUILD_TIME);

	route_init(g_zrouter_ctx.num, g_zrouter_ctx.destip, g_zrouter_ctx.gatewayip, g_zrouter_ctx.netmask,g_zrouter_ctx.ifname);

    int af = ip_version(g_zrouter_ctx.destip);
	if(g_zrouter_ctx.add) 
	{
		route_add(af);
	}	
	if(g_zrouter_ctx.del)
	{
		route_del(af);
	}
	
	route_cleanup();
	
    zrouter_cleanup();

	log_msg(L_INFO, "I'm off!");
    return I_R_OK;
}


int wq_route_add_ip4(unsigned char uip[4], unsigned char gip[4], unsigned char ifname[IFNAMSIZ], int tabid)
{

    if(!uip || !gip || !ifname)
    {
        log_msg(L_ERR, "[ZROUTER] One or more required parameters are NULL. PLEASE CHECK");
		return -1;
    }

    int tableID = 0;
    if ( !tabid )
    {
        tabid = tableID;
    }

    route_entry_t entry;
    memset(&entry, 0, sizeof(route_entry_t));


    // 使用inet_ntop函数将二进制形式的IPv4地址转换为点分十进制字符串
    inet_ntop(AF_INET, uip, entry.dst, 32);
    inet_ntop(AF_INET, gip, entry.gateway, 32);

    entry.enable = 1;
    //memcpy(entry.dst, uip, 4);
    //memcpy(entry.gateway, gip, 4);
    memcpy(entry.ifname, ifname, IFNAMSIZ);
    strcpy(entry.netmask, "255.255.255.255");
    //strcpy(entry.netmask, "64");
    entry.table = tabid;
    entry.dst_len = 32;

    //printf("route_init_destip=%s\n", entry.dst);
    //printf("route_init_gateway=%s\n", entry.gateway);
    //printf("route_init_netmask=%s\n", entry.netmask);
    //printf("route_init_ifname=%s\n", entry.ifname);

    int result = -1;

    result = ipv4_route_add(&entry);

    if (result != 0) {
        log_msg(L_ERR, "Failed to add route.\n");
        return -1;
    }

    log_msg(L_ERR,"Route add successfully.\n");
    return 0;

}


int wq_route_delete_ip4(unsigned char uip[4], unsigned char gip[4], unsigned char ifname[IFNAMSIZ], int tabid)
{
    if(!uip || !gip || !ifname)
    {
        log_msg(L_ERR, "[ZROUTER] One or more required parameters are NULL. PLEASE CHECK");
		return -1;
    }

    int tableID = 0;
    if ( !tabid )
    {
        tabid = tableID;
    }

    route_entry_t entry;
    memset(&entry, 0, sizeof(route_entry_t));


    // 使用inet_ntop函数将二进制形式的IPv4地址转换为点分十进制字符串
    inet_ntop(AF_INET, uip, entry.dst, 32);
    inet_ntop(AF_INET, gip, entry.gateway, 32);

    entry.enable = 1;
    //memcpy(entry.dst, uip, 4);
    //memcpy(entry.gateway, gip, 4);
    memcpy(entry.ifname, ifname, IFNAMSIZ);
    strcpy(entry.netmask, "255.255.255.255");
    //strcpy(entry.netmask, "64");
    entry.table = tabid;
    entry.dst_len = 32;

    // printf("route_init_destip=%s\n", entry.dst);
    // printf("route_init_gateway=%s\n", entry.gateway);
    // printf("route_init_netmask=%s\n", entry.netmask);
    // printf("route_init_ifname=%s\n", entry.ifname);

    int result = -1;

    result = ipv4_route_del(&entry);

    if (result != 0) {
        printf("Failed to del route.\n");
        return -1;
    }

    printf("Route del successfully.\n");
    return 0;

}


int wq_route_add_ip6(unsigned char uip[16], unsigned char gip[16], unsigned char ifname[IFNAMSIZ], int tabid)
{
    if(!uip || !gip || !ifname) 
    {
        log_msg(L_ERR, "[ZROUTER] One or more required parameters are NULL. PLEASE CHECK");
        return -1;
    }

    int tableID = 0;
    if ( !tabid )
    {
        tabid = tableID;
    }

    route_entry_t entry;
    memset(&entry, 0, sizeof(route_entry_t));

    // 使用inet_ntop函数将二进制形式的IPv6地址转换为字符串
    char ip6Dst[INET6_ADDRSTRLEN], ip6Gw[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, uip, ip6Dst, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, gip, ip6Gw, INET6_ADDRSTRLEN);

    entry.enable = 1;
    strcpy(entry.dst, ip6Dst);
    strcpy(entry.gateway, ip6Gw);
    memcpy(entry.ifname, ifname, IFNAMSIZ);
    strcpy(entry.netmask, "128"); // IPv6通常使用128位掩码
    entry.dst_len = 128;
    entry.table = tabid;

    // printf("route_init_destip=%s\n", entry.dst);
    // printf("route_init_gateway=%s\n", entry.gateway);
    // printf("route_init_netmask=%s\n", entry.netmask);
    // printf("route_init_ifname=%s\n", entry.ifname);
    // printf("route_init_table=%d\n", entry.table);

    int result = ipv6_route_add(&entry); // 假设您已经实现了一个适用于IPv6的添加路由函数

    if (result != 0) {
        printf("Failed to add route.\n");
        return -1;
    }

    printf("Route added successfully.\n");
    return 0;
}

int wq_route_delete_ip6(unsigned char uip[16], unsigned char gip[16], unsigned char ifname[IFNAMSIZ], int tabid)
{
    if(!uip || !gip || !ifname) {
        log_msg(L_ERR, "[ZROUTER] One or more required parameters are NULL. PLEASE CHECK");
        return -1;
    }

    int tableID = 0;
    if ( !tabid )
    {
        tabid = tableID;
    }

    route_entry_t entry;
    memset(&entry, 0, sizeof(route_entry_t));

    // 使用inet_ntop函数将二进制形式的IPv6地址转换为字符串
    char ip6Dst[INET6_ADDRSTRLEN], ip6Gw[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, uip, ip6Dst, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, gip, ip6Gw, INET6_ADDRSTRLEN);

    entry.enable = 1;
    strcpy(entry.dst, ip6Dst);
    strcpy(entry.gateway, ip6Gw);
    memcpy(entry.ifname, ifname, IFNAMSIZ);
    strcpy(entry.netmask, "128"); // IPv6通常使用128位掩码
    entry.dst_len = 128;
    entry.table = tabid;

    //printf("Deleting route...\n");
    //printf("route_delete_destip=%s\n", entry.dst);
    //printf("route_delete_gateway=%s\n", entry.gateway);
    //printf("route_delete_netmask=%s\n", entry.netmask);
    //printf("route_delete_ifname=%s\n", entry.ifname);
    //printf("route_init_table=%d\n", entry.table);

    int result = ipv6_route_del(&entry); // 假设您已经实现了一个适用于IPv6的删除路由函数

    if (result != 0) {
        printf("Failed to delete route.\n");
        return -1;
    }

    printf("Route deleted successfully.\n");
    return 0;
}
