#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/time.h>
#include <pthread.h>

#include "log.h"

#define LOG_TO_STDOUT      0  // 标准输出
#define LOG_TO_STDERR      1  // 标准错误
#define LOG_TO_LOGFILE     2  // 输出到文件
#define LOG_TO_DIRMAX      3

#define LOG_OPT_TIME       1
#define LOG_OPT_POS        2
#define LOG_OPT_BAR        4

#define LOG_FILE_SIZE_MAX  (10*1024*1024)  // 10M Bytes
#define LOG_FILE_NAME_LEN  256  // include file path
#define LOG_FILE_MODE_LEN  16

struct log_config 
{
    unsigned short log_flag;
    unsigned short log_opt;
};
							
static char *log_type_str[] = {
    "FATAL",
    "ERROR",
    "WARN", 
    "INFO", 
    "DEBUG",
};

static char log_file_name[LOG_FILE_NAME_LEN];
static char log_file_mode[LOG_FILE_MODE_LEN];
static FILE *log_output_fps[LOG_TO_DIRMAX] = {NULL,NULL,NULL };
static int g_log_level = 0;
static pthread_mutex_t logger_lock;

static struct log_config log_conf[LOG_LEVEL_MAX][LOG_TO_DIRMAX] = 
{
    /* FATAL*/
    {
        { 0, 0 },                                         // stdout
        { 1, LOG_OPT_TIME | LOG_OPT_POS | LOG_OPT_BAR },  // stderr
        { 1, LOG_OPT_TIME | LOG_OPT_POS | LOG_OPT_BAR },  // file
    }, 
    /* ERR*/
    {
        { 0, 0 },
        { 1, LOG_OPT_TIME | LOG_OPT_POS | LOG_OPT_BAR },
        { 1, LOG_OPT_TIME | LOG_OPT_POS | LOG_OPT_BAR },
    },
    /* WARN */
    {
        { 0, 0 },
        { 1, LOG_OPT_TIME | LOG_OPT_BAR },
        { 1, LOG_OPT_TIME | LOG_OPT_BAR },
    },
    /*INFO*/
    { 
        { 1, LOG_OPT_TIME },
        { 0, 0 },
        { 1, LOG_OPT_TIME },
    },
    /*DEBUG*/
    {
        { 1, LOG_OPT_TIME | LOG_OPT_BAR },
        { 0, 0 },
        { 0, 0 },
    },
};

int init_log(char *logfile_dir, char *logfile_name, char *mode, int level)
{
    FILE *logfile;

    if (NULL == logfile_dir || NULL == logfile_name || NULL == mode || level > LOG_LEVEL_MAX)
    {
        printf("%s: parameter(s) error.", __func__);
        return -1;
    }

    /* 判断目录是否存在 */
	if(0 != access(logfile_dir, F_OK))
	{
        /* 不存在时创建目录 */
        char str[64] = {0};
        snprintf(str, 64, "mkdir -p %s", logfile_dir);
        if(0 != system(str))
        {
            perror("create log dir failed:");
            printf("%s: fail to create dir %s.\n", __func__, logfile_dir);
            return -1;
        }
    }

    snprintf(log_file_name, LOG_FILE_NAME_LEN, "%s/%s", logfile_dir, logfile_name);
    snprintf(log_file_mode, LOG_FILE_MODE_LEN, "%s", mode);
    /* open the log file*/
    logfile = fopen(log_file_name, mode);
    if (!logfile)
    {
        perror("open log file failed");
        return -1;
    }
    log_output_fps[LOG_TO_STDOUT]  = stdout;
    log_output_fps[LOG_TO_STDERR]  = stderr;
    log_output_fps[LOG_TO_LOGFILE] = logfile;
    g_log_level = level;

    //fprintf(logfile, "\n********************************************************************************\n\n");
    fflush(logfile);
	pthread_mutex_init(&logger_lock, NULL);
    return 0;
}

static void log_with_option(int type, int fpno, char *time, const char *pos, const char *msg) 
{
    /* To avoid interleaving output from multiple threads. */
    //flockfile(log_output_fps[fpno]);
    pthread_mutex_lock(&logger_lock);

    if (log_conf[type][fpno].log_opt & LOG_OPT_TIME) 
        fprintf(log_output_fps[fpno], "%s  ", time); 

    if (log_conf[type][fpno].log_opt & LOG_OPT_BAR) 
        fprintf(log_output_fps[fpno], "[%s] ", log_type_str[type]); 

    fprintf(log_output_fps[fpno], "%s ", msg); 

    if (log_conf[type][fpno].log_opt & LOG_OPT_POS) 
        fprintf(log_output_fps[fpno], "(%s)", pos); 

    fprintf(log_output_fps[fpno], "\n"); 

    fflush(log_output_fps[fpno]);

    //funlockfile(log_output_fps[fpno]);
    pthread_mutex_unlock(&logger_lock);

    return;
}

static int log_rotate(void)
{
	FILE *logfile = log_output_fps[LOG_TO_LOGFILE];

    if (NULL == logfile)
    {
        logfile = fopen(log_file_name, log_file_mode);
        if (NULL == logfile)
        {
            perror("open log file failed");
            return -1;
        }
        log_output_fps[LOG_TO_LOGFILE] = logfile;
    }

    pthread_mutex_lock(&logger_lock);
    /* do we need to rotate the log file? */
    if (ftell(logfile) > LOG_FILE_SIZE_MAX)
    {
        char new_name[LOG_FILE_NAME_LEN+5];

        /* rotate log file */
        fclose(logfile);
        log_output_fps[LOG_TO_LOGFILE] = NULL;

        snprintf(new_name, sizeof(new_name), "%s.old", log_file_name);
        rename(log_file_name, new_name);

        logfile = fopen(log_file_name, log_file_mode);
        if (!logfile)
        {
            perror("open log file failed");
            pthread_mutex_unlock(&logger_lock);
            return -1;
        }
        log_output_fps[LOG_TO_LOGFILE] = logfile;
    }
    pthread_mutex_unlock(&logger_lock);
    return 0;
}

static void log_to_file(int type, char *time, const char *pos, const char *msg) 
{
    if (log_conf[type][LOG_TO_STDOUT].log_flag)  
        log_with_option(type, LOG_TO_STDOUT, time, pos, msg); 

    if (log_conf[type][LOG_TO_STDERR].log_flag) 
        log_with_option(type, LOG_TO_STDERR, time, pos, msg); 

    if (log_conf[type][LOG_TO_LOGFILE].log_flag)
    {
        /* do we need to rotate the log file? */
        if (0 != log_rotate())
        {
            return;
        }
        log_with_option(type, LOG_TO_LOGFILE, time, pos, msg); 
    }
}

static int get_str_time(char *out_str, int str_len)
{
    struct timeval t_val = {0};
    struct tm t_tm = {0};

    if(NULL == out_str || str_len <= 0)
        return -1;
    gettimeofday(&t_val, 0);
    localtime_r(&t_val.tv_sec, &t_tm);
    strftime(out_str, str_len, "%Y-%m-%d %H:%M:%S ", &t_tm);
    return 0;
}

void _log_msg(int type, const char *file, int line, const char *format, ...) 
{
    /* get time string */
    char time_str[32] = {0};

    if (type > g_log_level)
    {
        return;
    }
    if (0 != get_str_time(time_str, 32))
    {
        printf("get_str_time error.");
        exit(0);
    }

    /* get position string */
    char pos_str[32]  = {0};
    char line_str[16] = {0};
    const int pos_max_size = 30;

    snprintf(line_str, 16, "%i", line);
    int diff = strlen(file) + strlen(line_str) + 1 - pos_max_size;
    if (diff > 0) 
        snprintf(pos_str, 32, "%s:%i", file + diff, line);
    else 
        snprintf(pos_str, 32, "%s:%i", file, line);

    /* put va_list into msg buffer */
    char log_msg[4096] = {0};
    va_list args;
    va_start(args, format);
    vsnprintf(log_msg, sizeof(log_msg), format, args);
    va_end(args);

    log_to_file(type, time_str, pos_str, log_msg);

    if (type == L_FATAL)
    {
        exit(errno);
    }
}

/* re-entrant version */

void log_with_option_r(int type, int fpno, char *time, const char *pos, const char *msg) 
{
    if (log_conf[type][fpno].log_opt & LOG_OPT_TIME) 
        fprintf(log_output_fps[fpno], "%s  ", time); 

    if (log_conf[type][fpno].log_opt & LOG_OPT_BAR) 
        fprintf(log_output_fps[fpno], "[%s] ", log_type_str[type]); 

    fprintf(log_output_fps[fpno], "%s ", msg); 

    if (log_conf[type][fpno].log_opt & LOG_OPT_POS) 
        fprintf(log_output_fps[fpno], "(%s)", pos); 

    fprintf(log_output_fps[fpno], "\n"); 

    return;
}

