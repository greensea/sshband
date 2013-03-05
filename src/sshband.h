#ifndef __SSHBAND_H__
#define __SSHBAND_H__	1

#include <sys/types.h>
#include <sys/time.h>
#include <stdint.h>
#include <syslog.h>
#include <netinet/in.h>

/**
 * 清理线程的间隔，单位秒
 * 如果客户端非正常断线，服务器是无法探知的，所以需要设定一个时间来定期检查非正常断线的客户端
 */
#define SESSION_CLEANUP_TIME 120


/**
 * 默认的定时更新用户流量使用信息的时间间隔，单位：秒
 */
#define UPDATE_USAGE_PERIOD_DEFAULT 120

/**
 * sshband 配置文件路径
 */
#define SSHBAND_CONFIG_PATH	"/etc/sshband.conf"

/**
 * 默认 PID 文件路径
 */
#define SSHBAND_PID_PATH	"/var/run/sshband.pid"

/**
 * SSHBAND 日志级别
 */
#define SSHBAND_LOG_ERROR	2
#define SSHBAND_LOG_WARN	3
#define SSHBAND_LOG_INFO	4
#define SSHBAND_LOG_DEBUG	6
#define SSHBAND_LOG_MESSDEBUG	7	/** Mess debug */

#define SSHBAND_LOGMD(LOG, ...)	if (config_log_level >= SSHBAND_LOG_MESSDEBUG) { syslog(LOG_DAEMON | LOG_INFO, LOG, ##__VA_ARGS__); }
#define SSHBAND_LOGD(LOG, ...)	if (config_log_level >= SSHBAND_LOG_DEBUG) { syslog(LOG_DAEMON | LOG_INFO, LOG, ##__VA_ARGS__); }
#define SSHBAND_LOGI(LOG, ...)	if (config_log_level >= SSHBAND_LOG_INFO) { syslog(LOG_DAEMON | LOG_INFO, LOG, ##__VA_ARGS__); }
#define SSHBAND_LOGW(LOG, ...)	if (config_log_level >= SSHBAND_LOG_WARN) { syslog(LOG_DAEMON | LOG_INFO, LOG, ##__VA_ARGS__); }
#define SSHBAND_LOGE(LOG, ...)	if (config_log_level >= SSHBAND_LOG_ERROR) { syslog(LOG_DAEMON | LOG_INFO, LOG, ##__VA_ARGS__); }
#define SSHBAND_LOG(LOG, ...)	syslog(LOG_DAEMON | LOG_INFO, LOG, ##__VA_ARGS__)

extern int8_t config_log_level;

typedef struct hdl_pak_t {
	u_short sport;
	u_short dport;
	u_short len;
	u_char flags;
	struct in_addr ip_src, ip_dst;
} hdl_pak_t;

typedef struct ssh_session_t {
	uid_t uid;
	
	u_long client_data_time;	// 最后一次收到客户端数据包的时间
	time_t update_usage_time;	// 上一次向数据库更新用户流量数据的时间
	u_long stime;	// 会话启动时间
	
	unsigned long long outband;	// 服务器端上行流量
	unsigned long long inband;	// 服务器下行流量
	char client_addr[17];	// 客户端地址
	char server_addr[17]; // 用户连接服务器使用的服务器端 IP 地址
	char sessid[33];	// 会话唯一标识
	
	struct in_addr ip;
	struct ssh_session_t* next;
} ssh_session_t;


typedef struct acctsql_t {
	struct {
		char login[1024];
		char update[1024];
		char logout[1024];
	} fmt;
} acctsql_t;


void load_config();	
void ssh_session_cleanup();
void ssh_session_acct_update(ssh_session_t* sess);

int write_pid();

int delete_pid();

#endif
