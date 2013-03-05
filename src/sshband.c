#ifdef _FORTIFY_SOURCE
#undef _FORTIFY_SOURCE
#define _FORTIFY_SOURCE 1   /// 禁止 glibc 对 *printf 的 %N$ 进行参数完整性检查
#endif

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <libgen.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "sshband_mysql.h"
#include "sshband.h"
#include "sshband_pcap.h"
#include "userinfo.h"
#include "string.h"

extern uint64_t db_inserted_id;
extern sql_queue_t* sql_queue_head;

static char* config_config_path = NULL;	/// Path to configure file

u_short ssh_port = 22;
uid_t ssh_uid = 120;
static ssh_session_t* sessions[65536] = {NULL};
static long last_cleanup_time = 0;

int8_t config_log_level = SSHBAND_LOG_WARN;

char config_net_device[1024] = {0};
int config_update_usage_period = UPDATE_USAGE_PERIOD_DEFAULT;

char config_pid_path[1024] = {0};

char config_mysql_host[1024] = {0};
char config_mysql_user[1024] = {0};
char config_mysql_pass[1024] = {0};
char config_mysql_db[1024] = {0};
char config_sql_login[1024] = {0};
char config_sql_logout[1024] = {0};
char config_sql_update[1024] = {0};

struct acctsql_t sqlacct;

static char* uultostr(char* ptr, size_t siz, unsigned long long n) {
    snprintf(ptr, siz - 1, "%llu", n);
    
    return ptr;
}

const char* get_random_sess_id() {
	int i;
	static char ret[33];
	
	memset(ret, 0x00, sizeof(ret));
	for (i = 0; i < 4; i++) {
		sprintf(ret, "%08x%08x%08x%08x", rand(), rand(), rand(), rand());
	}

	return ret;
}

void load_sql_queue() {
	FILE* fp;
	sql_queue_t* p = NULL;
	char sql[sizeof(p->sql)] = {0};
	int n = 0;
	
	fp = fopen("/var/sshband.sql", "r");
	if (fp == NULL) {
		SSHBAND_LOGI("No queued SQL(s)\n");
		return;
	}
	
	sql_queue_head = p = malloc(sizeof(sql_queue_t));
	p->next = NULL;
	if (fread(p->sql, sizeof(p->sql), 1, fp)) {
		SSHBAND_LOGD("Loading SQL queue: %s\n", p->sql);
		n++;
	}
	
	while (fread(sql, sizeof(p->sql), 1, fp)) {
		p->next = malloc(sizeof(sql_queue_t));
		p = p->next;
		p->next = NULL;
		strncpy(p->sql, sql, sizeof(p->sql));
		SSHBAND_LOGD("Loading SQL queue: %s\n", p->sql);
		n++;
	}
	
	fclose(fp);
	unlink("/var/sshband.sql");	
	
	SSHBAND_LOGI("Loaded %d queued SQL(s)\n", n);
}

void save_sql_queue() {
	FILE* fp;
	sql_queue_t* p;
	int n = 0;
	
	if (sql_queue_head == NULL) {
		SSHBAND_LOGI("No SQL(s) to be save\n");
		return; 
	}
	
	fp = fopen("/var/sshband.sql", "w");
	if (fp == NULL) {
		SSHBAND_LOGW("Could not open /var/sshband.sql for writing\n");
		return ;
	}
	
	p = sql_queue_head;
	while (p != NULL) {
		fwrite(p->sql, sizeof(p->sql), 1, fp);
		sql_queue_head = p;
		p = p->next;
		free(sql_queue_head);
		
		n++;
	}

	fclose(fp);
	chmod("/var/sshband.sql", 0600);
	
	SSHBAND_LOGI("Saved %d SQL(s)\n", n);
}

/**
 * @param u_short port	客户端端口
 * @param &ssh_session_t** sess	若创建会话成功，会话节点指针将通过这个参数返回
 * @return int	0为成功，其他值为失败
 * 
 * 初始化一个新的会话
 * 首先要定位到相应的哈希表的位置，然后
 * ——如果哈希表位置为空，直接在这个位置上创建会话节点
 * ——如果哈希表位置非空，直接在它后面（链表）插入会话节点
 */
int ssh_session_init(u_short port, ssh_session_t** sess) {
	ssh_session_t* newsess = NULL;
	time_t ts = time(NULL);
	
	newsess = malloc(sizeof(ssh_session_t));
	if (newsess == NULL) {
		SSHBAND_LOGE("malloc() fail: %s\n", strerror(errno));
		return -1;
	}

	memset(newsess, 0x00, sizeof(ssh_session_t));
	newsess->next = NULL;
	newsess->uid = -1;
	newsess->stime = ts;
	newsess->outband = 0;
	newsess->inband = 0;
	newsess->client_data_time = ts;
	newsess->update_usage_time = ts;
	memset(newsess->sessid, 0x00, sizeof(newsess->sessid));
	strncpy(newsess->sessid, get_random_sess_id(), sizeof(newsess->sessid) - 1);
	
	if (sessions[port] == NULL) {
		sessions[port] = newsess;
	}
	else {
		newsess->next = sessions[port]->next;
		sessions[port]->next = newsess;
	}
	*sess = newsess;

	SSHBAND_LOGD("New session created, sessionid is %s\n", newsess->sessid);

	return 0;
}

void ssh_session_acct_new(ssh_session_t* sess, u_short rport) {
	char sql[1024] = {0};
	
	SSHBAND_LOGD("Insert new client %s(%s) info into SQL server\n", sess->client_addr, sess->sessid);

	//snprintf(sql, sizeof(sql) - 1, "INSERT INTO %s (%s, %s, %s, %s, %s, %s) VALUES (%d, FROM_UNIXTIME(%lu), '%s', '%s', '%s', %u)", config_table_acct, config_column_uid, config_column_connecttime, config_column_username, config_column_sessionid, config_column_clientip, config_column_clientport, sess->uid, sess->stime, get_name_by_uid(sess->uid), sess->sessid, sess->client_addr, rport);

	
	/// 参数顺序请参考 filedfmt_tbl
	/**                                               inband, outband, username, timestamp
	 *                                                starttime, clientip, cilentport, serverip
	 *                                                sessionid, clientdatatime, uid
	 */
	if (sqlacct.fmt.login[0] != 0x00) {
		snprintf(sql, sizeof(sql) - 1, sqlacct.fmt.login, "0", "0", get_name_by_uid(sess->uid), time(NULL),
														   sess->stime, sess->client_addr, (int)rport, sess->server_addr,
														   sess->sessid, (time_t)0, (unsigned int)sess->uid);
		db_query(sql);
	}
}

void ssh_session_start(hdl_pak_t pak) {
	u_short rport;
	int *ipval, *ipval2;
	ssh_session_t* sess;
	struct in_addr ip;
	struct in_addr sip;
	
	if (pak.dport == ssh_port) {
		rport = pak.sport;
		ip = pak.ip_src;
		sip = pak.ip_dst;
	}
	else {
		rport = pak.dport;
		ip = pak.ip_dst;
		sip = pak.ip_src;
	}
	
	/**
	 * 查找对应的客户端会话，先通过哈希值查找，找不到就顺着链表查找
	 * 若找不到，就调用 ssh_session_init 创建新的会话
	 * 如果找到的话，直接中断函数（也就是不执行后面的语句去调用 ssh_session_init了）
	 */
	sess = sessions[rport];
	ipval = (int*)&ip;
	while (sess != NULL) {
		ipval2 = (int*) &(sess->ip);
		if (*ipval == *ipval2) {
			return;
		}
		sess = sess->next;
	}
	
	SSHBAND_LOGD("No session found in current session list, created it now\n");

	if (0 == ssh_session_init(rport, &sess)) {
		strncpy(sess->client_addr, inet_ntoa(ip), sizeof(sess->client_addr) - 1);
		strncpy(sess->server_addr, inet_ntoa(sip), sizeof(sess->server_addr) - 1);
		sess->ip = ip;		
	}
}

void ssh_session_acct_end(ssh_session_t* sess) {
    char sql[1024];
    char inbandstr[20] = {0};
    char outbandstr[20] = {0};
	
	if (sess == NULL) {
		SSHBAND_LOGD("%s: Warning: sess == NULL\n", __func__);
		return;
	}
    
    uultostr(inbandstr, sizeof(inbandstr), sess->inband);
    uultostr(outbandstr, sizeof(outbandstr), sess->outband);
	
	SSHBAND_LOGD("Session %s from %s is end, updating info into SQL server\n", sess->sessid, sess->client_addr);
	
	ssh_session_acct_update(sess);
	
	//snprintf(sql, sizeof(sql) - 1, "UPDATE %s SET %s=FROM_UNIXTIME(%lu)  WHERE %s='%s'", config_table_acct, config_column_disconnecttime, sess->client_data_time, config_column_sessionid, sess->sessid);
	
	/// 参数顺序请参考 filedfmt_tbl
	if (sqlacct.fmt.logout[0] != 0x00) {
		snprintf(sql, sizeof(sql) - 1, sqlacct.fmt.logout, inbandstr, outbandstr, get_name_by_uid(sess->uid), time(NULL),
														   sess->stime, sess->client_addr, 0, sess->server_addr,
														   sess->sessid, sess->client_data_time, (unsigned int)sess->uid);

		db_query(sql);
	}
}

/**
 * 更新用户流量数据
 */
void ssh_session_acct_update(ssh_session_t* sess) {
    char sql[1024];
    char inbandstr[20] = {0};
    char outbandstr[20] = {0};
    
    uultostr(inbandstr, sizeof(inbandstr), sess->inband);
    uultostr(outbandstr, sizeof(outbandstr), sess->outband);
	
	//snprintf(sql, sizeof(sql) - 1, "UPDATE %s SET %s=%llu, %s=%llu WHERE %s='%s'", config_table_acct, config_column_inband, sess->inband, config_column_outband, sess->outband, config_column_sessionid, sess->sessid);

	/// 参数顺序请参考 filedfmt_tbl
	if (sqlacct.fmt.update[0] != 0x00) {
		snprintf(sql, sizeof(sql) - 1, sqlacct.fmt.update, inbandstr, outbandstr, get_name_by_uid(sess->uid), time(NULL),
	                                                   sess->stime, sess->client_addr, 0, sess->server_addr,
	                                                   sess->sessid, sess->client_data_time, (unsigned int)sess->uid);	
	
		db_query(sql);
	}
}

/**
 * 删除会话表中的节点
 */
int ssh_session_delete(ssh_session_t *sess,  int rport)
{
	ssh_session_t *prev = NULL;
	ssh_session_t *cur = NULL;    //ssh_session_t *next = NULL;
	int found;
	
    // 删除会话节点
	// 如果会话节点在哈希表中，直接删除即可
	// 如果在链表中，就需要链表中的删除节点操作	 
	if (sess == sessions[rport]) {
		sessions[rport] = sessions[rport]->next;
		free(sess);
	}
	else {
		found = 0;
		
		prev = sessions[rport];
		cur  = prev->next;   //next = NULL;  if  (cur)  next = cur->next;
		
		while (cur) {
			if (cur == sess) {
				found = 1;
				break;
			}
			prev = cur;
			cur  = prev->next;   //next = NULL;  if  (cur)  next = cur->next;
		}

		if (found == 1) {
			prev->next = cur->next;
			free(cur);		
		}
		else {
			SSHBAND_LOGD("error  %s   %d",  __FUNCTION__,  __LINE__);		
		}				
	}
	return 0;
}

void ssh_session_end(hdl_pak_t pak) {
	u_short rport;
	int *ipval, *ipval2;
	ssh_session_t* sess;

	if (pak.dport == ssh_port) {
		rport = pak.sport;
		ipval = (int*)&pak.ip_src;
	}
	else {
		rport = pak.dport;
		ipval = (int*)&pak.ip_dst;
	}
	
	/**
	 * 在哈希链表中查找会话节点
	 */
	sess = sessions[rport];
	while (sess != NULL) {
		ipval2 = (int*)&(sess->ip);
		if (*ipval == *ipval2) {
			break;
		}
		sess = sess->next;
	}
	
	if (sess == NULL) {
		char ipstr[19] = {0};
		
		strncpy(ipstr, inet_ntoa(pak.ip_src), sizeof(ipstr) - 1);
		SSHBAND_LOGD("No session found while closing session from %s\n", ipstr);
		
		return;
	}
	
	ssh_session_acct_end(sess);
	ssh_session_delete(sess, rport);
}

uid_t get_ssh_uid(unsigned long ip, u_short rport) {
	uid_t uid;

	uid = get_uid_by_ipport(ip, rport);
	if (uid != ssh_uid && uid != 0) {
		return uid;
	}
	else {
		SSHBAND_LOGD("No match uid %d with ip %lu and port %d found\n", uid, ip, rport);
		return -1;
	}
}

void ssh_session_gotpack(hdl_pak_t pak) {
	u_short rport;
	int *ipval, *ipval2;
	ssh_session_t *sess;
	struct in_addr ip;
	time_t ts = time(NULL);
	
	
	if (pak.dport == ssh_port) {
		rport = pak.sport;
		ipval = (int*)&pak.ip_src;
		ip = pak.ip_src;
	}
	else {
		rport = pak.dport;
		ipval = (int*)&pak.ip_dst;
		ip = pak.ip_dst;
	}
	
	// 定时清理非正常断开的客户端
	if (ts - last_cleanup_time > SESSION_CLEANUP_TIME) {
		ssh_session_cleanup();
	}

	
	/** 
	 * 在哈希链表中查找对应的会话节点
	 */
	sess = sessions[rport];
	while (sess != NULL) {
		ipval2 = (int*)&(sess->ip);
		if (*ipval == *ipval2) {
			break;
		}
		sess = sess->next;
	}
	if (sess == NULL) {
		char ipstr[19] = {0};
		
		strncpy(ipstr, inet_ntoa(pak.ip_src), sizeof(ipstr) - 1);
		SSHBAND_LOGMD("Receive packet from %s:%d, but not session is found in session list\n", ipstr, rport);
		return;
	}
	
	
	/**
	 * 正式处理
	 */
	if (sess->uid == -1) {
		//printf("uid==-1, try get uid, port=%d, ip=%.8x\n", rport, ip.s_addr);
		sess->uid = get_ssh_uid(ip.s_addr, rport);

		// 获取到UID以后，增加acct记录
		if (sess->uid != -1) {
			ssh_session_acct_new(sess, rport);
		}
	}
	
	/// 累加用户流量
	if (pak.sport == ssh_port) {
		sess->outband += pak.len;
	}
	else {
		sess->inband += pak.len;
		sess->client_data_time = ts;
	}
	
	/// 定时更新用户流量到数据库
	if (sess->uid != -1 && config_update_usage_period > 0 && ts - sess->update_usage_time >= config_update_usage_period) {
		SSHBAND_LOGD("Updating session %s used bandwidth into database, in=%lldbytes out=%lldbytes\n", sess->sessid, sess->inband, sess->outband);
		
		ssh_session_acct_update(sess);
		sess->update_usage_time = ts;
	}
}

void sshband_handler(hdl_pak_t pak) {
	//printf("%d --> %d\t%dB\t", pak.sport, pak.dport, pak.len);

	if (pak.flags & TH_SYN) {
		SSHBAND_LOGD("SYN %d --> %d\t%dB\n", pak.sport, pak.dport, pak.len);
		ssh_session_start(pak);
	}
	
	ssh_session_gotpack(pak);
	
	if (pak.flags & TH_FIN || pak.flags & TH_RST) {
		ssh_session_end(pak);
		SSHBAND_LOGD("FIN | RST %d --> %d\t%dB\n", pak.sport, pak.dport, pak.len);
	}
	
	//printf("\t%d", get_uid_by_port(pak.sport == 22 ? pak.dport : pak.sport));
}

/**
 * 去除字符串首尾的特定字符
 * 
 * @param char* 需要处理的字符串
 * @param char  需要取出的字符，如果这个参数是 ' '，就相当于去除字符串首尾的空格
 * @param char* 指向 str
 */
char* strtrm(char* str, char c) {
    int k = 0;
    int n;
    
    for (n = 0; str[n] != 0x00 && str[n] == c; n++);   /// 计算前导字符数
    memmove(str, str + n, strlen(str + n) + 1);
    
    k = strlen(str) - 1;

    while (k >= 0 && str[k] == c) {
        str[k] = 0x00;
        k--;
    }
    
    return str;
}


char* get_config(const char* name) {
	static char config[1024];
	char* value;
	char line[1024] = {0};
	char c;
	int i;
	FILE* fp;
	
	config[0] = 0;
	fp = fopen(config_config_path, "r");
	if (fp == NULL) {
		SSHBAND_LOGE("Could not open configure file `%s': %s\n", SSHBAND_CONFIG_PATH, strerror(errno));
		return config;
	}
	
	while (!feof(fp)) {
		// 读入一行，并跳过换行符
		i = 0;
		while (!feof(fp) && (c = fgetc(fp)) != '\n' && c != '\r') {
			line[i] = c;
			i++;
			if (i == sizeof(line) - 1) break;
		}
		line[i] = 0x00;
        
        strtrm(line, ' ');
        strtrm(line, '\t');

		// 判断是否是注释
		if (line[0] == '#') continue;

		value = strchr(line, '=');
		if (value != NULL) {
			line[value - line] = 0;
            strtrm(line, ' ');
            strtrm(line, '\t');
		}
	
		if (0 == strcmp(line, name)) {
			strncpy(config, value + 1, sizeof(config) - 1);
            config[sizeof(config) - 1] = 0x00;
            
			strtrm(config, ' ');
			strtrm(config, '\t');
            
			break;
		}
	}
    
	fclose(fp);
	
	return config;
}

void load_config(const char* path) {
	/**
	 * 设置配置文件路径
	 */
	if (path == NULL) {
		config_config_path = SSHBAND_CONFIG_PATH;
	}
	else {
		config_config_path = (char*)path;
	}
	SSHBAND_LOG("Using `%s' as configure file\n", config_config_path);
	
	/**
	 * 读取配置
	 */
	config_log_level = atoi(get_config("log_level"));

	ssh_port = atoi(get_config("ssh_port"));
	if (ssh_port == 0) {
		SSHBAND_LOGW("Could not find ssh_port in configure file, use default port 22\n");
		ssh_port = 22;
	}
	
	ssh_uid = atoi(get_config("ssh_uid"));

	config_update_usage_period = atoi(get_config("update_period"));
	if (config_update_usage_period < 0) {
		SSHBAND_LOGW("Could not find update_period in configure file, use default value %d\n", UPDATE_USAGE_PERIOD_DEFAULT);
		config_update_usage_period = UPDATE_USAGE_PERIOD_DEFAULT;
	}

	strncpy(config_pid_path, get_config("pid"), sizeof(config_pid_path) - 1);
	if (config_pid_path[0] == 0x00) {
		SSHBAND_LOGW("pid not set in configure file, use `%s' as default\n", SSHBAND_PID_PATH);
		strncpy(config_pid_path, SSHBAND_PID_PATH, sizeof(config_pid_path));
	}

	strncpy(config_mysql_pass, get_config("mysql_password"), sizeof(config_mysql_pass) - 1);
	strncpy(config_mysql_user, get_config("mysql_username"), sizeof(config_mysql_user) - 1);
	strncpy(config_mysql_db, get_config("mysql_database"), sizeof(config_mysql_db) - 1);
	strncpy(config_mysql_host, get_config("mysql_host"), sizeof(config_mysql_host) - 1);

	strncpy(config_net_device, get_config("network_device"), sizeof(config_net_device) - 1);	

	strncpy(config_sql_login, get_config("sql_login"), sizeof(config_sql_login) - 1);
	strncpy(config_sql_update, get_config("sql_update"), sizeof(config_sql_update) - 1);
	strncpy(config_sql_logout, get_config("sql_logout"), sizeof(config_sql_logout) - 1);

    memset(&sqlacct.fmt, 0x00, sizeof(sqlacct.fmt));
    sql_config2fmt(config_sql_login, sqlacct.fmt.login, sizeof(sqlacct.fmt.login));
    sql_config2fmt(config_sql_update, sqlacct.fmt.update, sizeof(sqlacct.fmt.update));
    sql_config2fmt(config_sql_logout, sqlacct.fmt.logout, sizeof(sqlacct.fmt.logout));
}

static void sshband_exit(int signo) {
	int i;
	ssh_session_t *sess, *next;
	
	for (i = 0; i < sizeof(sessions) / sizeof(ssh_session_t*); i++) {
		sess = sessions[i];
		while (sess != NULL) {
			next = sess->next;
			ssh_session_acct_end(sess);
			free(sessions[i]);
			sess = next;
		}
	}
	
	save_sql_queue();
	
	db_destroy();
	
	delete_pid();
	
	SSHBAND_LOGI("sshband stopped\n");
	
	closelog();	/// 关闭 Syslog
	
	exit(0);
}

int reg_signal() {
	struct sigaction sig_term;
	struct sigaction sig_int;
	
    memset(&sig_term, 0x00, sizeof(sig_term));
    memset(&sig_int, 0x00, sizeof(sig_int));
    
	sigemptyset(&sig_term.sa_mask);
	sigemptyset(&sig_int.sa_mask);
	
	sig_term.sa_handler = sshband_exit;
	sig_int.sa_handler = sshband_exit;	
	
	sigaction(SIGTERM, &sig_term, NULL);
	sigaction(SIGINT, &sig_int, NULL);
	
	return 0;
}

// 清理了：返回1      否则：返回0
static int cleanup_sess (ssh_session_t *sess, int port)
{
	unsigned long ino;
	pid_t pid;
	int ret = 0;

	if (sess == NULL)  return 0;

	if (sess->uid != ssh_uid && sess->uid != 0 && sess->uid != -1) {
		ino = get_inode_by_ipport(sess->ip.s_addr, port);
		pid = get_pid_by_inode(ino);
		if (pid <= 0) {
			ret = 1;
			SSHBAND_LOGD("cleanup session,  session id : %s ", sess->sessid);
			ssh_session_acct_end(sess);
			//free(sess);    // caller do free
		}
	}
	return ret;
}


// 每次调用最多只清理一个，哪怕有很多。  清理了：返回1    否则没找到：返回0
int ssh_session_cleanup_port (int port)
{
	ssh_session_t *sess = NULL;
	ssh_session_t *prev = NULL;

	sess = sessions[port];
	if (sess == NULL) return 0;

	// 在哈希表节点上
	if (cleanup_sess(sess, port) == 1) {
		sessions[port] = sess->next;
		free(sess);
		return 1;   // just return
	}

	// 在链表节点上
	prev = sess;
	sess = sess->next;
	while(sess != NULL) {
		if (cleanup_sess(sess, port) == 1) {
			prev->next = sess->next;
			free(sess);
			return 1;   // just return
		}
		prev = sess;
		sess = sess->next;
	}
	return 0;
}


/**
 * 清理非正常中断的SSH用户进程session_
 * 若会话列表中已有用户编号，而根据此会话端口在本机上查不到对应进程，则认为会话非正常中断
 */
void ssh_session_cleanup() 
{
	int i;
	//unsigned long ino;
	//pid_t pid;
	//ssh_session_t *sess = NULL;
	//ssh_session_t *prev = NULL;
	
	SSHBAND_LOGD("%s: clean in", __func__);

	for (i = 0; i < sizeof(sessions) / sizeof(ssh_session_t*); i++) {
		while (1) {
			if (ssh_session_cleanup_port(i) == 0)
				break;
		}
	}
	last_cleanup_time = time(NULL);
	SSHBAND_LOGD("%s: clean out", __func__);
}


/**
 * 写入 PID
 * 
 * @return int	成功返回0; 否则返回其他值
 */
int write_pid() {
	char proc_path[1024] = {0};
	int pid = 0;
	int n;
	FILE* fp;
	
	fp = fopen(config_pid_path, "r");
	
	if (fp != NULL) {
		n = fscanf(fp, "%d", &pid);
		fclose(fp);
		
		snprintf(proc_path, sizeof(proc_path), "/proc/%d", pid);
		
		if (access(proc_path, F_OK) == 0) {
			/// FIXME: 应该进一步检查当前存在的进程的二进制文件是不是 sshband 自身
			SSHBAND_LOGE("Seems another sshband instance is running, exiting...\n");
			return -1;
		}
	}
	
	fp = fopen(config_pid_path, "w");
	if (fp == NULL) {
		SSHBAND_LOGW("Can't open `%s' for writting\n", config_pid_path)
		return -2;
	}
	
	fprintf(fp, "%d", getpid());
	fclose(fp);
	
	return 0;
}

/**
 * 删除 PID 文件
 * 
 * @return int	成功返回0,否则返回其他值
 */
int delete_pid() {
	FILE* fp;
	int pid = 0;
	int ret, n;
	
	fp = fopen(config_pid_path, "r");
	
	if (fp != NULL) {
		n = fscanf(fp, "%d", &pid);
		fclose(fp);
	}
	
	if (pid == getpid()) {
		ret = unlink(config_pid_path);
		if (ret != 0) {
			SSHBAND_LOGW("Can't delete pid file `%s': %s\n", config_pid_path, strerror(errno));
			return -1;
		}
	}
	else {
		SSHBAND_LOGW("Seems pid file `%s' is not created by current process, it won't be delete\n", config_pid_path);
		return -1;
	}
	
	return 0;
}

int main(int argc, char** argv) {
	char* cfgpath = NULL;
	
	openlog(basename(argv[0]), LOG_PID | LOG_CONS | LOG_PERROR, LOG_INFO | LOG_DAEMON);	/// 初始化 Syslog
	
	if (argc >= 2) {
		cfgpath = argv[1];
	}
	load_config(cfgpath);
	
	reg_signal();
		
	/**
	 * 转入守护进程
	 */
	if (fork() != 0) {
		exit(0);
	}		
	else {
		/// 根据 PID 检查当前进程是否唯一
		if (write_pid() != 0) {
			exit(0);
		}
		
		/// 检查 SQL 服务器是否正常
		if (db_init() != 0) {
			SSHBAND_LOGE("MySQL configure error, please check sshband configure file\n");

			sshband_exit(2);
		}
		
		load_sql_queue();
		
		srand(time(NULL));
		last_cleanup_time = time(NULL);

		pcap_main();
	}
	
	SSHBAND_LOGI("sshband stopped\n");
	
	return 0;
}

