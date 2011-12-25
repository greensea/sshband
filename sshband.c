#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "mysql.h"
#include "sshband.h"
#include "pcap.h"
#include "userinfo.h"
#include "string.h"
#include "mysql.h"

extern uint64_t db_inserted_id;
extern sql_queue_t* sql_queue_head;

u_short ssh_port = 22;
uid_t ssh_uid = 120;
ssh_session_t* sessions[65536] = {NULL};
long last_cleanup_time = 0;

char config_mysql_host[1024] = {0};
char config_mysql_user[1024] = {0};
char config_mysql_pass[1024] = {0};
char config_mysql_db[1024] = {0};
char config_table_acct[1024] = {0};
char config_column_uid[1024] = {0};
char config_column_username[1024] = {0};
char config_column_inband[1024] = {0};
char config_column_outband[1024] = {0};
char config_column_connecttime[1024] = {0};
char config_column_disconnecttime[1024] = {0};
char config_net_device[1024] = {0};
char config_column_sessionid[1024] = {0};
char config_column_clientip[1024] = {0};
char config_column_clientport[1024] = {0};

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
	
	fp = fopen("/var/sshband.sql", "r");
	if (fp == NULL) {
		return;
	}
	
	sql_queue_head = p = malloc(sizeof(sql_queue_t));
	p->next = NULL;
	fread(p->sql, sizeof(p->sql), 1, fp);
	printf("p->sql: %s\n", p->sql);
	
	while (fread(sql, sizeof(p->sql), 1, fp)) {
		p->next = malloc(sizeof(sql_queue_t));
		p = p->next;
		p->next = NULL;
		strncpy(p->sql, sql, sizeof(p->sql));
		printf("p->sql: %s\n", p->sql);
	}
	
	fclose(fp);
	unlink("/var/sshband.sql");	
}

void save_sql_queue() {
	FILE* fp;
	sql_queue_t* p;
	
	if (sql_queue_head == NULL) {
		return; 
	}
	
	fp = fopen("/var/sshband.sql", "w");
	if (fp == NULL) {
		fprintf(stderr, "Could not open /var/sshband.sql for write\n");
		return ;
	}
	
	p = sql_queue_head;
	while (p != NULL) {
		fwrite(p->sql, sizeof(p->sql), 1, fp);
		sql_queue_head = p;
		p = p->next;
		free(sql_queue_head);
	}

	fclose(fp);
	chmod("/var/sshband.sql", 0600);
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
	
	newsess = malloc(sizeof(ssh_session_t));
	if (newsess == NULL) {
		return -1;
	}

	newsess->next = NULL;
	newsess->uid = -1;
	newsess->stime = time(NULL);
	newsess->outband = 0;
	newsess->inband = 0;
	newsess->client_data_time = time(NULL);
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

	return 0;
}

void ssh_session_acct_new(ssh_session_t* sess, u_short rport) {
	char sql[1024] = {0};
	
	if (sess == NULL) {
		return;
	}
	else {
	}
	
	snprintf(sql, 1023, "INSERT INTO %s (%s, %s, %s, %s, %s, %s) VALUES (%d, FROM_UNIXTIME(%lu), '%s', '%s', '%s', %u)", config_table_acct, config_column_uid, config_column_connecttime, config_column_username, config_column_sessionid, config_column_clientip, config_column_clientport, sess->uid, sess->stime, get_name_by_uid(sess->uid), sess->sessid, sess->client_addr, rport);
	db_query(sql);
}

void ssh_session_start(hdl_pak_t pak) {
	u_short rport;
	int *ipval, *ipval2;
	ssh_session_t* sess;
	struct in_addr ip;
	
	if (pak.dport == ssh_port) {
		rport = pak.sport;
		ip = pak.ip_src;
	}
	else {
		rport = pak.dport;
		ip = pak.ip_dst;
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

	if (0 == ssh_session_init(rport, &sess)) {
		strncpy(sess->client_addr, inet_ntoa(ip), sizeof(sess->client_addr) - 1);
		sess->ip = ip;		
	}
}

void ssh_session_acct_end(ssh_session_t* sess) {
	char sql[1024];
	
	if (sess == NULL) {
		return;
	}
	
	snprintf(sql, 1023, "UPDATE %s SET %s=%llu, %s=%llu, %s=FROM_UNIXTIME(%lu)  WHERE %s='%s'", config_table_acct, config_column_inband, sess->inband, config_column_outband, sess->outband, config_column_disconnecttime, sess->client_data_time, config_column_sessionid, sess->sessid);
	//printf("sql=%s\n", sql);
	db_query(sql);	
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
		return;
	}
	
	ssh_session_acct_end(sess);
	
	/**
	 * 删除会话节点
	 * 如果会话节点在哈希表中，直接删除即可
	 * 如果在链表中，就需要链表中的删除节点操作
	 */
	if (sess == sessions[rport]) {
		sessions[rport] = sessions[rport]->next;
		free(sess);
	}
	else {
		ssh_session_t* prev;
		
		prev = sessions[rport];
		while (prev->next != sess) {
			prev = prev->next;
		}
		prev->next = sess;
		free(sess);
	}
}

uid_t get_ssh_uid(unsigned long ip, u_short rport) {
	uid_t uid;

	uid = get_uid_by_ipport(ip, rport);
	if (uid != ssh_uid && uid != 0) {
		return uid;
	}
	else {
		return -1;
	}
}

void ssh_session_gotpack(hdl_pak_t pak) {
	u_short rport;
	int *ipval, *ipval2;
	ssh_session_t *sess;
	struct in_addr ip;
	
	
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
	
	// 检查是否应该清理非正常断开的客户端
	if (time(NULL) - last_cleanup_time > SESSION_CLEANUP_TIME) {
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
	
	if (pak.sport == ssh_port) {
		sess->outband += pak.len;
	}
	else {
		sess->inband += pak.len;
		sess->client_data_time = time(NULL);
	}
}

void sshband_handler(hdl_pak_t pak) {
	//printf("%d --> %d\t%dB\t", pak.sport, pak.dport, pak.len);

	if (pak.flags & TH_SYN) {
		printf("%d --> %d\t%dB\t", pak.sport, pak.dport, pak.len);
		printf("SYN \n");
		ssh_session_start(pak);
	}
	
	ssh_session_gotpack(pak);
	
	if (pak.flags & TH_FIN || pak.flags & TH_RST) {
		ssh_session_end(pak);
		printf("connect close\n");
	}
	
	//printf("\t%d", get_uid_by_port(pak.sport == 22 ? pak.dport : pak.sport));
	
	//printf("\n");
	
}

char* get_config(const char* name) {
	static char config[256] = {0};
	char* value;
	char line[256] = {0};
	char c;
	int i;
	FILE* fp;
	
	config[0] = 0;
	fp = fopen("/etc/sshband.conf", "r");
	if (fp == NULL) {
		fprintf(stderr, "Could not open configure file: %s\n", strerror(errno));
		return config;
	}
	
	while (!feof(fp)) {
		// 读入一行，跳过白字符
		i = 0;
		while (!feof(fp) && (c = fgetc(fp)) != '\n') {
			if (c == '\t' || c == ' ') continue;
			line[i] = c;
			i++;
			if (i == 255) break;
		}
		line[i] = 0;

		// 判断是否注释
		for (i = 0; i < 256; i++) {
			c = line[i];
			if (c != '\t' && c != ' ') break;
		}
		if (line[i] == '#') continue;

		value = strchr(line, '=');
		if (value != NULL) {
			line[value - line] = 0;
			
		}
	
		if (0 == strcmp(line, name)) {
			strncpy(config, value + 1, 255);
			
			break;
		}
	}
	fclose(fp);
	
	return config;
}

void load_config() {
	ssh_port = atoi(get_config("ssh_port"));
	if (ssh_port == 0) {
		fprintf(stderr, "Could not find ssh_port in configure file, use default value 22\n");
		ssh_port = 22;
	}
	ssh_uid = atoi(get_config("ssh_uid"));
	

	strncpy(config_mysql_pass, get_config("mysql_password"), sizeof(config_mysql_pass) - 1);
	strncpy(config_mysql_user, get_config("mysql_username"), sizeof(config_mysql_user) - 1);
	strncpy(config_mysql_db, get_config("mysql_database"), sizeof(config_mysql_db) - 1);
	strncpy(config_mysql_host, get_config("mysql_host"), sizeof(config_mysql_host) - 1);

	strncpy(config_table_acct, get_config("mysql_table_acct"), sizeof(config_table_acct) - 1);
	strncpy(config_column_uid, get_config("mysql_column_uid"), sizeof(config_column_uid) - 1);
	strncpy(config_column_username, get_config("mysql_column_username"), sizeof(config_column_username) - 1);
	strncpy(config_column_inband, get_config("mysql_column_inband"), sizeof(config_column_inband) - 1);
	strncpy(config_column_outband, get_config("mysql_column_outband"), sizeof(config_column_outband) - 1);
	strncpy(config_column_connecttime, get_config("mysql_column_connecttime"), sizeof(config_column_connecttime) - 1);
	strncpy(config_column_disconnecttime, get_config("mysql_column_disconnecttime"), sizeof(config_column_disconnecttime) - 1);
	strncpy(config_column_sessionid, get_config("mysql_column_sessionid"), sizeof(config_column_sessionid) - 1);
	strncpy(config_column_clientip, get_config("mysql_column_clientip"), sizeof(config_column_sessionid) - 1);
	strncpy(config_column_clientport, get_config("mysql_column_clientport"), sizeof(config_column_sessionid) - 1);
	
	strncpy(config_net_device, get_config("network_device"), sizeof(config_net_device) - 1);	
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
			sess = NULL;
			sess = next;
		}
	}
	
	save_sql_queue();
	
	unlink("/var/run/sshband.pid");
	exit(0);
}

int reg_signal() {
	struct sigaction sig_term;
	struct sigaction sig_int;
	
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
			SSHBAND_LOG("cleanup session,  session id : %s ", sess->sessid);
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
	
	SSHBAND_LOG("clean in");

	for (i = 0; i < sizeof(sessions) / sizeof(ssh_session_t*); i++) {
		while (1) {
			if (ssh_session_cleanup_port(i) == 0)
				break;
		}
	}	
	last_cleanup_time = time(NULL);
	SSHBAND_LOG("clean out");
}

int main(int argc, char** argv) {
	load_config();
	reg_signal();
	
	if (db_query("SELECT 1") != 0) {
		fprintf(stderr, "MySQL configure error, please check sshband configure file\n");
		exit(0);
	}
	
	load_sql_queue();
	
	srand(time(NULL));
	
	/**
	 * 转入守护进程
	 */
	if (fork() != 0) {
		exit(0);
	}		
	else {
		FILE* fp;
		
		fp = fopen("/var/run/sshband.pid", "w");
		if (fp != NULL) {
			fprintf(fp, "%d", getpid());
			fclose(fp);
		}
		else {
			fprintf(stderr, "Could not create pid file: /var/run/sshband.pid\n");
			exit(1);
		}
		
		pcap_main();
	}
	
	return 0;
}

