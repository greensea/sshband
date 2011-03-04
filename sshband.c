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


int ssh_session_init(u_short port) {
	if (sessions[port] == NULL) {
		sessions[port] = malloc(sizeof(ssh_session_t));
	}
	if (sessions[port] == NULL) {
		return -1;
	}

	sessions[port]->uid = -1;
	sessions[port]->stime = time(NULL);
	sessions[port]->outband = 0;
	sessions[port]->inband = 0;
	sessions[port]->client_data_time = time(NULL);
	memset(sessions[port]->sessid, 0x00, sizeof(sessions[port]->sessid));
	strncpy(sessions[port]->sessid, get_random_sess_id(), sizeof(sessions[port]->sessid) - 1);

	return 0;
}

void ssh_session_acct_new(u_short rport) {
	ssh_session_t* pak;
	char sql[1024] = {0};
	
	pak = sessions[rport];
	if (pak == NULL) {
		return;
	}
	else {
	}
	
	snprintf(sql, 1023, "INSERT INTO %s (%s, %s, %s, %s, %s, %s) VALUES (%d, FROM_UNIXTIME(%lu), '%s', '%s', '%s', %u)", config_table_acct, config_column_uid, config_column_connecttime, config_column_username, config_column_sessionid, config_column_clientip, config_column_clientport, pak->uid, pak->stime, get_name_by_uid(pak->uid), pak->sessid, pak->client_addr, rport);
	db_query(sql);
}

void ssh_session_start(hdl_pak_t pak) {
	u_short rport;
	struct in_addr ip;
	
	if (pak.dport == ssh_port) {
		rport = pak.sport;
		ip = pak.ip_src;
	}
	else {
		rport = pak.dport;
		ip = pak.ip_dst;
	}
	
	if (sessions[rport] == NULL) {
		ssh_session_init(rport);
		strncpy(sessions[rport]->client_addr, inet_ntoa(ip), sizeof(sessions[rport]->client_addr) - 1);
	}
}

void ssh_session_acct_end(u_short rport) {
	ssh_session_t* sess;
	char sql[1024];
	
	sess = sessions[rport];
	
	if (sess == NULL) {
		return;
	}
	
	snprintf(sql, 1023, "UPDATE %s SET %s=%llu, %s=%llu, %s=FROM_UNIXTIME(%lu)  WHERE %s='%s'", config_table_acct, config_column_inband, sess->inband, config_column_outband, sess->outband, config_column_disconnecttime, sess->client_data_time, config_column_sessionid, sess->sessid);
	//printf("sql=%s\n", sql);
	db_query(sql);	
}

void ssh_session_end(hdl_pak_t pak) {
	u_short rport;
	ssh_session_t* sess;

	rport = (pak.dport == ssh_port ? pak.sport : pak.dport) ;	
	sess = sessions[rport];
	
	if (sess == NULL) {
		return;
	}
	
	ssh_session_acct_end(rport);
	
	free(sess);
	sessions[rport] = NULL;
}

uid_t get_ssh_uid(u_short rport) {
	uid_t uid;
	
	uid = get_uid_by_port(rport);
	if (uid != ssh_uid && uid != 0) {
		return uid;
	}
	else {
		return -1;
	}
}

void ssh_session_gotpack(hdl_pak_t pak) {
	u_short rport;
	
	rport = (pak.dport == ssh_port ? pak.sport : pak.dport) ;
	
	// 检查是否应该清理非正常断开的客户端
	if (time(NULL) - last_cleanup_time > 60) {
		ssh_session_cleanup();
	}

	if (sessions[rport] == NULL) {
		return;
	}
	
	
	/**
	 * 正式处理
	 */
	if (sessions[rport]->uid == -1) {
		//printf("uid==-1, try to get uid on port %d...", rport);
		sessions[rport]->uid = get_ssh_uid(rport);
		//printf("%d\n", sessions[rport]->uid);
		// 获取到UID以后，增加acct记录
		if (sessions[rport]->uid != -1) {
			ssh_session_acct_new(rport);
		}
	}
	
	if (pak.sport == ssh_port) {
		sessions[rport]->outband += pak.len;
	}
	else {
		sessions[rport]->inband += pak.len;
		sessions[rport]->client_data_time = time(NULL);
	}
	
	//printf("port=%d\tinband=%lld\toutband=%lld\tuid=%d\n", rport, sessions[rport]->inband / 1024, sessions[rport]->outband / 1024, sessions[rport]->uid);
	
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
	
	for (i = 0; i < sizeof(sessions) / sizeof(ssh_session_t*); i++) {
		if (sessions[i] != NULL) {
			ssh_session_acct_end(i);
			free(sessions[i]);
			sessions[i] = NULL;
		}
	}
	
	save_sql_queue();
	
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

/**
 * 清理非正常中断的SSH用户进程session_
 * 若会话列表中已有用户编号，而根据此会话端口在本机上查不到对应进程，则认为会话非正常中断
 */
void ssh_session_cleanup() {
	int i;
	unsigned long ino;
	pid_t pid;
	ssh_session_t *sess;
	
	for (i = 0; i < sizeof(sessions) / sizeof(ssh_session_t*); i++) {
		if (sessions[i] == NULL) {
			continue;
		}
		
		sess = sessions[i];
		if (sess->uid != ssh_uid && sess->uid != 0 && sess->uid != -1) {
			ino = get_inode_by_port(i);
			pid = get_pid_by_inode(ino);
			if (pid <= 0) {
				ssh_session_acct_end(i);
				free(sess);
				sessions[i] = NULL;
			}
		}
	}
	
	last_cleanup_time = time(NULL);
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
		pcap_main();
	}
	
	return 0;
}

