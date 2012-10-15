#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mysql.h>
#include <errno.h>
#include "sshband.h"
#include "mysql.h"


extern char config_mysql_host[1024];
extern char config_mysql_user[1024];
extern char config_mysql_pass[1024];
extern char config_mysql_db[1024];

uint64_t db_inserted_id = 0;
sql_queue_t* sql_queue_head = NULL;

MYSQL* mysql = NULL;

int db_init() {
	MYSQL* sock;
	my_bool yes = 1;
	
	if (mysql != NULL) {
		SSHBAND_LOGD("MYSQL* mysql is already initilized\n");
		return 0;
	}
	
	mysql = (MYSQL*)malloc(sizeof(MYSQL));
	if (mysql == NULL) {
		SSHBAND_LOGE("%s: malloc() fail: %s\n", __func__, strerror(errno));
		return -1;
	}
	
	if (NULL == mysql_init(mysql)) {
		free(mysql);
		SSHBAND_LOGE("mysql_init() error\n");
		
		return -1;
	}
	
	/// 尝试连接数据库
	SSHBAND_LOGI("Connecting to MySQL server %s...\n", config_mysql_host);
	sock = mysql_real_connect(mysql, config_mysql_host, config_mysql_user, config_mysql_pass, config_mysql_db, 0, NULL, 0);
	if (sock == NULL) {
		SSHBAND_LOGE("Could not connect to MySQL server `%s': %s\n", config_mysql_host, mysql_error(mysql));
	}
	else {
		SSHBAND_LOGI("Connected to MySQL server %s\n", config_mysql_host);
	}
	
	mysql_options(mysql, MYSQL_OPT_RECONNECT, &yes);
	
	return 0;
}

int db_destroy() {
	if (mysql != NULL) {
		mysql_close(mysql);
		free(mysql);
	}
	
	return 0;
}

int db_query(const char* sql) {
	sql_queue_t* p;
	sql_queue_t* tmp;

	/// FIXME: 增加 addslash 函数，对 SQL 语句进行转义，防止注入
	
	/**
	 * 保存到 SQL语句队列
	 */
	tmp = malloc(sizeof(sql_queue_t));
	memset(tmp->sql, 0, sizeof(tmp->sql));
	tmp->next = NULL;
	strncpy(tmp->sql, sql, sizeof(tmp->sql) - 1);
	p = sql_queue_head;
	if (p == NULL) {
		p = sql_queue_head = tmp;
	}
	else {
		while (p->next != NULL) {
			p = p->next;
		}
		p->next = tmp;
	}
	

	if (mysql == NULL) {
		SSHBAND_LOGD("Assertion mysql != NULL fail\n");
		return -1;
	}

	/**
	 * SQL查询
	 */
	/**
	mysql_init(mysql);
	if (!(sock = mysql_real_connect(mysql, config_mysql_host, config_mysql_user, config_mysql_pass, config_mysql_db, 0, NULL, 0))) {
		SSHBAND_LOGE("Could not connect to MySQL server `%s': %s\n", config_mysql_host, mysql_error(mysql));
		return -1;
	}
	*/
	mysql_ping(mysql);

	while ((p = sql_queue_head) != NULL) {
		SSHBAND_LOGD("QUERYSQL: %s\n", p->sql);
		if (mysql_query(mysql, p->sql)) {
			SSHBAND_LOGE("Could not execute SQL(\"%s\") on MySQL server: %s\n", p->sql, mysql_error(mysql));
			//return -2;
		}
		/**
		 * 查询成功，删除队列中的语句
		 */
		sql_queue_head = p->next;
		free(p);
		
		db_inserted_id = mysql_insert_id(mysql);
	}
		
	return 0;
}

