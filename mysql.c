#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mysql.h>
#include "mysql.h"
#include <stdint.h>

extern char config_mysql_host[1024];
extern char config_mysql_user[1024];
extern char config_mysql_pass[1024];
extern char config_mysql_db[1024];

uint64_t db_inserted_id = 0;
sql_queue_t* sql_queue_head = NULL;

int db_query(const char* sql) {
	sql_queue_t* p;
	sql_queue_t* tmp;
	MYSQL mysql, *sock;
	
printf("INSQL: %s\n", sql);	

	/**
	 * SQL语句队列
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

	/**
	 * SQL查询
	 */
	mysql_init(&mysql);
	if (!(sock = mysql_real_connect(&mysql, config_mysql_host, config_mysql_user, config_mysql_pass, config_mysql_db, 0, NULL, 0))) {
		fprintf(stderr, "Could not connect to mysql: %s\n", mysql_error(&mysql));
		return -1;
	}
	

	while ((p = sql_queue_head) != NULL) {
		printf("QUERYSQL: %s\n", p->sql);
		if (mysql_query(sock, p->sql)) {
			fprintf(stderr, "Could not query sql (%s): %s\n", p->sql, mysql_error(sock));
			//return -2;
		}
		
		/**
		 * 删除队列中的语句
		 */
		sql_queue_head = p->next;
		free(p);
	
		db_inserted_id = mysql_insert_id(sock);
	}
	
	mysql_close(sock);
	
	return 0;
}

