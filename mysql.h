#ifndef __MYSQL_H__
#define __MYSQL_H__	1

int db_query(const char* sql);

int db_init(void);
int db_destroy(void);

typedef struct sql_queue_t {
	char sql[1024];
	struct sql_queue_t* next;
} sql_queue_t;

#endif
