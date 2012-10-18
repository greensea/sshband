#ifndef __MYSQL_H__
#define __MYSQL_H__	1

int db_query(const char* sql);

int db_init(void);
int db_destroy(void);

int sql_config2fmt(char*, char*, size_t);

typedef struct sql_queue_t {
	char sql[1024];
	struct sql_queue_t* next;
} sql_queue_t;

extern const char* fieldfmt_tbl[][2];

#endif
