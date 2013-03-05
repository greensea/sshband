#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mysql/mysql.h>
#include <errno.h>
#include <unistd.h>
#include "sshband.h"
#include "sshband_mysql.h"


extern char config_mysql_host[1024];
extern char config_mysql_user[1024];
extern char config_mysql_pass[1024];
extern char config_mysql_db[1024];

uint64_t db_inserted_id = 0;
sql_queue_t* sql_queue_head = NULL;

MYSQL* mysql = NULL;

/// 自定义 SQL 语句变量对应表
const char* fieldfmt_tbl[][2] = {
	{"inband", "%1$s"},
	{"outband", "%2$s"},
	{"username", "%3$s"},
	{"timestamp", "%4$ld"},
	{"starttime", "%5$ld"},
	{"clientip", "%6$s"},
	{"clientport", "%7$d"},
	{"serverip", "%8$s"},
	{"sessionid", "%9$s"},
    {"clientdatatime", "%10$ld"},
    {"uid", "%11$d"},
	{"%", "%%"}
};

int db_init() {
	MYSQL* sock = NULL;
	my_bool yes = 1;
	int slptime = 0;
	
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
	while (sock == NULL) {
		SSHBAND_LOGI("Connecting to MySQL server %s...\n", config_mysql_host);
		sock = mysql_real_connect(mysql, config_mysql_host, config_mysql_user, config_mysql_pass, config_mysql_db, 0, NULL, CLIENT_MULTI_STATEMENTS);
		if (sock == NULL) {
			SSHBAND_LOGE("Could not connect to MySQL server `%s': %s\n", config_mysql_host, mysql_error(mysql));

			slptime += 10;
			if (slptime > 300) {	// 5 min
				slptime = 300;
			}

			SSHBAND_LOGI("Retry after %d seconds\n", slptime);			
			sleep(slptime);
		}
		else {
			SSHBAND_LOGI("Connected to MySQL server %s\n", config_mysql_host);
		}
	}
	
	mysql_options(mysql, MYSQL_OPT_RECONNECT, &yes);
	
	return 0;
}

int db_destroy() {
	if (mysql != NULL) {
		mysql_close(mysql);
		free(mysql);
		mysql = NULL;
	}
	
	return 0;
}

int db_query(const char* sql) {
	sql_queue_t* p;
	sql_queue_t* tmp;
    MYSQL_RES* res;
    int fieldcnt;

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
        else {
            /// 查询成功 *必须* 清除结果集
            do {
                fieldcnt = mysql_field_count(mysql);
                res = mysql_store_result(mysql);
                if (res == NULL) {
                    if (fieldcnt > 0) {
                        SSHBAND_LOGE("Could not store MySQL result: %s\n", mysql_error(mysql));
                    }
                    continue;
                }
                else {
                    SSHBAND_LOGD("Processed result\n");
                    mysql_free_result(res);
                }
            } while (mysql_next_result(mysql) == 0);
        }
        
		/**
		 * 删除队列中的语句
		 */
		sql_queue_head = p->next;
		free(p);
		
		db_inserted_id = mysql_insert_id(mysql);
	}
		
	return 0;
}




/**
 * 配置文件自定义 SQL 查询语句变量字段转换说明：
 * 
 * 例如调用：snprintf(buf, sizeof(buf), fmt, username, inband, outband)
 *                                        %1$s    %2$lld   %3$lld                                     
 * 则 fmt 的转换过程如下：
 * -----1-----
 * INSERT INTO table (username, inband, outband) VALUES (%inband, %outband, %username)	/// 配置文件
 * INSERT INTO table (username, inband, outband) VALUES (%2$lld, %3$lld, %1$s)	/// fmt
 */

/**
 * 从指定的 % 位置开始取出 field
 * 合法的 field 是 %[a-zA-Z0-9]+
 * %% 会被转义为 %，也就是返回一个长度为 1 的 "%" field
 *
 * @param char*	原始配置字符串
 * @param int	指定的位置，即原始配置字符串的第几个字符
 * @param char*	取到的 field
 * @param size_t	field 参数变量缓冲区大小
 * @return int	返回 field 的长度，失败返回0
 */
size_t sql_config2fmt_getfield(char* in, int pos, char* field, size_t fieldsize) {	
	char c;
	int i = 0;
	
	pos++;
	
	if (in[pos] == '%') {
		strncpy(field, "%", fieldsize - 1);
		
		return 1;	/// strlen("%") == 1 byte
	}
	
	while ((c = in[pos]) != 0 && i < fieldsize - 1) {
		if ( ('a' <= c && c <= 'z') ||
			 ('A' <= c && c <= 'Z') ||
			 ('0' <= c && c <= '9') ) {
				 
			field[i] = c;
			
			i++;
			pos++;
		}
		else {
			break;
		}
	}
	
	field[i] = 0;

	return i;
}

/**
 * 将 field 转换成 fmt 格式
 * 
 * @param char*	field 字符串，不带前导 %
 * @return const char*	转换后的 fmt 格式的字符串
 */
char* sql_config2fmt_field2fmt(char* field) {
	int i;
	
	for (i = 0; i < sizeof(fieldfmt_tbl) / sizeof(fieldfmt_tbl[0]); i++) {
		if (strcmp(field, fieldfmt_tbl[i][0]) == 0) {
			return (char*)fieldfmt_tbl[i][1];
		}
	}
	
	return NULL;
}

/**
 * 将配置文件中的 SQL 语句替换成 printf format 语句
 * 
 * @param char* 配置文件中的 SQL 语句
 * @param char* 转换后的 fmt 字符串
 * @param size_t    转换后的 fmt 字符串缓冲区大小
 * @param int   成功返回0，否则返回其他值
 */
int sql_config2fmt(char* in, char* out, size_t outsize) {
	int i = 0;
	int k = 0;
	char field[128];
	char* fmt;
		
	if (in == NULL || out == NULL) {
		SSHBAND_LOGD("%s: Invalid argument: in == NULL || out == NULL\n", __func__);
		return -1;
	}
	
	/// 取出 % 打头的变量，提换成 fmt 格式
	while (in[i] != 0x00 && k < outsize - 1) {
		switch (in[i]) {
			case '%':
				if (k == outsize - 2) {
					/// 缓冲区正好不够长的情况
					out[k] = in[i];
					k++;
					i++;
					break;
				}
				else {
					size_t fieldlen = 0;
					
					fieldlen = sql_config2fmt_getfield(in, i, field, sizeof(field));
					fmt = sql_config2fmt_field2fmt(field);

					if (fmt == NULL) {
						SSHBAND_LOGW("Unknown field `%%%s' in SQL `%s'\n", field, in);
						
						out[k] = '%';
						k++;
						i++;
						out[k] = 0x00;
						
						strncat(out, in + i, outsize - k - 1);
						i += fieldlen;
						k += fieldlen;
					}
					else {
						out[k] = 0x00;
						strncat(out, fmt, outsize - k - 1);
						i += fieldlen + 1;	/// strlen('%') == 1 bytes
						k += strlen(fmt);
					}
				}
				
				break;
				
			default:
				out[k] = in[i];
				i++;
				k++;
				
				break;
		}	// End of switch
		
	}	// End of while
	
	out[k] = 0x00;
	
	if (in[i] != 0x00 && k >= outsize - 1) {
		SSHBAND_LOGW("SQL is too long: %s\n", in);
	}
	
    SSHBAND_LOGD("User custom SQL:  %s\n", in);
    SSHBAND_LOGD("Expand to format: %s\n", out);
	
	return 0;
}


