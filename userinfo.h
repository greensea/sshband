#ifndef __USERINFO_H__
#define __USERINFO_H__	1

uid_t get_uid_by_pid(pid_t pid);
pid_t get_pid_by_inode(unsigned long inode);
uid_t get_uid_by_ipport(unsigned long ip, unsigned short int rport);
char* get_name_by_uid(uid_t uid);
unsigned long get_inode_by_ipport(unsigned long ip, unsigned short int remote_port);
#endif
