#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <string.h>
#include <libgen.h>
#include <pwd.h>
#include "sshband.h"
#include "userinfo.h"

extern uid_t ssh_uid;
extern u_short ssh_port;

int is_sshd_proc(const char* path) {
	char cmdline[200] = {0};
	char buf[1024] = {0};
	FILE* fp;
	size_t readb;

	snprintf(cmdline, 199, "/proc/%s/cmdline", path);

	fp = fopen(cmdline, "r");
	if (fp == NULL) {
		return 0;
	}
	readb = fread(buf, 1, sizeof(buf), fp);
	fclose(fp);

	if (readb < 0) {
		SSHBAND_LOGW("Can't read %s, readb()=%d: %s\n", cmdline, readb, strerror(errno));
		return 0;
	}
	
	char* m_pos = NULL;
	m_pos = strrchr(buf, ':');
	if (m_pos != NULL) {
		buf[m_pos - buf] = 0;
	}	
	
	if (strcmp(basename(buf), "sshd") == 0) {
		//printf("%s\n", buf);
		return 1;
	}
	else {
		return 0;
	}
}

/**
 * @return int	1=存在，0=不存在
 */
int proc_inode_exists(const char* proc, unsigned long ino) {
	char fddirpath[200];
	char fdpath[200];
	DIR* dir;
	struct dirent* ent;	

	snprintf(fddirpath, 200, "/proc/%s/fd", proc);
	dir = opendir(fddirpath);
	if (dir == NULL) {
		SSHBAND_LOGD("%s opendir(\"%s\") fail: %s\n", __func__, fddirpath, strerror(errno));
		return 0;
	}
	
	while ((ent = readdir(dir)) != NULL) {
		struct stat s;
		
		snprintf(fdpath, 200, "/proc/%s/fd/%s", proc, ent->d_name);
		
		if (stat(fdpath, &s) != 0) {
			SSHBAND_LOGD("%s opendir(\"%s\") fail: %s\n", __func__,  fdpath, strerror(errno));
			closedir(dir);
			return 0;
		}
		else {
			//printf("%lu, %s\n", ino, fdpath);
			if (ino == s.st_ino) {
				closedir(dir);
				return 1;
			}
		}
	}
	
	closedir(dir);
	
	return 0;
}

unsigned long get_inode_by_ipport(unsigned long ip, unsigned short int remote_port) {
	FILE* fp;
	size_t readb;
	unsigned long sockid = 0;
	unsigned int lport = 0;
	unsigned int rport = 0;
	unsigned long rip = 0x0;

	fp = fopen("/proc/net/tcp", "r");
	if (fp == NULL) {
		SSHBAND_LOGE("Could not open /proc/net/tcp: %s", strerror(errno));
		return 0;
	}
	
	while (!feof(fp)) {
		while(fgetc(fp) != '\n' && !feof(fp));

		readb = fscanf(fp, "%*d: %*x:%x %lx:%x %*x %*x:%*x %*x:%*x %*x %*d %*d %lu %*d %*d %*x %*d %*d %*d %*d %*d", &lport, &rip, &rport, &sockid);
		if (lport == ssh_port && rport == remote_port && rip == ip) {
			break;
		}
		else {
			sockid = 0;
		}
	}

	fclose(fp);
	
	SSHBAND_LOGMD("inode of client(port %u) is %lu\n", remote_port, sockid);
	
	return sockid;
}

pid_t get_pid_by_inode(unsigned long inode) {
	DIR* dir;
	struct dirent* ent;
	pid_t pid = 0;
	
	dir = opendir("/proc");
	
	while ((ent = readdir(dir)) != NULL) {
		if (atoi(ent->d_name) == 0) {
			continue;
		}
		if (is_sshd_proc(ent->d_name) == 1) {
			if (proc_inode_exists(ent->d_name, inode) == 1) {
				// 根据UID判断进程不是root或sshd的才返回
				uid_t uid;
				uid = get_uid_by_pid(atol(ent->d_name));
				if (uid != 0 && uid != ssh_uid) {
					pid = atol(ent->d_name);	// fixme: 进程编号可能是无符号长整型，而我没找到atoul之类的函数
					closedir(dir);
					SSHBAND_LOGMD("pid of inode %lu is %d\n", inode, pid);
					
					return pid;
				}
				else {
			//		printf("inode=%lu, proc=%s, uid=%d\n", inode, ent->d_name, uid);
				}
			}
		}
	}
	
	SSHBAND_LOGMD("No pid match to inode %lu\n", inode);
	
	closedir(dir);
	
	return 0;
}

uid_t get_uid_by_pid(pid_t pid) {
	uid_t ruid = -1;
	size_t readb;
	char status[1000] = {0};
	char buf[1001] = {0};
	char* buf2;
	long uid, euid, suid, fsuid;
	FILE* fp;
	
	if (pid == 0) {
		SSHBAND_LOGMD("%s: Warning: pid == 0\n", __func__);
		return ruid;
	}
	
	snprintf(status, 200, "/proc/%d/status", pid);
	fp = fopen(status, "r");
	if (fp == NULL) {
		SSHBAND_LOGE("Could not open %s: %s", status, strerror(errno));
		return 0;
	}
	readb = fread(buf, 1000, 1, fp);	
	fclose(fp);

	if (readb < 0) {
		SSHBAND_LOGW("Can't read %s, fread()=%d: %s\n", status, readb, strerror(errno));
		return 0;
	}
	
	buf2 = strstr(buf, "Uid");
	sscanf(buf2, "Uid: %ld %ld %ld %ld", &uid, &euid, &suid, &fsuid);
	ruid = uid;
	
	SSHBAND_LOGMD("uid of pid %d is %d\n", pid, ruid);
	
	return ruid;
}

uid_t get_uid_by_ipport(unsigned long ip, unsigned short int rport) {
	unsigned long inode;
	pid_t pid = 0;
	uid_t uid = -1;

	inode = get_inode_by_ipport(ip, rport);
//		printf("(get_inode_by_rport(%d))=%lu\n", rport, inode);
    if (inode == 0) {
        return uid;
    }
    
	pid = get_pid_by_inode(inode);
//		printf("(get_pid_by inode)=%d\n", pid);
    if (pid == 0) {
        return uid;
    }
    
	uid = get_uid_by_pid(pid);
//		printf("(get_uid_by_pid)=%d\n", uid);

	return uid;
}


char* get_name_by_uid(uid_t uid) {
	struct passwd *pwd;
	static char name[32] = {0};
	
	if ((pwd = getpwuid(uid)) != NULL) {
		strncpy(name, pwd->pw_name, sizeof(name) - 1);
	}
	
	return name;
}

