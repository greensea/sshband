all : mysql.c mysql.h sshband.c sshband.h pcap.c pcap.h userinfo.c userinfo.h
	gcc -Wall -o "sshband" pcap.c userinfo.c sshband.c mysql.c  -lmysqlclient -lpcap -I/usr/include/mysql
