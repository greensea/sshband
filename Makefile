all : mysql.c mysql.h sshband.c sshband.h pcap.c pcap.h userinfo.c userinfo.h
	gcc -Wall -o "sshband" pcap.c userinfo.c sshband.c mysql.c  -lmysqlclient -lpcap -I/usr/include/mysql

install : sshband
	cp sshband /usr/sbin/
	chmod +x /usr/sbin/sshband
	cp sshband.init /etc/init.d/sshband
	chmod +x /etc/init.d/sshband
	if test ! -f /etc/sshband.conf; then cp sshband.conf /etc/; chown root /etc/sshband.conf; chmod 600 /etc/sshband.conf; fi

uninstall :
	rm -f /usr/sbin/sshband
	rm -f /etc/init.d/sshband

clean :
	rm -f *.o
	rm -f sshband
