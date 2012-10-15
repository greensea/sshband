CC=gcc
CFLAGS=-Wall -c -g -pipe -I/usr/include/mysql -D_GNU_SOURCE 
LDFLAGS=-lmysqlclient -lpcap

sshband : pcap.o userinfo.o sshband.o mysql.o
	$(CC) $(LDFLAGS) $^ -o $@

all : sshband

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
	rm -f *.d
	rm -f *.o
	rm -f sshband

SOURCE = $(wildcard *.c)
	sinclude $(SOURCE:.c=.d)

%.d: %.c
	$(CC) -MT "$*.o $*.d" -MM $(CFLAGS) $< > $@
