# 1.Get source #

Get the latest develop version of sshband

```
$ svn checkout http://sshband.googlecode.com/svn/trunk/ sshband 
```

# 2.Compile and install #

Before compiling, you need to install libpcap-devel and libmysqlclient-dev

On Fedora/CentOS :

```
# yum install libpcap-devel libmysqlclient-dev
```

On Debian/Ubuntu:

```
# apt-get install libpcap-dev libmysqlclient-dev
```

Now we are ready for compile.

```
cd sshband
./configure
make
make install
```

Open /etc/sshband.conf with your favorite text editor, configure sshband to fit your need.
sshband.sql is MySQL script which could create a MySQL table for the default configuration.