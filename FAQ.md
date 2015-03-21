### I login as _root_, but I can't see bandwidth information in database for _root_ user ###

sshband will not count the bandwidth for root user(which uid=0).

### Why is _sshd_ inserted into username field on my database ###

Check your configuration file whether you config ssh\_uid correctly. ssh\_uid could be obtaind by the command following:

```
cat /etc/passwd | grep sshd | awk -F ":" '{print $3}'
```

### I have login via SSH, but I can't see my username in database ###

1. If your are login as _root_ , you won't see your name, cause sshband will not count bandwidth for _root_ user.

2. Maybe you just login, sshband need more SSH traffic before updating database. Do something then your will see your name.