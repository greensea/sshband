CREATE TABLE `sshacct` (
  `id` int(11) NOT NULL auto_increment,
  `uid` int(11) NOT NULL,
  `inband` bigint(20) NOT NULL,
  `outband` bigint(20) NOT NULL,
  `connecttime` datetime NOT NULL,
  `disconnecttime` datetime NOT NULL,
  `username` varchar(255) NOT NULL,
  `clientip` char(15) NOT NULL,
  `sessionid` char(32) NOT NULL,
  `clientport` int(11) NOT NULL,
  PRIMARY KEY  (`id`),
  KEY `sessionid` (`sessionid`)
);
