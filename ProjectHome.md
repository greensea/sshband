## sshband 是什么 ##

sshband 是一个统计 SSH 流量的程序，它可以统计每个 SSH 会话所使用的网络流量，SSH 隧道代理请求消耗的流量也会计算在内。当前版本可以将会话保存在 MySQL 数据库内。

## 设计初衷 ##

sshband 最初的设计目的是为了统计服务器上用户使用 SSH 代理所消耗的流量，记录每个用户使用的流量。配合一个自己编写的脚本，定期删除流量超过配额的用户。

sshband 适用于那些开放了 SSH 代理服务，而又想给用户设定流量配额的服务器。

## 快速导航 ##

编译安装： [Install](Install.md)

配置文件解读： [Configure](Configure.md)

工作原理： [Working](Working.md)