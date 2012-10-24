<?php
$stime = microtime(true);

$DB_HOST = 'localhost';
$DB_USER = 'sshband';
$DB_PASS = 'sshband';
$DB_NAME = 'sshaccount';

if (!mysql_connect($DB_HOST, $DB_USER, $DB_PASS)) {
    die(mysql_error());
}

if (!mysql_select_db($DB_NAME)) {
    die(mysql_error());
}

function size2readable($size) {
    $fmt = '';

    if ($size < 1000) {
        $fmt = sprintf('%d B', $size);
    }    
    else if ($size < 1000 * 1000) {
        $fmt = sprintf('%0.2f KiB', $size / 1024);
    }
    else if ($size < 1000 * 1000 * 1000) {
        $fmt = sprintf('%0.2f MiB', $size / 1024 / 1024);
    }
    else if ($size < 1000 * 1000 * 1000 * 1000) {
        $fmt = sprintf('%0.2f GiB', $size / 1024 / 1024 / 1024);
    }
    else if ($size < 1000 * 1000 * 1000 * 1000 * 1000) {
        $fmt = sprintf('%0.2f TiB', $size / 1024 / 1024 / 1024 / 1024);
    }
    else {
        $fmt = sprintf('%0.2f PiB', $size / 1024 / 1024 / 1024 / 1024 / 1024);
    }
    
    return $fmt;
}

function time2readable($ts) {
    $ret = '';
    
    if ($ts >= 86400) {
        $ret .= sprintf('%d天', floor($ts / 86400));
        $ts -= floor($ts / 86400) * 86400;
    }
    
    if ($ts >= 3600 || $ret != '') {
        $ret .= sprintf('%d小时', floor($ts / 3600));
        $ts -= floor($ts / 3600) * 3600;
    }
    
    if ($ts >= 60 || $ret != '') {
        $ret .= sprintf('%d分', floor($ts / 60));
        $ts -= floor($ts / 60) * 60;
    }
    
    $ret .= sprintf('%d秒', $ts);
    
    return $ret;
}



?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
	"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">

<head>
	<title>SSH 流量使用情况</title>
	<meta http-equiv="content-type" content="text/html;charset=utf-8" />
	<link href="sshband.css" type="text/css" rel="stylesheet" media="screen" />
</head>

<body>
    
    <h1>SSH 流量使用情况</h1>
    
    <menu>
        <a href="<?php echo basename(__FILE__);?>">所有记录</a>
        <a href="<?php echo basename(__FILE__);?>?group=user">按用户</a>
        <a href="<?php echo basename(__FILE__);?>?group=host">按主机</a>
        <a href="<?php echo basename(__FILE__);?>?group=userhost">按用户主机</a>
    </menu>
    
    <?php
    $sql = '';
    switch ($_GET['group']) {
        case 'user':
            $sql = "SELECT username, SUM(inband) AS inband , SUM(outband) AS outband , SUM( GREATEST( UNIX_TIMESTAMP(disconnecttime) - UNIX_TIMESTAMP(connecttime), 0 ) ) AS onlinetime,
'-' AS clientip, 0 AS connecttime, 0 AS disconnecttime, '-' AS host 
FROM sshacct 
GROUP BY username 
ORDER BY username ASC";
            break;
        case 'host':
            $sql = "SELECT host, SUM(inband) AS inband , SUM(outband) AS outband , SUM( GREATEST( UNIX_TIMESTAMP(disconnecttime) - UNIX_TIMESTAMP(connecttime), 0 ) ) AS onlinetime,  '-' AS clientip, 0 AS connecttime, 0 AS disconnecttime,  '-' AS username
FROM sshacct
GROUP BY host
ORDER BY host ASC";
            break;
        case 'userhost';
            $sql = "SELECT username, host, SUM(inband) AS inband , SUM(outband) AS outband , SUM( GREATEST( UNIX_TIMESTAMP(disconnecttime) - UNIX_TIMESTAMP(connecttime), 0 ) ) AS onlinetime,  0 AS connecttime, 0 AS disconnecttime, '-' AS clientip
FROM sshacct
GROUP BY host,username
ORDER BY username ASC, host ASC";
            break;
        default:
            $sql = "SELECT *, GREATEST( UNIX_TIMESTAMP(disconnecttime) - UNIX_TIMESTAMP(connecttime), 0 ) AS onlinetime FROM sshacct ORDER BY id DESC ";
            break;
    }
    
    $dbstime = microtime(true); 
    if (!($res = mysql_query($sql))) {
        die(mysql_error() . "<pre>$sql</pre>");
    }
    $query_time = sprintf('%0.3f', microtime(true) - $dbstime);
    ?>
    
    <table class="list" border="1" cellspacing="0">
        <caption>共 <?php echo mysql_num_rows($res);?> 条记录</caption>
        <tr>
            <th style="width: 10em;">用户名</th>
            <th style="width: 8em;">客户端地址</th>
            <th style="width: 9em;">登陆服务器</th>
            <th style="width: 10em;">登录时间</th>
            <th style="width: 10em;">退出时间</th>
            <th style="width: 12em;">在线时长</th>
            <th>使用流量（下载/上传）</th>
        </tr>
        
        <?php
        while ($row = mysql_fetch_array($res)) {
        ?>
            <tr>
                <td><?=htmlspecialchars($row['username'])?></td>
                <td><?=$row['clientip']?></td>
                <td><?=htmlspecialchars($row['host'])?></td>
                <td><?=$row['connecttime']?></td>
                <td><?=$row['disconnecttime']?></td>
                <td><?=time2readable($row['onlinetime'])?></td>
                <td class="band">
                    <?php
                    $total = $row['inband'] + $row['outband'];
                    $rtotal = max($total, 2);
                    $in_ratio = round(max(1, $row['inband']) * 100 / $rtotal);
                    $out_ratio = round(max(1, $row['outband']) * 100 / $rtotal);
                    ?>
                    <div class="band_total">共使用 <?=size2readable($total)?></div>
                    <div class="band_upload"><?=size2readable($row['inband'])?></div>
                    <div class="band_download" style="width: <?=$out_ratio?>%;"><?=size2readable($row['outband'])?></div>
                </td>

            </tr>
        <?php
        }
        ?>
        
    </table>

    <hr />

    <div class="footer">
        <div>数据库查询耗时 <?=$query_time?> 毫秒，页面执行耗时 <?=sprintf('%0.3f', microtime(true) - $stime)?> 毫秒</div>
        <div>This PHP script is part of sshband package.</div>
    </div>
	
</body>

</html>
