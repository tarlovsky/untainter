############# INPUT
<?php
$u = $_GET["u"];
$p = $_GET["p"];
$koneksi = pg_escape_string($_GET["koneksi"]);
$b = $b;
$b = pg_escape_string($u.$p.pg_escape_string($u.$p));
$tmp = mysql_escape_string($tmp);
$tmp = pg_query($b, $koneksi);
$t = ($tmp);
mysql_query($t);
?>
*-----------Line: 6---------*
[*] @ Sensitive sink [pg_query] has beed corrected!

*-----------Line: 7---------*

*-----------Line: 8---------*
[*] @ Sensitive sink [mysql_query] is accepting a tainted value/s [t]!
############# INPUT
<?php
$u = $_GET['username'];
$ul = $_GET['ul'];
$u = ($ul . $ul = $u);
$q = "SELECT pass FROM users WHERE user='".$u."'";
$koneksi = mysql_escape_string($_GET['koneksi']);
$t = pg_escape_string($q);
mysql_query(pg_query(($t)), ($koneksi));
?>
*-----------Line: 6---------*
[*] @ Sensitive sink [pg_query] has beed corrected!
[*] @ Sensitive sink [mysql_query] is accepting a tainted value/s coming from [_GET["username"]]!
############# INPUT
<?php
echo mysql_real_escape_string($_GET["username"]);
?>
*-----------Line: 0---------*
[*] @ Sensitive sink [echo] is accepting a tainted value/s coming from [_GET["username"]]!
############# INPUT
<?php
echo $_GET["username"].$_GET["USER"];
?>
*-----------Line: 0---------*
[*] @ Sensitive sink [echo] is accepting a tainted value/s coming from [_GET["USER"]]!
[*] @ Sensitive sink [echo] is accepting a tainted value/s coming from [_GET["username"]]!
############# INPUT
<?php
echo mysql_query(mysql_real_escape_string($_GET["username"]));
?>
*-----------Line: 0---------*
[*] @ Sensitive sink [mysql_query] has beed corrected!
[*] @ Sensitive sink [echo] is accepting a tainted value/s coming from [_GET["username"]]!