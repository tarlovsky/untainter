############# INPUT #############
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
############# INPUT #############
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
############# INPUT #############
<?php
echo mysql_real_escape_string($_GET["username"]);
?>
*-----------Line: 0---------*
[*] @ Sensitive sink [echo] is accepting a tainted value/s coming from [_GET["username"]]!
############# INPUT #############
<?php
echo $_GET["username"].$_GET["USER"];
?>
*-----------Line: 0---------*
[*] @ Sensitive sink [echo] is accepting a tainted value/s coming from [_GET["USER"]]!
[*] @ Sensitive sink [echo] is accepting a tainted value/s coming from [_GET["username"]]!
############# INPUT #############
<?php
echo mysql_query(mysql_real_escape_string($_GET["username"]));
?>
*-----------Line: 0---------*
[*] @ Sensitive sink [mysql_query] has beed corrected!
[*] @ Sensitive sink [echo] is accepting a tainted value/s coming from [_GET["username"]]!
############# INPUT #############
<?php
echo $a.$_GET["U"];
?>
[*] @ Sensitive sink [echo] is accepting a tainted value/s coming from [_GET["U"]]!
############# INPUT #############
<?php
$i = $_FILES["user"];
$j = $_GET["user"];
while(True){
    $a = True;
    $b = "HELO";
    $c = $_GET["c"];
}
mysql_query($c);
?>
We overestimate
*-----------Line: 3---------*
[*] @ Sensitive sink [mysql_query] is accepting a tainted value/s [c]!
############# INPUT #############
<?php
$u = $_GET["u"];
$u1 = $_GET["u1"];
$u2 = $_GET["u2"];
$u3 = $_GET["u3"];
$u4 = $_GET["u4"];
if($u){
    $p = $u;
}else if ($u1){
    $a = $_GET['a'];
}else if (True){
    $b = $_GET['b'];
}else if ($u3){
    $c = $_GET['c'];
}else{
    $d = $_GET['d'];
}
?>
*-----------Line: x---------*
This code uses if_chain_tainters
The tainted dict is:
Tainted variables: {u'a': [u'_GET["a"]', u'u', u'u1'], u'c': [u'_GET["c"]', u'u', u'u1', u'u3'], u'b': [u'_GET["b"]', u'u', u'u1'], u'd': [u'_GET["d"]'], u'u4': [u'_GET["u4"]'], u'u1': [u'_GET["u1"]'], u'u3': [u'_GET["u3"]'], u'u2': [u'_GET["u2"]'], u'p': [u'_GET["u"]', u'u'], u'u': [u'_GET["u"]']}
Example: c is tainted by:
'c': [u'_GET["c"]', 'u', 'u1', 'u3']
?>