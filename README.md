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
    mysql_query($b);
}else{
    $d = $_GET['d'];
}
?>
*-----------Line: 5---------*
[*] @ Sensitive sink [mysql_query] is accepting a tainted value/s [b]!

Tainted variables: {u'a': [u'_GET["a"]', u'u', u'u1'], u'c': [u'_GET["c"]', u'u', u'u1', u'u3'], u'b': [u'_GET["b"]', u'u', u'u1'], u'd': [u'_GET["d"]'], u'u4': [u'_GET["u4"]'], u'u1': [u'_GET["u1"]'], u'u3': [u'_GET["u3"]'], u'u2': [u'_GET["u2"]'], u'p': [u'_GET["u"]', u'u'], u'u': [u'_GET["u"]'], (u'mysql_query', u'_GET["b"]'): [u'u', u'u1', u'u3', u'u3']}

u'c': [u'_GET["c"]', u'u', u'u1', u'u3']
############# INPUT #############
<?php
$i1 = $_FILES["user"];
$j1 = $_GET["user"];
while(True){
    $a = True;
    $b = "HELO";
    $c = $_GET["c"];
}
mysql_query($c);
shell_exec($_GET["incl"]);
die($_GET["get"]);
print $_GET["print"];
include($_GET["print"]);
require($_GET["REQUIRE"]);
########################
Processing ast_while_01.txt
Possible [SQL injection] @ [Line:4] Sensitive sink [mysql_query] is accepting a tainted value/s [c]!
Possible [OS Command Injection] @ [Line:5] Sensitive sink [shell_exec] is accepting a tainted value/s coming from [_GET["incl"]]!
Possible [Cross site scripting] @ [Line:6] Sensitive sink [exit] is accepting a tainted value/s coming from [_GET["get"]]!
Possible [Cross site scripting] @ [Line:7] Sensitive sink [print] is accepting a tainted value/s coming from [_GET["print"]]!
Possible [Remote File Inclusion] @ [Line:8] Sensitive sink [include] is accepting a tainted value/s coming from [_GET["print"]]!
Possible [Remote File Inclusion] @ [Line:9] Sensitive sink [include] is accepting a tainted value/s coming from [_GET["REQUIRE"]]!
------------Tainted values-----------
[i1]: _FILES["user"]
[c]: _GET["c"]
[j1]: _GET["user"]
-------------------------------------
?>
############# INPUT #############
<?php
$i1 = $_FILES["user"];
$j1 = $_GET["user"];
while(True){
    $a = True;
    $b = "HELO";
    $c = $_GET["c"];
}
mysql_query($c);
shell_exec($_GET["incl"]);
die(htmlentities($_GET["get"]));
print $_GET["print"];
include($_GET["print"]);
require($_GET["REQUIRE"]);
unlink ($_GET['unlink_file']);
shell_exec($_FILES['SHELLCODE.txt']);
pcntl_exec($_FILES['program'], $_FILES['args1']);
exec("alex");
file_put_contents("astring".$_FILES["f"]);
?>
########################
Processing ast_while_01.txt
Possible [SQL injection] @ [Line:4] Sensitive sink [mysql_query] is accepting a tainted value/s [c]!
Possible [OS Command Injection] @ [Line:5] Sensitive sink [shell_exec] is accepting a tainted value/s coming from [_GET["incl"]]!
Possible [Cross site scripting] @ [Line:6] Sensitive sink [exit] has beed corrected!
Possible [Cross site scripting] @ [Line:7] Sensitive sink [print] is accepting a tainted value/s coming from [_GET["print"]]!
Possible [Remote File Inclusion] @ [Line:8] Sensitive sink [include] is accepting a tainted value/s coming from [_GET["print"]]!
Possible [Remote File Inclusion] @ [Line:9] Sensitive sink [include] is accepting a tainted value/s coming from [_GET["REQUIRE"]]!
Possible [Remote File Inclusion] @ [Line:10] Sensitive sink [unlink] is accepting a tainted value/s coming from [_GET["unlink_file"]]!
Possible [OS Command Injection] @ [Line:11] Sensitive sink [shell_exec] is accepting a tainted value/s coming from [_FILES["SHELLCODE.txt"]]!
Possible [OS Command Injection] @ [Line:12] Sensitive sink [pcntl_exec] is accepting a tainted value/s coming from [_FILES["program"]]!
Possible [OS Command Injection] @ [Line:12] Sensitive sink [pcntl_exec] is accepting a tainted value/s coming from [_FILES["args1"]]!
Possible [Cross site scripting] @ [Line:14] Sensitive sink [file_put_contents] is accepting a tainted value/s coming from [_FILES["f"]]!
------------Tainted values-----------
[i1]: _FILES["user"]
[c]: _GET["c"]
[j1]: _GET["user"]
-------------------------------------
############# INPUT #############
<?php
$j1 = $_GET["user"];
$j2 = $_GET["password"];
while($j2){
    $j2 = strdup($j1,1);    
}
?>
########################
Processing ast_test_01.txt
------------Tainted values-----------
[j1]: _GET["user"]
[j2]: _GET["user"]
-------------------------------------