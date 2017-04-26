#!/usr/bin/perl
use DBI;
use Socket;
use Getopt::Std;
use Net::SNMP;

getopts('o:a:u:p:d:');

#Connect to database
$driver="mysql";
$hostname="localhost";
$database=$opt_d;
$user=$opt_u;
$password=$opt_p;
$adminpwd=$opt_a;
$dsn="DBI:$driver:database=nodetracker;host=$hostname";
$dsn2="DBI:$driver:database=mysql;host=$hostname";
$dbh=DBI->connect($dsn,"root",$adminpwd);
$dbh2=DBI->connect($dsn2,"root",$adminpwd);

if ($opt_o eq "a"){
	#add new user
	$sql="insert into Logins(dbname,rwuser,rwpwd,active) values('$database','$user','$password',1)";
	print "$sql\n";
	$sth=$dbh->prepare($sql);
	$sth->execute();

	
	$sql="INSERT INTO user VALUES('%','$user',PASSWORD('$password'),'N','N','N','N','N','N','N','N','N','N','N','N','N','N','NONE','','','')";
	print "$sql\n";
	$sth=$dbh2->prepare($sql);
	$sth->execute();

	$sql="INSERT INTO db VALUES('','$database','$user','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y')";
	print "$sql\n";
	$sth=$dbh2->prepare($sql);
	$sth->execute();

}else{
	$sql="update Logins set rwpwd='$password' where dbname='$database' and rwuser='$user'";
	print "$sql\n";
	$sth=$dbh->prepare($sql);
	$sth->execute();

	$sql="update user set password=PASSWORD('$password') where user='$user'";
	print "$sql\n";
	$sth=$dbh2->prepare($sql);
	$sth->execute();

}

$sth->finish();
$dbh->disconnect();
$dbh2->disconnect();

$cmd="mysqladmin --password=$adminpwd flush-privileges";
print "$cmd\n";
system($cmd);




