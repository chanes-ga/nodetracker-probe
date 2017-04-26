#!/usr/bin/perl
use DBI;
use Getopt::Std;

getopts('p:');

#Connect to database
$driver="mysql";
$hostname="localhost";
$database="nodetracker";       #as specified on the command line
$user="root";
$password=$opt_p;
$dsn="DBI:$driver:database=$database;host=$hostname";

$dbh=DBI->connect($dsn,$user,$password);

$sql="select * from Logins where active=1";
$sth=$dbh->prepare($sql);
$sth->execute();
my $r=$sth->fetchrow_hashref();
while($r){
	$cmd="/sqldbs/nodetracker/scripts/rrdbuilder.pl -d $r->{dbname} -u $user  -p $password &";
	system($cmd);
	$r=$sth->fetchrow_hashref();
}
$sth->finish();
$dbh->disconnect();
