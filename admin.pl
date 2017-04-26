#!/usr/bin/perl
#########################################################################################################
# Program: admin.pl
# Author: Christopher A. Hanes
# Revision: 0.0.1
# Changelog:
#########################################################################################################

use DBI;
use Socket;
use Getopt::Std;
use Net::SNMP;

getopts('d:u:p:');

#Connect to database
$driver="mysql";
$hostname="localhost";
$database=$opt_d;
$user=$opt_u;
$password=$opt_p;

#list of tables to copy into new database
@tables=("EncryptionStatus","Devices","Port","IP","IFDescriptions", "nmap","nmap_changelog","IPBlocks",
	"IPAllocations","RouterIPs","RouterIFs","SNMP_OID","OID_Instances","OID_Instance_D","HourlyValues","RawSNMP");

#list of global tables that should be symbolically linked to table in nodetracker database
@symbolictables=("CryptSpecs","SNMP_MIB","SNMP_Value_D","EthernetCodes");

$dsn="DBI:$driver:database=nodetracker;host=$hostname";
$dbh=DBI->connect($dsn,$user,$password);

$basedir="/var/www/html/$database";
$dbdir="/sqldbs/$database";
$srcdir="/sqldbs/nodetracker";
$owner="apache";
$mrtgcfg="$basedir/data";
print "$basedir\n";



if (Exists($basedir)==1||Exists($dbdir)){
	print "already exists";
	#exit(0);
}

$cmd="mkdir $basedir";
$cmd="mkdir $mrtgcfg";

$cmd="mkdir $dbdir";
print "$cmd\n";
system($cmd);

#copy tables to new database
foreach $table(@tables){
	$cmd="cp --target-directory=$dbdir $srcdir/$table.*";
	#print "$cmd\n";
	system($cmd);
}
#symlink to global tables..
foreach $table(@symbolictables){
	$cmd="ln -s $srcdir/$table.* $dbdir/.";
	print "$cmd\n";
	system($cmd);
}



$cmd="chown mysql.mysql $dbdir -R";
Execute($cmd);

$cmd="mkdir $basedir";
Execute($cmd);

$cmd="mkdir $mrtgcfg";
Execute($cmd);

#need tmp dir for custom snmp probe reports
$cmd="mkdir $mrtgcfg/tmp";
Execute($cmd);


$cmd="ln -s /var/www/html/nodetracker $basedir/common";
Execute($cmd);

$cmd="ln -s  /var/www/html/index2.php  $basedir/index.php";
Execute($cmd);

sub Execute($){
	my $cmd=shift;
	print "$cmd\n";
	system($cmd);
	
}

sub Exists($){
	my $fn=shift;
	my $r = -e $fn;
	if ($r==1){
		return 1;
	}else{
		return 0;
	}

}










