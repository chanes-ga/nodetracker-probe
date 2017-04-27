#!/usr/bin/perl

##########################################################################################################################################
# Program: icmp.pl
# Author:  Christopher Hanes
# Revision: 1.0.1
# Changelog:
# 12/07/05: v1.0.1 Better tracking of packet loss - not ignoring unreachables anymore
##########################################################################################################################################
use walkfuncs;
use DBI;

#Database settings
$driver="mysql";
$hostname="localhost";
$database="nt_icnet";       
$user="tech";
$password="alef314";
$dsn="DBI:$driver:database=$database;host=$hostname;mysql_client_found_rows=true";



my $dbh = DBI->connect($dsn,$user,$password);


$hostfile="/usr/local/nodetracker/hosts";
$fping="/usr/local/sbin/fping";

clean();
#exit;
while(1){
	scan();
	sleep(50);
}

sub clean(){
	my $monthsToKeep=4;
	my $secondsAgo=$monthsToKeep*30*24*3600;
	my $oldtime=time()-$secondsAgo;
	my $sql="delete from ICMPData where timeblock<$oldtime";
	my $sth=$dbh->prepare($sql);
	$sth->execute();
	print $sth->rows." deleted\n";
	$sth->finish;
	
	
}

sub scan()
{
	#redirect stderr to stdout
	$cmd="$fping -q -c 3 -f $hostfile 2>&1 |";

	$timeblock=time();
	print "time: $timeblock";
	$timeblock=int($timeblock/60)*60; 
	print "-> $timeblock\n";
	open(FD, $cmd);

	while($line=<FD>){
		print $line;
		if($line=~m/^(\d+\.\d+\.\d+\.\d+)\s+\:.*\/(\d+)\%(\n|.*)/){
			$ip=$1;
			$loss=$2;
			$other=$3;
			if(length($other)>1){
				($a,$b)=split(/=/,$other);
				($min,$avg,$max)=split(/\//,$b);
			}
			$ip=toAddress($ip);
			if($loss!=100){
				$min=getIntVal($min);
				$avg=getIntVal($avg);
				$max=getIntVal($max);			
			}else{
				$min=0;
				$avg=0;
				$max=0;
			}
			
			$sql="insert into ICMPData(ip,timeblock,loss,min,mean,max) values($ip,$timeblock,$loss,$min,$avg,$max)";
			print "$1,$timeblock, $loss\n$sql\n\n";

			#print "1:$sql\n";


			$sth=$dbh->prepare($sql);
			$sth->execute();

		}elsif($line=~m/.*Unreachable.*sent to\s+(.*)/){
			#chop($line);
			#$loss=100;
			#$min=5000;
			#$avg=5000;
			#$max=5000;
			#$ip=toAddress($1);
                        #$sql="insert into ICMPData(ip,timeblock,loss,min,mean,max) values($ip,$timeblock,$loss,$min,$avg,$max)";
                        #print "2:$sql\n";
			#$sth=$dbh->prepare($sql);
			#$sth->execute();

		}else{
			#print "out2: $line";

		}
	}
	close(FD);
}


sub getIntVal($){
	my $v=shift;	
	my $r=int($v+.5);
	return $r;

}
