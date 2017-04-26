#!/usr/bin/perl -w
##########################################################################################################################################
# Program: rrdbuilder.pl
# Author:  Christopher Hanes
# Description: archives Mysql data into rrd files for long term storage and access
# Revision: 0.2.1
# Changelog:
# 12/20/01: v0.1.1  When new interfaces appear then that if is not defined in existing RRD and updates start failing; the quick fix
#	    is to delete the RRD, set the lastupdate to 0 and recreate it
# 01/24/02: v0.1.2 deleteOld moved from probe.pl to here
# 03/07/02: v0.2.0 fixed perl warnings; added cleanup of dead MACs to deleteOld
# 11/06/03: v0.2.1 rrd created in basedir if it doesn't exist
#########################################################################################################################################

use DBI;
use Socket;
use Getopt::Std;

getopts('d:u:p:');

$driver="mysql";
$hostname="localhost";
$database=$opt_d;	#as specified on the command line
$user=$opt_u;
$password=$opt_p;
$dsn="DBI:$driver:database=$database;host=$hostname;mysql_client_found_rows=true";

$sleeptime=300;

$basedir="/var/www/html/$database/data";
$rrdtool="/usr/local/rrdtool/bin/rrdtool";
$basetime=300;
$halfhoursteps=1800/$basetime;
$twohoursteps=7200/$basetime;
$daysteps=(24*3600)/$basetime;

$RRAs="RRA:MIN:.5:1:288  RRA:AVERAGE:.5:1:288 RRA:MAX:.5:1:288"; 	#12 samples/hr * 24 hours = 288
# 2 samples/hr * 24 hrs * 7 days = 336
$RRAs=$RRAs." RRA:MIN:.5:$halfhoursteps:336  RRA:AVERAGE:.5:$halfhoursteps:336 RRA:MAX:.5:$halfhoursteps:336";
# 12 samples/day * 30 days = 360
$RRAs=$RRAs." RRA:MIN:.5:$twohoursteps:360 RRA:AVERAGE:.5:$twohoursteps:360 RRA:MAX:.5:$twohoursteps:360";
# 1 sample/day * 365 days = 365
$RRAs=$RRAs." RRA:MIN:.5:$daysteps:365 RRA:AVERAGE:.5:$daysteps:365 RRA:MAX:.5:$daysteps:365";

while(1){


$dbh=DBI->connect($dsn,$user,$password);

$sql="select refid,lastrrdupdate,rrd_dataType from OID_Instances left join SNMP_OID using(shortoid) order by refid";
my $sth=$dbh->prepare($sql);
$sth->execute();
my $r=$sth->fetchrow_hashref();
my $ret;
while($r){
	$updaterrd=1;

	#print "$r->{refid}\t$r->{rrd_dataType}\n";
	$rrdfile=$basedir."/$r->{refid}.rrd";
	print $rrdfile."\n";
	if(($r->{lastrrdupdate}==0)||(!(-e $rrdfile))) {
		$updaterrd=&CreateRRD($r->{refid},$r->{rrd_dataType});		
	}

	if($updaterrd==1){
		#add values to rrd file
		&DoUpdate($r->{refid},$r->{lastrrdupdate});
	}
	$r=$sth->fetchrow_hashref();
}

## delete old stuff
$lastweek=time()-3600*24*7;
&deleteOld($lastweek);  #compress everything between 7 and 30 days ago to 4 hour samples


$dbh->disconnect();


sleep($sleeptime);
}

sub DoUpdate($$){
	my $refid=shift;
	my $lasttime=shift;
	my ($template, $values);
	my $rows;
	my $c;
	my $ret;
	my $error;
	print "Updating RRD for $refid since $lasttime";
	my $sql="select * from RawSNMP where refid=$refid and timestamp>$lasttime order by timestamp,ifnum";
	my $sth=$dbh->prepare($sql);
	$sth->execute();
	my $r=$sth->fetchrow_hashref();
	$prevtime=$r->{timestamp};
	$rows=$sth->rows;
	#print "\n$rows\n";
	$c=0;

	while($c<$rows){
		$error=0;
		#print "on $c/$rows\n";
		$template="--template ";
		$values=$prevtime.":";
		while ($r&&($prevtime==$r->{timestamp})){
			$template=$template."if$r->{ifnum}:";
			$values=$values."$r->{value}:";
			$c++;
			$r=$sth->fetchrow_hashref();
		}
		chop($template);
		chop($values);
		$cmd="$rrdtool update $basedir/$refid.rrd $template $values 2>&1";
		$ret=`$cmd`;
		print $ret;
		chop($ret);
		if (($ret eq "ERROR: Template contains more DS definitions than RRD")||(substr($ret,0,22 )eq "ERROR: unknown DS name")){
			# The # of interfaces has changed; we need to recreate the RRD file
			# This is kind of clunky but works for now
			
			$cmd="rm -f $basedir/$refid.rrd";
			system($cmd);
			#Next iteration will create and populate the rrd file
			$error=1;
		}
		if($r->{timestamp}){
			$prevtime=$r->{timestamp};
		}
		print ".";
	}
	if($rows>0){
		if ($error==0){
			$time=$prevtime;
		}else{
			$time=0;
		}
		$sql="update OID_Instances set lastrrdupdate=$time where refid=$refid";
		#print $sql."\n";
		$sth=$dbh->prepare($sql);	
		$sth->execute();
	}
	print "\n";
	$sth->finish();
}

sub CreateRRD($$){
	my $refid=shift;
	my $datatype=shift;
	my $sql;
	my ($r,$ret);
	$ret=0;
	print "Creating RRD for $refid\n";
	#get start time of data
	$sql="select min(timestamp) as s from RawSNMP where refid=$refid";
	#print $sql."\n";
	my $sth=$dbh->prepare($sql);
	$sth->execute();
	$r=$sth->fetchrow_hashref();

	if ($r->{s}){
		$starttime=$r->{s}-$basetime;
		#print "$database s:$r->{s}\tb:$basetime\n";
		$sql="select distinct ifnum from RawSNMP where refid=$refid order by ifnum";
		$sth=$dbh->prepare($sql);
		$sth->execute();
		if($sth->rows>0){	
			$r=$sth->fetchrow_hashref();
			my $ds="";
			while($r){
				$ds=$ds."DS:if$r->{ifnum}:$datatype:".($basetime*4).":U:U ";
				#print $r->{ifnum}."\n";
				$r=$sth->fetchrow_hashref();
			}	
			$cmd="$rrdtool create $basedir/$refid.rrd --step $basetime --start $starttime $ds $RRAs";
			print $cmd."\n";
			system($cmd);
			$ret=1;
		}
	}
	$sth->finish();
	return $ret;
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

sub deleteOld($)
{               
	my $sth2;
        my $killtime=shift;
        my $sql="delete from RawSNMP where timestamp<$killtime";
        my $sth=$dbh->prepare($sql);
	my $path="/var/www/html/$database/data/";
	my $cmd;
        $sth->execute();
        print "Deleted ".$sth->rows."\n";

	#do general cleanup
	$sql="select refid, OID_Instances.MAC from OID_Instances left join Devices using(MAC) where Devices.MAC is null";
	$sth=$dbh->prepare($sql);
	$sth->execute();
	if ($sth->rows>0){
		$r=$sth->fetchrow_hashref();
		while($r){
			$cmd="rm -f $path$r->{refid}.* $path"."tmp/*.$r->{refid}.*"; 
			system($cmd);
			$sql="delete from OID_Instances where refid=$r->{refid}";
			$sth2=$dbh->prepare($sql);
			$sth2->execute();	
			#print "$cmd\n $sql\n";
			$r=$sth->fetchrow_hashref();
		}
	}
	$sth->finish;


}









