#!/usr/bin/perl -w
##########################################################################################################################################
# Program: probe.pl
# Author:  Christopher Hanes
# Revision: 0.6.1
# Changelog:
# 08/01/01:v0.2.0  rewrote to support nonblocking SNMP queries resulting in drastic speed improvements
# 08/06/01:v0.2.1  added collection of interface descriptions
# 08/14/01:v0.2.2  added handler for SNMP timeouts
# 08/16/01:v0.2.3  added standard deviation monitoring; for specified OIDs, values for 1 Hour are stored in the HourlyValues table;
#			new values are then compared against the 1 hour average for the OID using traditional statistical methods.
# 08/16/01:v0.2.4  added email notification support of OIDs outside above range; values are now stored in HourlyValues for 2 hours vs 1
# 08/20/01:v0.2.5  floored min value and ceiled max value
# 09/25/01:v0.2.6  added IP address to email notification
# 10/28/01:v0.2.7  delete everything older than 1 week since everything is rrd archived.
# 10/31/01:v0.2.8  modified code to use Mail::Sendmail package for win2k compatibility
#		   support for nodetracker.conf config file
# 11/01/01:v0.2.9  output now directed to log file
# 11/09/01:v0.2.10 changes to improve ease of startup from different calling paths
# 12/12/01:v0.2.11 support for encrypted SNMP community strings
# 12/19/01:v0.3.0  support for running against an encrypted database
# 01/24/02:v0.4.0  walk.pl converted to package walk.pm and integrated into probe.pl
# 01/24/02:v0.4.1  deleteOld removed
# 01/25/02:v0.5.0  integration with nmap using the newly created nmap.pm
# 02/15/02:v0.5.1  SendEmail function call not working; added to export list in globals.pm
# 03/05/02:v0.5.2  support for scheduling of walks and autodiscoveries
# 03/07/02:v0.6.0  fixed all perl warnings
# 06/04/02:v0.6.1  fixed problem causing crash when running against empty database
##########################################################################################################################################
#    Copyright (C) 2001  Christopher A. Hanes
#    
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or   
#    (at your option) any later version.
#    
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of 
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
#    GNU General Public License for more details.
#    
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#    
#########################################################################################################################################
use Socket;
use Net::SNMP(qw(snmp_event_loop oid_lex_sort));
use Date::Format qw(time2str);
use POSIX qw(ceil floor);

### this section common to all code
($path,$program)=&getPathInfo();

#this must loaded first in order for other packages to work correctly
use globals;

globals::Initialize($path,$program);
require walk;
require mycrypt;
require nmap;

$timeunit=600;

$dbh = DBI->connect($globals::dsn,$globals::user,$globals::password);

mycrypt::Initialize($dbh);

my $key;
my $keyvalid;


my $sth;

my $i=1; 	#interval counter used to determine when to fetch OID Descriptions

walk::main($dbh);  
exit;
while(1){
	$key=$globals::key;
	#need to do this each time in case key has changed and to know if data is encrypted
	$keyvalid=mycrypt::verifyKey($key);
	if ($keyvalid==0){
        	print "You must specify a correct cipher key on the command line in the form of -k key.\nPerhaps you have changed your key?\n";
	        exit;
	}
	nmap::Initialize($dbh,$keyvalid,$key);

	&maybeSleep();
	&Probe();
	#should we do a walk?
	$now=time();
	$hour=time2str("%k",$now);
	$minute=time2str("%M",$now);
	print "The hour is $hour and the minute is $minute\n";

	$sql="select scheduleWalk,scheduleDiscovery from EncryptionStatus";
	$sth=$dbh->prepare($sql);
	$sth->execute();
	$r=$sth->fetchrow_hashref();
	
	if( ($r->{scheduleWalk}==1) || (($hour==11)||($hour==0))&&($minute<10)){
		walk::main($dbh);
	}	

	if( $r->{scheduleDiscovery}==1){
		$cmd=$path."autodiscover.pl -u $globals::user -p $globals::password -d $globals::database -k $globals::key &";
		print $cmd;
		system($cmd);
	}
	


}

$sth->finish();
$dbh->disconnect();

sub Probe(){
	#do all queries on Custom OIDs
	Log("Starting SNMP queries...$i\n\n");

	$sql="select ifDescShortOID,OID_Instances.shortoid,refid,oid,descriptionoid,public,monitorSTD,PrimaryIP,OID_Instances.MAC from 
		OID_Instances left join 
		Devices 
		on 
		Devices.MAC=OID_Instances.MAC left 
		join 
		SNMP_OID on SNMP_OID.shortoid=OID_Instances.shortoid where PrimaryIP is not null order by OID_Instances.MAC,OID_Instances.shortoid";

	print $sql;
	$sth=$dbh->prepare($sql);
	$sth->execute();
	my @sessions=();

	$timestamp=int(time()/$timeunit)*$timeunit;
	$intervaltimespan=7200;	#2 hours
	$hourtop=int($timestamp/$intervaltimespan)*$intervaltimespan;
	$interval=($timestamp-$hourtop)/$timeunit;
	$sql="delete from HourlyValues where timeinterval=$interval";
	$sth2=$dbh->prepare($sql);
	$sth2->execute();
	Log("Interval: $interval\t$hourtop\t$timestamp\n");

	my $r=$sth->fetchrow_hashref();
	while($r){
		$shortoid=$r->{shortoid};
		$refid=$r->{refid};
		$oid=$r->{oid};
		$oiddescription=$r->{descriptionoid};

		$ip=$r->{PrimaryIP};

		if ($keyvalid==3){
			#need to decrypt IP address
			$ip=mycrypt::cryptText(0,$ip,$key);
		}
        	$community=mycrypt::cryptText(0,$r->{public},$key);
		#print "$ip $community\n";
        	my ($session, $error) = Net::SNMP->session(
	                -hostname  => $ip,
        	        -community => $community, 
                	-port      => 161,
			-nonblocking => 0x1
        	);
		
		if (!defined($session)) {
			#print $ip."\n";
			Log("ERROR: $error\n");

	        	 foreach $s(@sessions) { $s->[0]->close(); }
		         exit 1;
      		}

		my @other=($refid,$shortoid,$oid,$oiddescription,$timestamp,$interval,$r->{monitorSTD});
		my $otherptr=\@other;
		#print "other $otherptr $otherptr->[1]\n";
		push(@sessions,[$session,$otherptr]);
		$r=$sth->fetchrow_hashref();	
	}

	foreach $s(@sessions) {
		$otherptr=$s->[1];
		$oid=$otherptr->[2];
		#print "$s->[0]\t$otherptr->[2]\n";
		#$s->[0]->timeout(20);
		$s->[0]->translate(0);
	        $s->[0]->get_table(
	             -baseoid => $oid,
	             -callback    => [\&SaveTable, $s->[1]]
	        );
	}

	# 12 * 10 minutes = every 2 hours grab OID Descriptions
	if ($i==12) {
		#we need to grab the OID Descriptions this time as well
		Log("Grabbing OID Descriptions\n");
		foreach $s(@sessions) {
	        	$otherptr=$s->[1];
		        $oiddescription=$otherptr->[3];
			if ($oiddescription ne ""){
			        $s->[0]->get_table(
        			     -baseoid => $oiddescription,
	        		     -callback    => [\&SaveDescriptionTable, $s->[1]]
		        	);
			}

		}

		#reset i;
		$i=1;
	}


	# Enter the event loop - this gets things going and the query results sent to SaveTable
	snmp_event_loop();

	calculateSTD();

	$i=$i+1;
}


sub SaveTable(){
	my ($session,$otherptr)=@_;
	#print $session->hostname()."\n";
	my @tmp=();
	my $emailHandler;
	my ($ifvalue,$ifnum,$max,$min);
	my $response = $session->var_bind_list;
	my $timestamp=$otherptr->[4];
	my $refid=$otherptr->[0];
	my $shortoid=$otherptr->[1];
	my $interval=$otherptr->[5];
	my $monitorSTD=$otherptr->[6];
	my ($r,$sth);
	my $lasterror="";
	if (!defined($session->var_bind_list)){
		$lasterror=$session->error();
		print "Not defined $refid\n";
	}else{
		
		#print "Defined $refid\n";
	        foreach $oid(keys(%{$response})) {
        	        $ifvalue=$response->{$oid};
                	(@tmp)=split(/\./,$oid);
	                $ifnum=$tmp[$#tmp];

			#add to RawSNMP
			$sql="insert into RawSNMP(refid,shortoid,timestamp,ifnum,value) values($refid,$shortoid,$timestamp,$ifnum,$ifvalue)";
			#if($refid==47){
			#	print "$sql\n";
			#}

			$sth=$dbh->prepare($sql);
			$sth->execute();

			if ($monitorSTD==1){
				#check for out of bounds value
				$sql="select avg,std from OID_Instance_D where refid=$refid and ifnum=$ifnum";
				$sth=$dbh->prepare($sql);
				$sth->execute();
				$r=$sth->fetchrow_hashref();

				if ($r&&defined($r->{avg})){
					$max=$r->{avg}+3*$r->{std};
					$min=$r->{avg}-3*$r->{std};
					$min=floor($min);
					$max=ceil($max);
					if ($min<0){
						$min=0;
					}
					if (($ifvalue<$min)||($ifvalue>$max)){
						SendMessage($refid,$ifnum,$ifvalue,$min,$max);	
					}


				}


				#add to HourlyValues
				$sql="insert into HourlyValues(refid,ifnum,timeinterval,value) values($refid,$ifnum,$interval,$ifvalue)";
				$sth=$dbh->prepare($sql);
				$sth->execute();	


			}
			
        	}
	}
	if ($keyvalid==3){
		$lasterror=cryptText(1,$lasterror,$key);
	}
	$sql="update OID_Instances set lasterror=\"$lasterror\",lasttime=$timestamp where refid=$refid";
	#print "$sql\n";
	$sth=$dbh->prepare($sql);

	$sth->execute();
	$sth->finish();
	$s->close();

}
sub SaveDescriptionTable(){
	
        my ($session,$otherptr)=@_;
        #print $session->hostname()."\n";
        #print $otherptr->[2]."\n";
        my @tmp=();
        my ($ifvalue,$ifnum);
        my $response = $session->var_bind_list;
        my $timestamp=time();
	my $refid=$otherptr->[0];
        my $shortoid=$otherptr->[1];
        my $sth;
  	Log("Saving Descriptions for $refid $keyvalid\n");
        foreach $oid(keys(%{$response})) {
                $ifvalue=$response->{$oid};
		#if ($keyfield==3){
			#we need to encrypt the text
		#	$ifvalue=cryptText(1,$ifvalue,$key)
		#}
                (@tmp)=split(/\./,$oid);
                $ifnum=$tmp[$#tmp];
		#print "$ifnum\t$ifvalue\n";
		$sql="update OID_Instance_D set ifdescr=\"$ifvalue\" where refid=$refid and ifnum=$ifnum";
                $sth=$dbh->prepare($sql);
                $sth->execute();
		if ($sth->rows==0){
			$sql="insert into OID_Instance_D(refid,ifnum,ifdescr) values($refid,$ifnum,\"$ifvalue\")";
			$sth=$dbh->prepare($sql);
			$sth->execute();
		}

        }
                             
        $sth->finish();
        $s->close();
}



sub maybeSleep(){
	#we want to start the queries on at the beginning of each new time cycle defined by the top of the hour and $timeunit
	#for example, if $timeunit is 300 (5 minutes) then, we need to start queries at 10:00, 10:05, 10:10, etc.

	my $sql="select count(*) as c from Devices where active=1 and runNMAP=1";
	my $sth=$dbh->prepare($sql);
	$sth->execute();
        my $r=$sth->fetchrow_hashref();
	my $nmaphosts=$r->{c};
	if($nmaphosts>0){
		my $nmaprate= $timeunit/($globals::conf{nmapInterval}*24*3600/$nmaphosts);
		my $random=rand;
		print "Nmap rate $nmaprate $nmaphosts $random\n";
		if($random<=$nmaprate){
			print "Starting nmap...\n";
			nmap::scanNext(1);

		}
		
	}

	$sth->finish();


	$t=time();
	my $nomoresleep=0;
	$nextStartTime=(int($t/$timeunit)+1)*$timeunit;
	while( ( ($t=time())<$nextStartTime)&&($nomoresleep==0)){
		$delta=($nextStartTime-$t);
		Log("Need to sleep a little longer for $delta seconds...\t");
		$sleeptime=int(.9*$delta);
		if ($sleeptime>5){
			Log("Sleeping for $sleeptime.\n");
			sleep($sleeptime);
		}else{
			sleep(10);
			Log("Done sleeping\n");
			$nomoresleep=1;
		}
	}
}

sub calculateSTD(){
	$s=time();
	my ($r,$r2,$sth,$sth2,$sql);
	my $limit=10;
	$sql="select avg(value) as a,std(value) as s,ifnum,refid from HourlyValues group by refid,ifnum order by 
refid,ifnum";

	$sth=$dbh->prepare($sql);
	$sth->execute();
	$r=$sth->fetchrow_hashref();
	while ($r){
		$sql="update OID_Instance_D set avg=$r->{a}, std=$r->{s} where refid=$r->{refid} and ifnum=$r->{ifnum}";
		$sth2=$dbh->prepare($sql);
		$sth2->execute();
		if ($sth2->rows==0){
			$sql="insert into OID_Instance_D(refid,ifnum,avg,std) values($r->{refid},$r->{ifnum},$r->{a},$r->{s})";
			$sth2=$dbh->prepare($sql);
			$sth2->execute();
		}
		$sth2->finish();

		$r=$sth->fetchrow_hashref();
	}
	$sth->finish();

	$t=time()-$s;
	Log("$t seconds to calculate std deviation\n");

}
sub SendMessage($){
	my $refid=shift;
	my $ifnum=shift;
	my $value=shift;
	my $min=shift;
	my $max=shift;
	my ($sql,$sth,$r);
	my $emailHandler;
	my $body;
	$sql="select Devices.PrimaryIP,Devices.Description as device,IFDescriptions.Description as interface,SNMP_OID.description as 
oid
		 from Devices 
		left join IFDescriptions on IFDescriptions.IP=Devices.PrimaryIP and ifnum=$ifnum 
		left join OID_Instances on OID_Instances.MAC=Devices.MAC left join SNMP_OID on 
		SNMP_OID.shortoid=OID_Instances.shortoid where refid=$refid";
	
	$sth=$dbh->prepare($sql);
	$sth->execute();
	$r=$sth->fetchrow_hashref();
	$subject="$r->{device} $r->{interface}";

	$body="\nIP: $r->{PrimaryIP}\n$r->{oid}\nInterface: $ifnum\nGot: $value\nExpected: $min - $max";
	SendEmail($subject,$body);
	$sth->finish();


}



sub round {
    my($number) = shift;
    return int($number + .5);
}



sub getPathInfo(){
        #include this routing in all modules
        #determine path program was executed from so we know where to include nodetracker packages from
        $path=$0;
        if (index($path,"/")>=0){
                $separator="/";
        }elsif(index($path,"\\")>=0){
                $separator="\\";
        }
        $pos=0;
        while( ($pos=index($path,$separator,$pos))>=0){
                $lastpos=$pos;
                $pos++;
        }
        $program=substr($path,$lastpos+1);
        $path=substr($path,0,$lastpos+1);

	#important!!
	push(@INC,$path);

        return ($path,$program);
}

