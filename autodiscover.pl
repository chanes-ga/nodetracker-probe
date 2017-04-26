#!/usr/bin/perl -w
##########################################################################################################################################
# Program: autodiscover.pl
# Author:  Christopher Hanes
# Revision: 0.3.0
# Changelog:
# 03/05/02: v0.1.0  formerly nmap.pl, autodiscover.pl does SNMP discoveries only; also updates NodeTracker with changes to SNMP 
# 	    communities on existing devices
# 03/06/02: v0.2.0  major bug fixes; changed to perl -w and fixed alot of warnings
# 03/07/02: v0.3.0  fixed all perl warnings
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
use Net::SNMP;

@hostKeywords=("Linux","Windows");
%devices=();
%ips=();
### this section common to all code
($path,$program)=&getPathInfo();

use globals;

globals::Initialize($path,$program);

require walkfuncs;
require mycrypt;

$key=$globals::key;

$dbh=DBI->connect($globals::dsn,$globals::user,$globals::password);
mycrypt::Initialize($dbh);

$nkey=mycrypt::GetNKey($globals::key);
$keyvalid=mycrypt::verifyKey($key);
if ($keyvalid==0){
        print "You must specify a correct cipher key on the command line in the form of -k key.\n";
        exit;
}

$sql="update EncryptionStatus set scheduleDiscovery=2";
$sth=$dbh->prepare($sql);
$sth->execute();



@snmpstrings=split(/,\s*/,$globals::conf{snmpstrings});

#do autodiscovery
print "Beginning Auto Discover\n";
&autoDiscover();
#&findSNMP("10.0.1.0/28");
&updateDB();
$dbh->disconnect();
Log("--------------SCAN COMPLETED----------------\n");

sub updateDB(){
	my ($public,$mac,$sql,$sth,$ip,$os);
	print "Updating DB\n";
	foreach $mac(keys %devices){
		$public=mycrypt::cryptText(1,$devices{$mac}{community},$key);
		$ip=$devices{$mac}{ip};
		$os=$devices{$mac}{os};
		if($keyvalid==$globals::stateEncrypted){
			$os=mycrypt::cryptText(1,$os,$key);
			$ip=mycrypt::cryptText(1,$ip,$key);
			#important to do mac last since hash has unencrypted mac
			$mac=mycrypt::cryptText(1,$mac,$key);
		}

		$sql="update Devices set public=\"$public\" where MAC=\"$mac\"";
		$sth=$dbh->prepare($sql);
		$sth->execute();
		if ($sth->rows==0){
			#need to add newly discovered device
			$sql="insert into Devices(MAC,PrimaryIP,public,osguess,Description,type,active) 
values(\"$mac\",\"$ip\",\"$public\",\"$os\",\"$ip\",$devices{$mac}{devicetype},1)";
			print $sql;
			$sth=$dbh->prepare($sql);
			$sth->execute();
		}
		#print "$mac\t$devices{$mac}{ip}\t$devices{$mac}{community}\t$devices{$mac}{devicetype}\n$sql\n";
	}


	$sql="update EncryptionStatus set scheduleDiscovery=0,lastDiscovery=".time();
	$sth=$dbh->prepare($sql);
	$sth->execute();
	$sth->finish();

}

sub autoDiscover(){
        my ($sql, $r,$sth1,$i,$ip,$sth2,$r2,$block);
	$sql="select * from IPBlocks order by network";
	$sth1=$dbh->prepare($sql);
	$sth1->execute();
	$r=$sth1->fetchrow_hashref();
	while($r){
		$netbits=toNetBits($r->{mask});
		$network=$r->{network};
		if ($keyvalid==$globals::stateEncrypted){
			$network=mycrypt::doxor($nkey,$network);			
		}
		$network=toIP($network);
		$block="$network/$netbits";
		print "$block\n";
		findSNMP($block);
		$r=$sth1->fetchrow_hashref();
	}
	$sth1->finish();
}
sub findSNMP($){
	#use nmap to check for snmp on host
	my $block=shift;
	my $cmd=$globals::conf{nmap}." -n -sU -p 161 $block |";
	my $foundcommunity=0;
	open(FD,$cmd);
	#print "$cmd\n";
	while($line=<FD>){
		if ($line=~m/Interesting ports on.*\((.*)\).*/){
			$ip=$1;
			print "SNMP running on $ip...";
			#snmp is running on this machine...
			#now try to find correct snmpstring			

			#if ($ips{$ip}!=1){
			if (!defined($ips{$ip})){
				foreach $community(@snmpstrings){
					if ($foundcommunity==0){
						$foundcommunity=tryCommunity($ip,$community);
					}
				}
			}else{
				print "Already scanned device with $ip\n";
			}
			#reset for next device
			$foundcommunity=0;
		}
	}	
	close(FD);
}

sub tryCommunity($){
	my $ip=shift;
	my $community=shift;
	my $devicelayer=0;
	my $os;
	my $cmd;
	my $ret=0;
	my ($session, $error) = Net::SNMP->session(
    		  -hostname  => $ip,
		  -community => $community,
 	          -port      =>  161 
	);

	if (!defined($session)) {
	      	printf("ERROR: %s.\n", $error);
      		exit 1;

   	}

	my $switchPortTableOID=".1.3.6.1.2.1.17.4.3.1.2";
	my $ipif="1.3.6.1.2.1.4.20.1.2"; 
	my $ipaddresses="1.3.6.1.2.1.4.20.1.1";
	my $result=$session->get_table($ipif);

	if (!defined($result)) {
      		#printf("ERROR: %s.\n", $session->error);
   	}else{
		print "Found community $community on $ip...\n";
		my $oid="$ipif.$ip";
		my $ipinterface=$result->{$oid};
		if (!defined($ipinterface)){
                        #must be network or broadcast address
                        print "Found network or broadcast address\n";
                        return $ret;

		}
		#print "IP Interface: $oid $ipinterface\n";
	   	my $ifphysaddress="1.3.6.1.2.1.2.2.1.6.$ipinterface";
		$result=$session->get_request($ifphysaddress);
		$mac=fixMAC($result->{$ifphysaddress});
		if ($mac eq ""){
			print "No MAC!\n";
			return $ret;
		}


		#pull ip addresses so we can skip them later
		$result=$session->get_table($ipaddresses);
        	foreach my $oid(keys(%{$result})  ) {
			$ips{$result->{$oid}}=1;
        	}

		$ret=1;
		#determine device type
		
		#test for layer 2
		$result=$session->get_table($switchPortTableOID);
		if (!defined($result)) {
			#not layer 2; use nmap to guess whether router or host
			$cmd=$globals::conf{nmap}." -O $ip |";
			#print $cmd."\n";
			open(FD2,$cmd);
			my $line;
			while($line=<FD2>){
				if($line=~m/Remote OS guesses:\d*(.*)/){
					$os=$1;
					$devicelayer=getDeviceTypeFromOS($os);
				}				
			}
			close(FD2);
		}else{
			$devicelayer=2;
		}
		$devices{$mac}{ip}=$ip;
		$devices{$mac}{community}=$community;
		$devices{$mac}{devicetype}=$devicelayer;
		$devices{$mac}{os}=$os;
		#print "\tIP If is $ipinterface\n\tPhys Address is $mac\n\tOS:$os\n\tDevice Layer=$devicelayer\n";

   	}

   	$session->close;
	return $ret;
}
sub getDeviceTypeFromOS($){
	my $os=shift;
	my $found=0;
	my $devicetype=0;
	#is is it a host
	foreach $token(@hostKeywords){
		if($found==0){
			$found=index($os,$token)+1;
		}
	}
	if($found!=0){
		#then this is a host
	}else{
		#then this is a router
		$devicetype=3;
	}
	return $devicetype;
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






