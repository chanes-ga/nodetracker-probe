##########################################################################################################################################
# Program: walk.pm
# Author:  Christopher Hanes
# Revision: 1.4.0
# Changelog:
# 09/14/01: modified VerifyPrimaryIP
# 09/20/01: v0.2.0 finished major rewrite of entire code to support non-blocking SNMP queries.  
# 09/20/01: v0.3.0 parallelized reverse lookups using IO-Selects; DNS lookup time reduced from 3 minutes to 30 seconds or less
# 10/08/01: v0.3.1 added physAddress collection into IFDescriptions table; added lastactive field to Devices table
# 10/11/01: v0.3.2 fixed bug: need to clean out RouterIP table at beginning to eliminate stagnate info hanging around
# 10/30/01: v0.3.3 eliminated need for Net::IP package
# 10/31/01: v0.3.4 support for nodetracker.conf config file
# 11/09/01: v0.3.5 improved ease of startup from different calling paths
# 12/14/01: v0.4.0 support for encrypted SNMP community strings and database encryption
# 12/19/01: v0.4.1 added procedure SaveRouterIFs to pull extended descriptions from user-specified location
# 01/17/01: v0.4.2 fixed bug so that FindUnknownDevices inserts new Devices with encrypted public strings
# 01/24/02: v0.5.0 walk.pl becomes walk.pm, a fully functional package, that can be integrated with probe.pl
# 02/18/02: v0.5.1 added lastupdated field to RouterIPs to prevent IPAllocations from being screwed up by temporary network outages
# 03/05/02: v0.5.2 time tracking of most recent run
# 03/07/02: v0.6.0 fixed all perl warnings
# 05/10/02: v0.6.1 added lastupdated field to Port table to allow for cleaning out old data periodically
# 06/04/02: v0.6.2 fixed problem in StorePorts to correlate BRIDGE MIB ifnum to normal MIB-2 interfaces ifnums; normally they are the 
#		   the same but they are not in certain switches (such as Cisco)
# 08/03/04: v1.0.0 added lastupdated field to IFDescriptions
# 08/05/04: v1.0.1 added use strict and fixed resulting problems
# 08/06/04: v1.0.2 FindUnknownDevices eliminated; IPs from RouterInterfaces now stored in IP table with sourceType=1
# 08/12/04: v1.1.0 Added to code to determine switch topography (ie. details of crossover connections)
# 08/13/04: v1.1.1 Crossover discovery moved to separate package
# 08/17/04: v1.2.0 Crossover identification moved to Crossover.pm; stripped old code out of StorePorts
# 08/26/05: v1.2.1 Minor bug fixes
# 08/29/05: v1.3.0 ping of IP blocks before walk to improve results
# 09/01/05: v1.4.0 eliminated dependency upon Devices.active and added procedure UpdateLastActive in walkfuncs
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
package walk;

use globals;
use Net::SNMP(qw(snmp_event_loop oid_lex_sort));
use Net::DNS;
use IO::Select;
use walkfuncs;
use Crossover;
use strict;

#All the data structures local to this package
my $dbh;
my $key;
my $keyvalid;
my $defaultcommunity;
my $lastactive;
my @sessions=(); 
my %routerIPs=();
my %ifs=();
my %ports=();
my %arpTable=();
my %forward=();
my $res = new Net::DNS::Resolver;
my $sel = new IO::Select();

my @allDevices=(
	 	 [$globals::IFDescriptionOID, 	[\%ifs,"descr",1] ]
		,[$globals::IFSpeedOID, 	[\%ifs,"speed",1] ]
		,[$globals::IFPhysAddressOID, 	[\%ifs,"physAddress",1] ]
		,[$globals::IFOpStatusOID, 	[\%ifs,"opstatus",1] ]
	);		
my @allSwitches=(
		 [$globals::switchPortTypeTableOID, 	[\%ports,"type",6] ]
		,[$globals::switchPortTableOID, 	[\%ports,"port",6] ]
		,[$globals::switchPortIFIndex, 		[\%ports,"offset",1] ]

	);
my @allRouters=(
		 [$globals::routerOID,		[\%arpTable,  "mac",    5] ]
		,[$globals::routerIPOID,	[\%routerIPs, "address",4] ]
		,[$globals::routerIPMaskOID,	[\%routerIPs, "mask",   4] ]
		,[$globals::routerIPIfnumOID,	[\%routerIPs, "ifnum",  4] ]
	);






sub main($){
	#main procedure that initiates walk of layer 2/3 devices
	$dbh=shift;
	walkfuncs::Initialize($dbh);
	$key=$globals::key;
	$defaultcommunity=mycrypt::cryptText(1,"public",$key);


	$lastactive=time();
	$keyvalid=mycrypt::verifyKey($key);

	if ($keyvalid==0){
		print "You must specify a correct cipher key on the command line in the form of -k key.\n";
		#exit;
	}elsif($keyvalid==$globals::stateEncrypted){
		#data is encrypted; need to unencrypt
		mycrypt::cryptAll(0,$key);	
	}

	#nmap::Initialize($dbh,$keyvalid,$key);
	#nmap::pingNetworks();
	
	my $daybeforeyesterday=time()-2*24*3600;
	ClearTable("delete from Crossovers where lastupdated<".($lastactive-3600*24*14) );
	ClearTable("delete from Port where lastupdated<".($lastactive-3600*24*14) );
	ClearTable("delete from MACData where lastupdated<".($lastactive-3600*24*14) );

	#ClearTable("update Devices set active=0 where type not in($globals::typeRouter,$globals::typeSwitch)");
	ClearTable("delete from IP");
	ClearTable("delete from RouterIPs where IP not in('0','1') and lastupdated<$daybeforeyesterday");
	ClearTable("delete from IFDescriptions where lastupdated<$daybeforeyesterday");

	my $sql="select nodeID,oid,MAC,PrimaryIP as IP, public,type from Devices left join SNMP_OID on SNMP_OID.shortoid=Devices.ifDescShortOID 
			where type in($globals::typeRouter,$globals::typeSwitch)";
	my $sth=$dbh->prepare($sql);
	$sth->execute();
	my $r=$sth->fetchrow_hashref();
	my $i=0;
	my $mac;
	my $nodeID;
	my $ip;
	my $community;
	my $s;
	print "Found ".$sth->rows." SNMP devices to walk.\n";	
	while($r){
		$mac=$r->{MAC};
		$nodeID=$r->{nodeID};
		$ip=$r->{IP};
		$community=mycrypt::cryptText(0,$r->{public},$key);
		Log("Community for $ip is $community\n");
		#print $r->{MAC}."\n".$r->{public}."|\t".length($community)."\t".$community."\n";
		CheckForInOutOIDs($nodeID);
	        my ($session, $error) = Net::SNMP->session(
        	        -hostname  => $ip,
	                -community => $community,
        	        -port      => 161,
                	-nonblocking => 0x1
	        );
		if (!defined($session)) {
	        	Log("ERROR: $error\n");          
     				foreach $s(@sessions) { $s->[0]->close(); }
	         	exit 1;
      		}
	        my @other=($r->{type},"dummy",$r->{oid});
	        my $otherptr=\@other;
	        push(@sessions,[$session,$otherptr]);	
		$r=$sth->fetchrow_hashref();
		$i++;
	}
	$sth->finish();
	my $otherptr;
	my $type;
	foreach $s(@sessions) {
	        $otherptr=$s->[1];
        	$type=$otherptr->[0];
		PrepareSNMPCalls($s->[0],\@allDevices);
		if ($type==$globals::typeSwitch){
			PrepareSNMPCalls($s->[0],\@allSwitches);
		}elsif ($type==$globals::typeRouter){
			PrepareSNMPCalls($s->[0],\@allRouters);
		}
		if (defined($otherptr->[2])){
			#????? need my?
        	        $s->[0]->get_table(	
	                     -baseoid => $otherptr->[2],
        	             -callback    => [\&SaveRouterIFs,$otherptr->[2]]
	                );
		
		}
	}

	snmp_event_loop(); 
	StoreIfDescriptions();
	StoreRouterIPs();
	StorePorts();
	StoreIP();

	IdentifyUnusedIPBlocks();
	DoReverseLookups();
	#FindCrossovers($dbh);
	#VerifyPrimaryIP();
	UpdateLastActive();

	foreach $s(@sessions) { $s->[0]->close(); }
	

	if($keyvalid==$globals::stateEncrypted){
		#data was encrypted when we started so we need to encrypt it back
		mycrypt::cryptAll(1,$key);
	}

	$sql="update EncryptionStatus set scheduleWalk=0,lastWalk=".time();
	$sth=$dbh->prepare($sql);
	$sth->execute();
	Log("************** DATABASE UPDATED ***************\n");

}


sub SaveRouterIFs(){
        my ($value,$ip);
        my ($key,$i);
        my ($session,$baseoid)=@_;
	my $lasterror;
	my $response;
	my $oid;
        $ip=$session->hostname;
	
	my $sql="delete from RouterIFs where ip='$ip'";
	my $sth=$dbh->prepare($sql);
	$sth->execute();

	Log("Saving Extended Descriptions for $ip using $baseoid\n");
        if (!defined($session->var_bind_list)){
                $lasterror=$session->error();
                Log("$ip\t$lasterror\n");
        }
                        
        $response = $session->var_bind_list;
        foreach $oid(oid_lex_sort(keys(%{$response}))) {
		$key=substr($oid,length($baseoid)+1);
		$sql="insert into RouterIFs values('$ip',$key,\"$response->{$oid}\")";
		$sth=$dbh->prepare($sql);
		$sth->execute();
		
	}
	$sth->finish();
}


sub ProcessLookups(){
	my ($ip,$rr,$packet,$host,$sth2);
	my $timeout=5;
	my @answer=();
	my @ready=();
	my $sock;
	my $sql;
	
	while (@ready = $sel->can_read($timeout)) {
        	foreach $sock (@ready) {
	                $packet = $res->bgread($sock);
        	        @answer=$packet->answer;
                	#print $#answer."\n";
	                foreach $rr(@answer){
				$ip=$forward{$sock};
                	        $host=$rr->ptrdname;
                		$sql="update IP set DNS='$host' where IP='$ip'";
      			       	#print $sql."\n";
                		Log(".");
                		$sth2=$dbh->prepare($sql); 
                		$sth2->execute();
	                }
        	        $sel->remove($sock);
                	$sock->close();
	        }	
	}
}
sub DoReverseLookups(){
        my ($sql,$sth,$r,$ip,$s,$i);
	my $maxlookupqty=50;
        Log("ReverseLookups\n");   
        $s=time();
        $sql="select IP from IP";
        $sth=$dbh->prepare($sql);
        $sth->execute();
        $r=$sth->fetchrow_hashref();
	$i=0;
        while($r){
                $ip=$r->{IP};
        	my $bgsock = $res->bgsend($ip,"PTR");
		#print "Adding $ip to $bgsock\n";
        	$forward{$bgsock}=$ip;
		$sel->add($bgsock);
                $r=$sth->fetchrow_hashref();
		if ($i==$maxlookupqty){
			ProcessLookups();
			$i=0;
		}
		$i=$i+1;
        }

	#close off any remaining handles;
	my @h=$sel->handles;
	foreach my $sock(@h){
	        $sock->close();
	}  
        Log("\n\n");
	Log(time()-$s." s for reverse lookups to complete\n");
}

sub PrepareSNMPCalls($$){
	my ($ptr, $oid, $argptr);
	my $tmp;
	my $session=shift;
	my $listptr=shift;
	my @snmpArgs=@$listptr;
	
        foreach $ptr(@snmpArgs){
                $oid=$ptr->[0];
                $argptr=$ptr->[1];
                $session->get_table( 
                     -baseoid => $oid,
                     -callback    => [\&ProcessSNMPResults, $argptr]
                );
        }
}

sub StoreIP(){
	my ($routerip,$ip,$sth,$mac,$ifnum,$int_ip,$host,$sql);
	my @tmp=();
	Log("StoreIP: Start\n");
	foreach $routerip(keys %arpTable){
		Log("Storing IP Table from $routerip\n");
		my @ips=keys %{ $arpTable{$routerip}{mac} };
		foreach $ip(@ips){
			$mac=$arpTable{$routerip}{mac}{$ip};
			Log("ip: $ip  mac: $mac\n");

			($ifnum,@tmp)=split(/\./,$ip);
			$ip=join("\.",@tmp);


			$mac=fixMAC($mac);
			if (length($mac)>0){
				#ARP table by definition better have a valid MAC
				$int_ip=toAddress($ip);			

		                $sql="insert into IP(ip,address,mac,routerif,sourceIP) values('$ip',$int_ip,'$mac',$ifnum,'$routerip')";
        	        	Log("$sql\n\n");
	        	        $sth=$dbh->prepare($sql);
        	        	$sth->execute();
				Log("a");	
			}
		}
		Log("\n");
		$sth->finish();
	}
		

}
sub StoreOnePort($$$$){
	my $ip=shift;
	my $mac=shift;
	my $ifnum=shift;
	my $mactype=shift;
	my $sql;
	my $sth;
	#print "ip=$ip\tmac=$mac\tif=$ifnum\t$mactype\tlast=$lastactive\n";

	#mactype=3 == a learned address

	Log("p");

	$mac=HexMac($mac);
                        
	if ($mactype==3){
        	$sql="insert into Port(switch,ifnum,mac,lastupdated) values('$ip',$ifnum,'$mac',$lastactive)";
	        $sth=$dbh->prepare($sql);
        	$sth->execute();
        }else{
        	Log("\nAddress not learned: $mac\n");
	}
	#store everything in tmp table MACData so we can figure out crossover connections
	$sql="insert into MACData(switch,ifnum,mac,lastupdated)values ('$ip',$ifnum,'$mac',$lastactive)";
	$sth=$dbh->prepare($sql);
	$sth->execute();
}
sub StorePorts(){
	my ($ip,$r,$sth,$sth2,$sql,$mactype,$ifnum,$maxIf,$i,$newifnum,$mac);
	my @macs=();
	$maxIf=0;
	foreach $ip(keys %ports){
		Log("Storing Ports for $ip\n");
		@macs=keys % { $ports{$ip}{type} };
		#Log("$ip: @macs\n");
	        ClearTable("delete from Port where Switch='$ip'");
	        ClearTable("delete from MACData where Switch='$ip'");
		my @addressCount=();

		foreach $mac(@macs){
			$ifnum=-1;
			$newifnum=-1;
			$mactype=$ports{$ip}{type}{$mac};
			$ifnum=$ports{$ip}{port}{$mac};	#this may not be the real ifnum
			#print "Testing: $ifnum\t$newifnum\n";
			if(defined($ifnum)){
				$newifnum=$ports{$ip}{offset}{$ifnum};  #this will grab the real ifnum
				if (defined($newifnum)){
					#print "Testing2: $ifnum\t$newifnum\n";
					$ifnum=$newifnum;
				}
				StoreOnePort($ip,$mac,$ifnum,$mactype);
			}

		}
		Log("\n");
	}
	#clean out ports with multiple macs on them (ie will later be identified as crossovers)
	$sql="select count(*) as c,Switch,ifnum from Port group by Switch,ifnum having c>1";
	$sth=$dbh->prepare($sql);
	$sth->execute();
	$r=$sth->fetchrow_hashref();
	while($r){
		$sql="delete from Port where Switch='$r->{Switch}' and ifnum=$r->{ifnum}";
		Log("$sql\n");
		$sth2=$dbh->prepare($sql);
		$sth2->execute();
		$r=$sth->fetchrow_hashref();
	}

}
sub StoreRouterIPs(){
	my ($routerip, $sql,$sth,$mask,$ifnum,$int_ip,$int_mask,$int_network,$now);
	$now=time();
	Log("StoreRouterIPs: Start\n");
	foreach $routerip(keys %routerIPs){
		Log("Storing Router IP info for $routerip\n");
		
		my @addresses=keys %{ $routerIPs{$routerip}{address} };

		foreach my $ip(@addresses){
			$mask=$routerIPs{$routerip}{mask}{$ip};
			$int_ip=toAddress($ip);
			$int_mask=toAddress($mask);
			$int_network= $int_ip&$int_mask;
			$ifnum=$routerIPs{$routerip}{ifnum}{$ip};
			#print "$routerip\t$ip\t$int_ip\t$mask\t$int_mask\t$int_network\n";
			
			$sql="update RouterIPs set lastupdated=$now, ifnum=$ifnum,
					mask=$int_mask where IP='$routerip' and network=$int_network";
			$sth=$dbh->prepare($sql);
			$sth->execute();



			if ($sth->rows==0){
		                $sql="insert into RouterIPs(IP,ifnum,address,mask,network,lastupdated)
        		                values('$routerip',$ifnum, $int_ip,$int_mask,$int_network,$now)";
				#print $sql."\n";
	                	$sth=$dbh->prepare($sql);
        	        	$sth->execute();		
			}
			#test
			$sql="insert into IP(IP,routerif,address,sourceType,sourceIP)
				values('$ip',$ifnum,$int_ip,1,'$routerip')";
			Log("$sql\n");
	                $sth=$dbh->prepare($sql);
        	        $sth->execute();

			Log("r");
		}


		#$sth->finish();
		Log("\n");
	}
	#fill in MAC where possible...
	$sql="update IP,IFDescriptions set IP.MAC=physAddress where IP.sourceIP=IFDescriptions.IP and 
		IP.routerif=IFDescriptions.ifnum and sourceType=1";
	$sth=$dbh->prepare($sql);
        $sth->execute();


}
sub StoreIfDescriptions(){
	my ($sth,$sql,$ip,$ifdescr,$ifspeed,$ifOpStatus,$ifnum,@ifnums,$ifPhysAddress);
	my $now=time();
	
	foreach $ip(keys %ifs){
		Log("Storing if info for $ip\n");
		@ifnums=keys %{ $ifs{$ip}{descr} };

		ClearTable("delete from IFDescriptions where IP='$ip'");

		foreach $ifnum(@ifnums){
			$ifdescr=$ifs{$ip}{descr}{$ifnum};
			$ifspeed=$ifs{$ip}{speed}{$ifnum}/8;
			$ifOpStatus=$ifs{$ip}{opstatus}{$ifnum};
			$ifPhysAddress=$ifs{$ip}{physAddress}{$ifnum};
			if($ifPhysAddress!~m/\w+/){
				$ifPhysAddress="";
			}
			if(length($ifPhysAddress)==14){
				$ifPhysAddress=fixMAC($ifPhysAddress);
			}
			if (!defined($ifOpStatus)){
				$ifOpStatus=0;
			}
			#print "$ip\t$ifnum\t$ifdescr\t$ifspeed\t$ifstatus\n";
		        $sql="insert into IFDescriptions(IP,ifnum,description,speed,opStatus,physAddress,lastupdated) 
				values('$ip',$ifnum,'$ifdescr',$ifspeed,$ifOpStatus,'$ifPhysAddress',$now)";
			Log("$sql\n");
        	        Log("i");
	                $sth=$dbh->prepare($sql);
		        $sth->execute(); 
			
		}	
		$sth->finish;
		Log("\n");

	} 
}


sub ProcessSNMPResults(){
	my ($value,$ip);
	my ($key,$i);
	my @tmp=();
	my ($session,$otherptr)=@_;
	my ($lasterror, $response);
        $ip=$session->hostname;
	
	my $hashptr=$otherptr->[0];
	my $field=$otherptr->[1];
	my $keyparts=$otherptr->[2]-1;

        #print "Getting $field for IP $ip";

        if (!defined($session->var_bind_list)){
                $lasterror=$session->error();
                Log("$ip\t$lasterror\n");
        }
                
        $response = $session->var_bind_list;
        foreach my $oid(oid_lex_sort(keys(%{$response}))) {
                (@tmp)=split(/\./,$oid);
		$key="";
                for ($i=$keyparts;$i>=0;$i--){
                        $key=$key.$tmp[$#tmp - $i]."\.";
                }
		chop($key);
                $value=$response->{$oid};
		$hashptr->{$ip}{$field}{$key}=$value;
		#Log("oid: $oid k: $key\tv: $response->{$oid} $value \n");
		#print ".";
        }                 
	#print "\n";
}

1;
