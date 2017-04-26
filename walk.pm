#!/usr/bin/perl
##########################################################################################################################################
# Program: walk.pm
# Author:  Christopher Hanes
# Revision: 0.6.2
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

#All the data structures local to this package
$dbh;
$key;
$keyvalid;
$defaultcommunity;
$lastactive;
@sessions=(); 
%routerIPs=();
%ifs=();
%ports=();
%arpTable=();
%forward=();
$res = new Net::DNS::Resolver;
$sel = new IO::Select();

@allDevices=(
	 	 [$globals::IFDescriptionOID, 	[\%ifs,"descr",1] ]
		,[$globals::IFSpeedOID, 		[\%ifs,"speed",1] ]
		,[$globals::IFPhysAddressOID, 	[\%ifs,"physAddress",1] ]
		,[$globals::IFOpStatusOID, 	[\%ifs,"opstatus",1] ]
	);		
@allSwitches=(
		 [$globals::switchPortTypeTableOID, 	[\%ports,"type",6] ]
		,[$globals::switchPortTableOID, 		[\%ports,"port",6] ]
		,[$globals::switchPortIFIndex, 		[\%ports,"offset",1] ]

	);
@allRouters=(
		 [$globals::routerOID,		[\%arpTable,  "mac",    5] ]
		,[$globals::routerIPOID,		[\%routerIPs, "address",4] ]
		,[$globals::routerIPMaskOID,	[\%routerIPs, "mask",   4] ]
		,[$globals::routerIPIfnumOID,	[\%routerIPs, "ifnum",  4] ]
	);



require walkfuncs;



sub main($){
	#main procedure that initiates walk of layer 2/3 devices

	$dbh=shift;
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
	$daybeforeyesterday=time()-2*24*3600;
	ClearTable("delete from Port where lastupdated<".($lastactive-3600*24*14) );
	ClearTable("update Devices set active=0 where type not in($globals::typeRouter,$globals::typeSwitch)");
	ClearTable("delete from IP");
	ClearTable("delete from RouterIPs where IP not in('0','1') and lastupdated<$daybeforeyesterday");
	$sql="select oid,MAC,PrimaryIP as IP, public,type from Devices left join SNMP_OID on SNMP_OID.shortoid=Devices.ifDescShortOID where type in($globals::typeRouter,$globals::typeSwitch)";
	$sth=$dbh->prepare($sql);
	$sth->execute();
	my $r=$sth->fetchrow_hashref();
	my $i=0;

	while($r){
		$mac=$r->{MAC};
		$ip=$r->{IP};
		$community=mycrypt::cryptText(0,$r->{public},$key);
		print "Community for $ip is $community\n";
		#print $r->{MAC}."\n".$r->{public}."|\t".length($community)."\t".$community."\n";
		CheckForInOutOIDs($mac);
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
        	        $session->get_table(	
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
	IdentifyUnused();
	FindUnknownDevices($defaultcommunity);
	DoReverseLookups();
	VerifyPrimaryIP();

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
	$maxlookupqty=50;
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
	foreach $sock(@h){
	        $sock->close();
	}  
        Log("\n\n");
	Log(time()-$s." s for reverse lookups to complete\n");
}

sub PrepareSNMPCalls($$){
	my ($ptr, $oid, $argptr);
	$session=shift;
	$listptr=shift;
	@snmpArgs=@$listptr;

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
	my ($routerip,$ip,$sth,$mac,$ifnum,$int_ip,$host);
	my @tmp=();

	foreach $routerip(keys %arpTable){
		Log("Storing IP Table from $routerip\n");
		my @ips=keys %{ $arpTable{$routerip}{mac} };
		foreach $ip(@ips){
			$mac=$arpTable{$routerip}{mac}{$ip};
			($ifnum,@tmp)=split(/\./,$ip);
			$ip=join("\.",@tmp);
			$mac=fixMAC($mac);

			$int_ip=toAddress($ip);
			
	                #$host = (gethostbyaddr(pack("C4",split(/\./,$ip)),2))[0];
			#print "$routerip\t$ip\t$int_ip\t$ifnum\t$mac\n";

	                $sql="insert into IP(ip,address,mac,routerif) values('$ip',$int_ip,'$mac',$ifnum)";
                	#print "$sql\n";
	                $sth=$dbh->prepare($sql);
        	        $sth->execute();
                 
			Log("a");

		}
		Log("\n");
		$sth->finish();
	}
		

}
sub StorePorts(){
	my ($ip,$sth,$mactype,$ifnum,$maxIf,$i,$newifnum);
	my @macs=();

	foreach $ip(keys %ports){
		Log("Storing Ports for $ip\n");
		@macs=keys % { $ports{$ip}{type} };

	        ClearTable("delete from Port where Switch='$ip'");
		my @addressCount=();

		foreach $mac(@macs){
			$mactype=$ports{$ip}{type}{$mac};
			$ifnum=$ports{$ip}{port}{$mac};	#this may not be the real ifnum
			$newifnum=$ports{$ip}{offset}{$ifnum};  #this will grab the real ifnum
			print "Testing: $ifnum\t$newifnum\n";
			$ifnum=$newifnum;
			#print "$ip\t$mac\t$ifnum\t$mactype\n";


	                #mactype=3 == a learned address

	                if ($mactype==3){
        	                $addressCount[$ifnum]+=1;
                	        if ($ifnum>$maxIf){
                        	        $maxIf=$ifnum;
                        	}
	                }else{
        	                Log("\nAddress not learned: $mac\n");
                	}
	                Log("p");
                        
	                if (($mactype==3)&&($addressCount[$ifnum]<2)){
        	                $mac=HexMac($mac);
                	        $sql="insert into Port(switch,ifnum,mac,lastupdated) values('$ip',$ifnum,'$mac',$lastactive)";
	                        $sth=$dbh->prepare($sql);
        	                $sth->execute();
                	        $sql="update Devices set lastactive=$lastactive,active=1 where MAC='$mac'";
                        	$sth=$dbh->prepare($sql);
	                        $sth->execute();
                	}

		}
		Log("\n");

	        for ($i=0;$i<=$maxIf;$i++){
        	        if ($addressCount[$i]>1){
				my $mac="$ip\.$i";
                	        Log("Interface $i is an uplink on $ip\n");
                        	$sql="update Port set uplink=1,MAC='$mac' where Switch='$ip'
					and ifnum=$i";
	                        #print "$sql\n";
        	                $sth=$dbh->prepare($sql);
                	        $sth->execute();
				
				$sql="select MAC from Devices where MAC='$mac'";
				$sth=$dbh->prepare($sql);
				$sth->execute();
				if($sth->rows==0){
	                        	$sql="insert into Devices(MAC,description) values('$mac','Crossover Link')";
			                $sth=$dbh->prepare($sql);
        	        	        $sth->execute();        
				}
        	        }

	        }
	}
}
sub StoreRouterIPs(){
	my ($routerip, $sql,$sth,$mask,$ifnum,$int_ip,$int_mask,$int_network,$now);
	$now=time();
	foreach $routerip(keys %routerIPs){
		Log("Storing Router IP info for $routerip\n");
		
		my @addresses=keys %{ $routerIPs{$routerip}{address} };

		foreach $ip(@addresses){
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
			Log("r");
		}
		#$sth->finish();
		Log("\n");
	}

}
sub StoreIfDescriptions(){
	my ($sth,$ip,$ifdescr,$ifspeed,$ifOpStatus);
	foreach $ip(keys %ifs){
		Log("Storing if info for $ip\n");
		@ifnums=keys %{ $ifs{$ip}{descr} };

		ClearTable("delete from IFDescriptions where IP='$ip'");

		foreach $ifnum(@ifnums){
			$ifdescr=$ifs{$ip}{descr}{$ifnum};
			$ifspeed=$ifs{$ip}{speed}{$ifnum}/8;
			$ifOpStatus=$ifs{$ip}{opstatus}{$ifnum};
			$ifPhysAddress=$ifs{$ip}{physAddress}{$ifnum};
			if(length($ifPhysAddress)==14){
				$ifPhysAddress=fixMAC($ifPhysAddress);
			}
			if (!defined($ifOpStatus)){
				$ifOpStatus=0;
			}
			#print "$ip\t$ifnum\t$ifdescr\t$ifspeed\t$ifstatus\n";
	                $sql="insert into IFDescriptions(IP,ifnum,description,speed,opStatus,physAddress) values('$ip',$ifnum,'$ifdescr',$ifspeed,$ifOpStatus,'$ifPhysAddress')";
	                #print "$sql\n";
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
        foreach $oid(oid_lex_sort(keys(%{$response}))) {
                (@tmp)=split(/\./,$oid);
		$key="";
                for ($i=$keyparts;$i>=0;$i--){
                        $key=$key.$tmp[$#tmp - $i]."\.";
                }
		chop($key);
                $value=$response->{$oid};
		$hashptr->{$ip}{$field}{$key}=$value;
		#print "$key\t$value\n";
		#print ".";
        }                 
	#print "\n";
}


1;

