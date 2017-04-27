##########################################################################################################################################
# Program: walkfuncs.pm
# Author:  Christopher Hanes
# Revision: 1.2.0
# Changelog:
# 03/06/02: v0.5.0 fixed alot of bugs and warnings output from perl -w
# 08/05/04: v1.0.0 made walkfuncs a package
# 08/05/04: v1.0.1 added use strict and fixed resulting problems
# 08/06/04: v1.0.2 FindUnknownDevices eliminated and changed to fixMAC
# 08/22/05: v1.0.3 Eliminated use of Math::BigInt due to problems calculating gcd on FC3:
#		   Specifically, the error was
#			Can't use an undefined value as an ARRAY reference at /usr/local/lib/perl5/5.8.0/Math/BigInt/Calc.pm 
# 08/30/05: v1.0.4 bug fix to MaxSubnetSize when offset is 0
# 09/01/05: v1.1.0 added UpdateLastActive procedure
# 12/15/05: v1.2.0 changes to fixMAC to deal with hex strings coming in as binary - see note in fixMAC
##########################################################################################################################################
package walkfuncs;
use globals;
use strict;

require Exporter;

our @ISA = qw(Exporter);
our @EXPORT = ('ClearTable','CheckForInOutOIDs','toAddress','toNetBits','toIP', 'FixPrimaryIP','VerifyPrimaryIP','IdentifyUnusedIPBlocks',
	'computeNetSize','DescribeIPBlocks','FillIPBlocks','FillFreeSpace','log2','GetMask',
	'MaxSubnetSize','HexMac','DecMac','fixMAC','UpdateLastActive');


my $dbh;
sub Initialize($){
	$dbh=shift;
}
sub CheckForInOutOIDs($){
	#This is needed to make sure each router/switch has refids for collecting basic in/out octects
	my $nodeID=shift;
	my ($sth,$sql,$r);
	$sql="select * from OID_Instances where nodeID=$nodeID and shortoid in(21,22)";
	$sth=$dbh->prepare($sql);
	$sth->execute();
	my $c=$sth->rows;

	if($c==0){
		#need to add both in and out
		$sql="insert into OID_Instances(nodeID,shortoid) values($nodeID,21)";
		$sth=$dbh->prepare($sql);
		$sth->execute();
		Log($sql."\n");
		$sql="insert into OID_Instances(nodeID,shortoid) values($nodeID,22)";
		Log($sql."\n");
		$sth=$dbh->prepare($sql);
		$sth->execute();


	}elsif($c==1){
		#only need to add one...
		$r=$sth->fetchrow_hashref();
		if ($r->{shortoid}==21){
			$sql="insert into OID_Instances(nodeID,shortoid) values($nodeID,22)";
		}else{
			$sql="insert into OID_Instances(nodeID,shortoid) values($nodeID,21)";
		}
		Log($sql."\n");
		$sth=$dbh->prepare($sql);
		$sth->execute();
	}
	
	
}
sub toAddress($){
        my $ip=shift;
        my @oct=split(/\./,$ip);
	my $o;
        my $address=0;
        my $shiftbits=24;
        foreach $o(@oct){
                #$o=sprintf("%x",$o);
                $address+=$o*2**$shiftbits;
                #print $address."\n";
                $shiftbits-=8;
        }
	return $address;
}
sub toNetBits($){
	my $mask=shift;
	my $size;
	$size=(0xFFFFFFFF^$mask)+1;
	my $netbits=32-log2($size);
	return $netbits;
}
sub toIP($){
        my $ip=shift;
	#print $ip."\t";
        $ip=sprintf("%08x",$ip);
	#print $ip."\n";
        my @ip=split("",$ip);
        my @oct=();
	my $o;
        $oct[0]="0x".$ip[0].$ip[1];
        $oct[1]="0x".$ip[2].$ip[3];
        $oct[2]="0x".$ip[4].$ip[5];
        $oct[3]="0x".$ip[6].$ip[7];
        $ip="";
        foreach $o(@oct){
		#print $o."\t".oct($o)."\n";
                $ip=$ip.oct($o)."\.";
        }
        chop($ip);
        return $ip;
}

sub FixPrimaryIP(){
	my ($sth,$sth2,$r2,$sql,$r,$ip);
	$sql="select MAC,description from Devices where type not in(2,3) and IPAutoFill=1 and active=1";
	$sth=$dbh->prepare($sql);
	$sth->execute();
	$r=$sth->fetchrow_hashref();
	while ($r){
		$sql="select min(address) as address from IP where MAC='$r->{MAC}'";
		Log("Fixing $r->{description}\n");
		#print $sql."\n";
		$sth2=$dbh->prepare($sql);
		$sth2->execute();
		if($sth2->rows>0){
			$r2=$sth2->fetchrow_hashref();
			if (defined($r2->{address})){
				$ip=toIP($r2->{address});
				$sql="update Devices set PrimaryIP='$ip',IPAutoFill=0 where MAC='$r->{MAC}'";	
				Log("$sql\n");
				$sth2=$dbh->prepare($sql);
				$sth2->execute();
			}
		}
		$r=$sth->fetchrow_hashref();
	}
}
sub VerifyPrimaryIP(){
	my $sql="select MAC,PrimaryIP,type from Devices";
	my $sth=$dbh->prepare($sql);
	my ($sth2,$r2);
	$sth->execute();
	my $r=$sth->fetchrow_hashref();
	while ($r){
		$sql="select IP from IP where MAC='$r->{MAC}' and IP='$r->{PrimaryIP}'";
		$sth2=$dbh->prepare($sql);
		$sth2->execute();
		if ($sth2->rows==0){
			#this PrimaryIP is not in the ARP table or
			#IP is not bound to this MAC

			if ($r->{type}!=$globals::typeRouter){
				Log("Primary IP $r->{PrimaryIP} is wrong for $r->{MAC}\n");
				$sql="update Devices set IPAutoFill=1 where MAC='$r->{MAC}'";
				$sth2=$dbh->prepare($sql);
				$sth2->execute();
			}elsif($r->{PrimaryIP} eq $r->{MAC}){
				#we have a router or switch
				#need to find MAC address of router or switch
				Log("Need MAC for $r->{PrimaryIP}\t");
				$sql="select MAC from IP where IP=\"$r->{PrimaryIP}\"";
				$sth2=$dbh->prepare($sql);
				$sth2->execute();
				$r2=$sth2->fetchrow_hashref();
				if($r2){		
					$sql="update Devices set MAC=\"$r2->{MAC}\" where MAC=\"$r->{PrimaryIP}\"";			
					$sth2=$dbh->prepare($sql);
					$sth2->execute();
				}else{
					#try looking for hardware address in IFDescriptions
					$sql="select distinct physAddress from IFDescriptions where IP='$r->{PrimaryIP}' 
						and physAddress<>'' order by physAddress desc";
					$sth2=$dbh->prepare($sql);
					$sth2->execute();
					$r2=$sth2->fetchrow_hashref();
					if($r2){
						$sql="update Devices set MAC=\"$r2->{physAddress}\" where MAC=\"$r->{PrimaryIP}\"";
						$sth2=$dbh->prepare($sql);
						$sth2->execute();
					}else{
						Log("Still no MAC");
					}
				}
				Log("\n");
			}
		}
		$r=$sth->fetchrow_hashref();
	}
	$sth2->finish();
	$sth->finish();
	FixPrimaryIP();	
}
sub IdentifyUnusedIPBlocks(){
	my ($sth, $sth2,$sql,$network,$mask,$netsize,$netend);
	$sql="delete from RouterIPs where ip='0'";
	$sth=$dbh->prepare($sql);
	$sth->execute();

	$sql="select * from IPBlocks order by network";
	$sth=$dbh->prepare($sql);
	$sth->execute();
	my $r=$sth->fetchrow_hashref();
	while($r){
        	$network=$r->{network};
        	$mask=$r->{mask};
        	$netsize=computeNetSize($mask);
		print "IdentifyUnused: $network\t$mask\t$netsize\n";
        	$netend=$network+$netsize;
        	FillIPBlocks($network,$netend);
        	DescribeIPBlocks($network,$netend);
	
		$r=$sth->fetchrow_hashref();
	}
	Log("\n");
	#now clean up IPAllocations
	$sql="select IPAllocations.network,IPAllocations.mask from IPAllocations 
		left join RouterIPs using(network,mask) where RouterIPs.IP is null";
	Log($sql."\n");
	$sth=$dbh->prepare($sql);
	$sth->execute();
	$r=$sth->fetchrow_hashref();
	while($r){
		$sql="delete from IPAllocations where network=$r->{network} and mask=$r->{mask}";
		Log($sql."\n");
		$sth2=$dbh->prepare($sql);
		$sth2->execute();
		$r=$sth->fetchrow_hashref();
	}

}
sub computeNetSize($){
	my $mask=shift;
	my $size=$mask^(0xFFFFFFFF);
	$size+=1;
	return $size;
}
sub DescribeIPBlocks($$){
	#adds default records to IPAllocations for blocks not in there yet.
	my $network=shift;
	my $netend=shift;
	my $sth2;
        my $sql="select distinct RouterIPs.network,RouterIPs.mask from RouterIPs 
		left join IPAllocations using(network,mask) where IPAllocations.network is null
                and RouterIPs.network>=$network and RouterIPs.network<$netend order by RouterIPs.network";
        my $sth=$dbh->prepare($sql);
	$sth->execute();
	my $r=$sth->fetchrow_hashref();
	while($r){
		$sql="insert into IPAllocations(network,mask) values($r->{network},$r->{mask})";
		Log($sql."\n");
		$sth2=$dbh->prepare($sql);
		$sth2->execute();
		$r=$sth->fetchrow_hashref();	
	}
	$sth->finish();

}
sub FillIPBlocks($$){
	# Get current IP block allocation info from router ip/mask combinations
	# Then fill in blank information
	my $network=shift;
	my $netend=shift;
	my $sth2;
	my ($blocksize, $offset,$nextNet,$parentClassC);
        my $sql="select distinct network,mask from RouterIPs
                where network>=$network and network<$netend order by network";
	my $sth=$dbh->prepare($sql);
	$sth->execute();
	if ($sth->rows==0){
		#everything is free in this space 
		FillFreeSpace($network,$netend);
		$sth->finish();
		return;
	}
	my $r=$sth->fetchrow_hashref();
        $nextNet=$r->{network};
	if ($network<$nextNet){
		#we are going to need to "fill" free space from beginning of block to this first allocated block
		$nextNet=$network;

	}
	while ($r){
                $blocksize=computeNetSize($r->{mask});  #blocksize of this allocated block
		$offset=0;
		if ($r->{network}>$nextNet){
			#fill in the free space between current net and expected nextNet
			FillFreeSpace($nextNet,$r->{network});

		}
		$parentClassC=$r->{network}&0xFFFFFF00;
		#printf ("a parent:%X\tmynet:%X\n",$parentClassC,$r->{network});
		#print "\tblocksize: $blocksize\n";

		$nextNet=$r->{network}+$blocksize;
		$r=$sth->fetchrow_hashref();
	}

	
	if ($nextNet<$netend){
		#we need to fill in to the end of the block
		FillFreeSpace($nextNet,$netend);
	}
	$sth->finish();
	#$sth2->finish();
	

}	
sub FillFreeSpace($$){
	my $startNet=shift;
	my $endNet=shift;
	my $parentClassC=$startNet&0xFFFFFF00;
	my $nextNet=$startNet;

	my $subnetsize;
	my $mask;
	my $sth;
	my $sql;

	Log("FillFreeSpace: parentC: $parentClassC nextNet: $nextNet endNet: $endNet\n");
	while ($nextNet<$endNet){
		$subnetsize=MaxSubnetSize($nextNet-$parentClassC,$endNet-$nextNet);
		$mask=GetMask($subnetsize);
		
        	#printf ("ffspace parent:%X\tmynet:%X\t%X\n",$parentClassC,$nextNet,$mask );
        	$sql="insert into RouterIPs(ip,address,mask,network,ifnum) values('0',0x".sprintf("%X",$nextNet).",0x".sprintf("%X",$mask).",$nextNet,0)";
		Log($sql."\n");
		
        	#print "\t$sql\n";
		$sth=$dbh->prepare($sql);
		if (!$sth){
              		die "Error:" . $sth->errstr . "\n";

		}
	        if (!$sth->execute) {
              		die "Error:" . $sth->errstr . "\n";
          	}

		$nextNet=$nextNet+$subnetsize;
	}
	$sth->finish();
}

sub log2($){
	#bizarre behavior by log function requires first converting to string then back to integer
	#before using else log returns NaN
	my $tmp=shift;
	$tmp=$tmp.".0";
	my $val=$tmp+0;
	my $log2=log 2;
	my $result=(log $val)/($log2);
	Log("log2: $val $log2 $result\n");
	return $result;
}
sub GetMask($){
	my $size=shift;
	my $hostbits=log2($size);
	my $mask=0xFFFFFFFF;
	$mask=$mask << $hostbits;
	Log("size: $size hostbits: $hostbits mask: $mask\n");
	return $mask;
}
sub gcd
{
    my $a = shift;
    my $b = shift;
    Log("gcd: a=$a b=$b\n");

    if ($b > $a)
    {
        ($a, $b) = ($b , $a);
    }

    while ($a % $b > 0)
    {
        ($a, $b) = ($b, $a % $b);
    }

    return $b;
}
sub MaxSubnetSize($$){
	my $offset=shift;
	my $max=shift;
	Log("offset: $offset max: $max\n");

        #my @v=($offset,256);
       	#my $maxsubnetSize=Math::BigInt::bgcd(@v);
	my $maxsubnetSize=256;

	if($offset!=0){
		$maxsubnetSize=gcd($offset,256);
	}

        while ($max<$maxsubnetSize){
       		$maxsubnetSize=$maxsubnetSize/2;
        }
	if ($maxsubnetSize==2){
		#eliminate /31's
		#$maxsubnetSize=1;
	}

	Log("offset: $offset max: $max maxsub: $maxsubnetSize\n");
	my $result=int($maxsubnetSize);
	return $result;

}
sub ClearTable($){
	my $sth;
	my $sql;
	$sql=shift;
	#print "$sql\n";
	$sth=$dbh->prepare($sql);
	$sth->execute();
}


sub HexMac($){
	my $mac=shift;
	my @macArray=split(/\./,$mac);
	for my $i(0..5){
		$macArray[$i]=sprintf("%1x",$macArray[$i]);
		if (length($macArray[$i])==1){
			$macArray[$i]="0".$macArray[$i];
		}
	}
	$mac="$macArray[0]\.$macArray[1]\.$macArray[2]\.$macArray[3]\.$macArray[4]\.$macArray[5]";
	return $mac;
}
sub DecMac($){
        my $mac=shift;
        my @macArray=split(/\./,$mac);
        for my $i(0..5){
		$macArray[$i]="0x".$macArray[$i];
                $macArray[$i]=oct $macArray[$i];
		$macArray[$i]=sprintf("%1d",$macArray[$i]);

        }
        $mac="$macArray[0]\.$macArray[1]\.$macArray[2]\.$macArray[3]\.$macArray[4]\.$macArray[5]";
        return $mac; 
} 
  
sub fixMAC($){
	my $tmp=shift;
	my $mac="";
	my $i;
	my $char;
	#Log("\nfixMAC: len=".length($tmp)." $tmp -> ");

	if(length($tmp)==6){
		#12/14/05
		#convert this ASCII to a HEX string
		#bad results from SNMP lib since we should have gotten string length 14

		for($i=0;$i<6;$i++){
	        	$char=substr($tmp,$i,1);
	        	$mac=$mac.sprintf("%02x",ord($char));
		}
		$mac="0x".$mac;
		$tmp=$mac;
	}


	if (!defined($tmp)||($tmp!~m/\w+/)||(length($tmp)!=14)){
		$mac="";
		return $mac;
	}



	$tmp=substr($tmp,2); 
	my @macArray=("","","","","","");
	for my $i(0..5){
		$macArray[$i]=substr($tmp,$i*2,2);
	}

	$mac="$macArray[0]\.$macArray[1]\.$macArray[2]\.$macArray[3]\.$macArray[4]\.$macArray[5]";
	#print("$mac\n");
	return $mac;
}
sub UpdateLastActive()
{
	my $sql="select nodeID, lastactive from Devices order by nodeID";
	my $sth=$dbh->prepare($sql);
	$sth->execute();
	my $r=$sth->fetchrow_hashref();
	my $time;
	while($r){
		$time=GetStampFromInterfaces($r->{nodeID});
		#print "node: $r->{nodeID} $time";	
		$time=GetStampFromOIDs($r->{nodeID},$time);
		#print " -> $time $r->{lastactive}\n";	
		if($time>$r->{lastactive}){
			$sql="update Devices set lastactive=$time where nodeID=$r->{nodeID}";
			$dbh->do($sql);
		}
		$r=$sth->fetchrow_hashref();
	}

}
sub GetStampFromOIDs($$){
	my $nodeID=shift;
	my $time=shift;
        my $sql="select lasttime as last from OID_Instances where nodeID=$nodeID";
        my $sth=$dbh->prepare($sql);
        $sth->execute();
        my $r=$sth->fetchrow_hashref();
        while($r){
                if($r->{last}){           
                        if($r->{last}>$time){
                                $time=$r->{last};
                        }
                }
                $r=$sth->fetchrow_hashref();
        }

        return $time;

}
sub GetStampFromInterfaces($)
{
	my $nodeID=shift;
	my $sql="select Port.lastupdated from Links left join Port using(MAC) where Links.nodeID=$nodeID";
	my $sth=$dbh->prepare($sql);
	$sth->execute();
        my $r=$sth->fetchrow_hashref();
	my $time=0;
        while($r){
		if($r->{lastupdated}){
			if($r->{lastupdated}>$time){
				$time=$r->{lastupdated};
			}
		}
                $r=$sth->fetchrow_hashref();
        }

	return $time;
}
1;
