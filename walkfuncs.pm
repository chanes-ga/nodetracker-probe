##########################################################################################################################################
# Program: walkfuncs.pm
# Author:  Christopher Hanes
# Revision: 0.5.0
# Changelog:
# 03/06/02: v0.5.0 fixed alot of bugs and warnings output from perl -w
##########################################################################################################################################
sub CheckForInOutOIDs($){
	#This is needed to make sure each router/switch has refids for collecting basic in/out octects
	my $mac=shift;
	my ($sth,$sql,$r);
	$sql="select * from OID_Instances where MAC='$mac' and shortoid in(21,22)";
	$sth=$dbh->prepare($sql);
	$sth->execute();
	my $c=$sth->rows;

	if($c==0){
		#need to add both in and out
		$sql="insert into OID_Instances(MAC,shortoid) values('$mac',21)";
		$sth=$dbh->prepare($sql);
		$sth->execute();
		Log($sql."\n");
		$sql="insert into OID_Instances(MAC,shortoid) values('$mac',22)";
		Log($sql."\n");
		$sth=$dbh->prepare($sql);
		$sth->execute();


	}elsif($c==1){
		#only need to add one...
		$r=$sth->fetchrow_hashref();
		if ($r->{shortoid}==21){
			$sql="insert into OID_Instances(MAC,shortoid) values('$mac',22)";
		}else{
			$sql="insert into OID_Instances(MAC,shortoid) values('$mac',21)";
		}
		Log($sql."\n");
		$sth=$dbh->prepare($sql);
		$sth->execute();
	}
	
	
}
sub toAddress($){
        my $ip=shift;
        my @oct=split(/\./,$ip);
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
			$ip=toIP($r2->{address});
			$sql="update Devices set PrimaryIP='$ip',IPAutoFill=0 where MAC='$r->{MAC}'";
			Log("$sql\n");
			$sth2=$dbh->prepare($sql);
			$sth2->execute();
		}
		$r=$sth->fetchrow_hashref();
	}
}
sub VerifyPrimaryIP(){
	$sql="select MAC,PrimaryIP,type from Devices";
	$sth=$dbh->prepare($sql);
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
sub IdentifyUnused(){
	my ($sth, $sth2,$sql);
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
		#print "$network\t$mask\t$netsize\n";
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
sub FindUnknownDevices($){
	my $public=shift;
	$sql="select distinct IP.MAC as MAC from IP left join Devices using(MAC) where Devices.MAC is null";
	$sth=$dbh->prepare($sql);
	$sth->execute();
	Log("Finding Unknown Devices");
	my $r=$sth->fetchrow_hashref();
	while ($r){
		$sql="insert into Devices(MAC,Description,Active,RunNMAP,IPAutoFill,type,public) 
values('$r->{MAC}','Unknown',1,0,1,0,\"$public\")";
		$sth2=$dbh->prepare($sql);
		$sth2->execute();
		Log(".");
		$r=$sth->fetchrow_hashref();
	}
	Log("\n");
	
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
        $sql="select distinct RouterIPs.network,RouterIPs.mask from RouterIPs 
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
	my $network=shift;
	my $netend=shift;
	my $sth2;

        $sql="select distinct network,mask from RouterIPs
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
        my $nextNet=$r->{network};
	if ($network<$nextNet){
		$nextNet=$network;

	}
	while ($r){
                $blocksize=computeNetSize($r->{mask});
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

	#printf ("FillFreeSpace:%X\t%X\n",$nextNet,$endNet);
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
	my $val=shift;
	return (log $val)/(log 2);
}
sub GetMask($){
	my $size=shift;
	$hostbits=log2($size);
	my $mask=0xFFFFFFFF;
	$mask=$mask << $hostbits;
	return $mask;
}
sub MaxSubnetSize($$){
	my $offset=shift;
	my $max=shift;
	my $maxsubnetSize;
        @v=($offset,256);
       	$maxsubnetSize=Math::BigInt::bgcd(@v);
        while ($max<$maxsubnetSize){
       		$maxsubnetSize=$maxsubnetSize/2;
        }
	if ($maxsubnetSize==2){
		#eliminate /31's
		#$maxsubnetSize=1;
	}
	return $maxsubnetSize;

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
	$mac=shift;
	@macArray=split(/\./,$mac);
	for $i(0..5){
		$macArray[$i]=sprintf("%1x",$macArray[$i]);
		if (length($macArray[$i])==1){
			$macArray[$i]="0".$macArray[$i];
		}
	}
	$mac="$macArray[0]\.$macArray[1]\.$macArray[2]\.$macArray[3]\.$macArray[4]\.$macArray[5]";
	return $mac;
}
sub DecMac($){
        $mac=shift;
        @macArray=split(/\./,$mac);
        for $i(0..5){
		$macArray[$i]="0x".$macArray[$i];
                $macArray[$i]=oct $macArray[$i];
		$macArray[$i]=sprintf("%1d",$macArray[$i]);

        }
        $mac="$macArray[0]\.$macArray[1]\.$macArray[2]\.$macArray[3]\.$macArray[4]\.$macArray[5]";
        return $mac; 
} 
  
sub fixMAC($){
	my $tmp=shift;
	if (!defined($tmp)||($tmp eq "")){
		$mac="";
		return $mac;
	}
	$tmp=substr($tmp,2); 
	my @macArray=("","","","","","");
	for my $i(0..5){
		$macArray[$i]=substr($tmp,$i*2,2);
	}

	$mac="$macArray[0]\.$macArray[1]\.$macArray[2]\.$macArray[3]\.$macArray[4]\.$macArray[5]";
	if ($mac eq "....."){
		$mac="";
	}
	return $mac;
}
1;
