#!/usr/bin/perl
##########################################################################################################################################
# Program: nmap.pl
# Author:  Christopher Hanes
# Revision: 0.6.0
# Changelog:
# 01/25/02: v0.4.0 converted to a real package; fixed prototype errors in function definations
# 		also now integrated with probe.pl
# 02/01/02: v0.4.1 minor corrections to code
# 03/07/02: v0.6.0 fixed all perl warnings
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
package nmap;

require mycrypt;
use globals;

$key;
$keyvalid;
$dbh;


sub Initialize($$$){
	$dbh=shift;
	$keyvalid=shift;
	$key=shift;
}

sub scanNext($){
	my $totalscans=shift;
        my ($sql, $r,$sth1);
        my ($sth2,$r2);
        my %portList=();
        $sql="select MAC, PrimaryIP as IP, Description,RunNMAP  from Devices where PrimaryIP is not null 
                and active=1 and runNMAP=1 order by lastnmap limit $totalscans";
        $sth1=$dbh->prepare($sql);
        $sth1->execute();
        $r=$sth1->fetchrow_hashref();
        while($r){
                Log("$r->{Description}\t$r->{IP}\n");
                $sql="select Port from nmap where MAC='$r->{MAC}'";
                $sth2=$dbh->prepare($sql);
                $sth2->execute();
                $r2=$sth2->fetchrow_hashref();
                while ($r2){
                        $portList{$r2->{Port}}=1;
                        #print "*** $r2->{Port}\n";
                        $r2=$sth2->fetchrow_hashref();
                }
                $sth2->finish();

                ClearNMAP($r->{MAC});           #this will clear out old garbage even if we don't run nmap
                if ($r->{RunNMAP}==1){
                        runNMAP($r->{IP},$r->{MAC},\%portList,$keyvalid);
                }
                %portList=();

                $r=$sth1->fetchrow_hashref();
        }
}

sub ClearNMAP($){
        my $sql;
        $mac=shift;
        $deletesql="delete from nmap where MAC='$mac'";
        $updatesql="update Devices set tcpsequence='', osguess='', rating=null,ratingcomment='' where MAC='$mac'";
        $sql=$deletesql;
        #print "$sql\n";
        $sth=$dbh->prepare($sql);
        $sth->execute();
        $sql=$updatesql;
        $sth=$dbh->prepare($sql);
        $sth->execute();

}

sub runNMAP($$$$)
{
	my $host=shift;
	my $mac=shift;
	#my $nmap=shift;
	my $portListPtr=shift;
	my $cryptstate=shift;
	my $portcount=0;
	my $timestamp=time();
	my $sth;
	my $osguess;
	my $rating;
	my $comment;
	my %portList=%$portListPtr;

	if ($cryptstate==$globals::stateEncrypted){
		#decrypt the Primary IP
		$host=mycrypt::cryptText(0,$host,$key);
	}


	$nmapcmd=$globals::conf{nmap}." -I -O -v --host 200000 ".$host." |";
	$rating="0";	
	print "$key $nkey $cryptstate\t$nmapcmd\n";
	open(FD,$nmapcmd) or die;
	while ($line=<FD>){
		#print $line;
		if ($line=~m/(\d+)\/\w+\s+(\w+)\s+([\w\-]+)\s+(.*)/){
		#if ($line=~m/(\d+\/\w+)\s+(\w+)\s+([\w\-]+)\s+(.*)/){
			$port=$1;
			$state=$2;
			$service=$3;
			$owner=$4;

			if ($cryptstate==$globals::stateEncrypted){
				#$mac should already be encrypted!
				$port=mycrypt::doxor($nkey,$port);
				$service=mycrypt::cryptText(1,$service,$key);
			}


			Log("\t$port\t$state\t$service\t$owner\n");
			if($portList{$port}!=1){
				#new port
				$portList{$port}=3;
			}
			$portList{$port}=2;
			

			$sql="insert into nmap(MAC,Port,Service,State,Owner) values('$mac',$port,'$service','$state','$owner')";
			print "$sql\n";
			$sth=$dbh->prepare($sql);
			$sth->execute();
			$portcount=$portcount+1;
		}else{
			if ($line=~m/TCP Sequence Prediction: Class=(.*)/){
				$tcpsequence=$1;
				Log( "tcpsquence: $1\n");
			}else{
				if ($line=~m/.*Difficulty=(\d+)\s+\((.*)\)/){
					Log("difficulty: $1\t$2\n");
					$rating=$1;
					$comment=$2;

				}else{
					if (($line=~m/Remote OS guesses:\s+(.*)/)||($line=~m/Remote operating system guess:\s+(.*)/)){
						$osguess=$1;
					}

				}
			}
		
		}
	}
	close(FD);
	if ($cryptstate==$globals::stateEncrypted){
		$comment=mycrypt::cryptText(1,$comment,$key);
		$osguess=mycrypt::cryptText(1,$osguess,$key);
		$tcpsequence=mycrypt::cryptText(1,$tcpsequence,$key);
	}
	$sql="update Devices set tcpsequence='$tcpsequence',
		rating=$rating,ratingcomment='$comment', osguess='$osguess',lastnmap=$timestamp where MAC='$mac'";
	print "$sql\n";
	$sth=$dbh->prepare($sql);
	$sth->execute();	


	my $changelog="";
	foreach $port(keys %portList){
		if ($cryptstate==$globals::stateEncrypted){
			#since $port maybe encrypted
			$actualPort=mycrypt::doxor($nkey,$port);
		}else{
			$actualPort=$port;
		}

		if($portList{$port}==1){
			#old port not found this run
			$changelog=$changelog."Port $actualPort DOWN<br>";
		}elsif($portList{$port}==3){
			#new port found this run
			$changelog=$changelog."Port $actualPort UP<br>";
		}
		#reset value;
		$portList{$port}=0;
	}
	if($cryptstate==$globals::stateEncrypted){
		$changelog=mycrypt::cryptText(1,$changelog,$key);
	}
	#print "Changes:".$changelog."\n";
	if (length($changelog)>0){
		$sql="insert into nmap_changelog(MAC,timestamp,changedescription) values('$mac',$timestamp,'$changelog')";
		print $sql;
		$sth=$dbh->prepare($sql);
		$sth->execute();		
	}
	$changelog="";
	$sth->finish();
}

1;







