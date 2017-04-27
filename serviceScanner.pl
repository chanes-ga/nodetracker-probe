#!/usr/bin/perl
##########################################################################################################################################
# Program: serviceScanner.pl
# Author:  Christopher Hanes
# Revision: 1.0.0
# Changelog:
# 10/31/01: v0.1.2 mail handling now provided by Mail::Sendmail package to provide win2k support
#	    configuration read from nodetracker.conf
# 11/01/01: v0.1.3 more config variable read from conf file; output messages now directed to logfile
# 11/09/01: v0.1.4 improved startup from different calling paths
# 12/15/05: v1.0.0 major rewrite; using IO::Select and IO::Socket::INET now
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
use IO::Select;
use IO::Socket::INET;
use Errno;
use Date::Parse;
use Date::Format qw(time2str);


### this section common to all code
my ($path,$program)=&getPathInfo();

#this must loaded first in order for other packages to work correctly
use globals;

globals::Initialize($path,$program);

#Log("Sending notifications to $emails\n");

my $sth;
$sleeptime=$globals::conf{"scannerInterval"}+0;
$maxFailures=$globals::conf{"scannerRetriesBeforeAlert"};
$ignoreFailures=$globals::conf{"scannerFailuresBeforeIgnore"};
%currentFailures=();
%description=();
while(1)
{


$dbh = DBI->connect($globals::dsn,$globals::user,$globals::password);


$portSQL= "and Port in (".$globals::conf{portWatchList}.") ";
$sql="select PrimaryIP,nmap.nodeID,Port,Service,Devices.Description from nmap left join Devices using(nodeID) where active=1 and state='open' and PrimaryIP<>'' $portSQL  and RunNMAP=1 order by PrimaryIP limit 100";
print "$sql\n";
$sth=$dbh->prepare($sql);
$sth->execute();
if ($sth->rows>0){
	 $sel = IO::Select->new();

	$r=$sth->fetchrow_hashref();
	while($r){
		$host=$r->{PrimaryIP};
		($port,$protocol)=split("\/",$r->{Port});
		
		print $r->{PrimaryIP}."\t".$r->{Description}."\t$port $protocol\t".$r->{Service}."\n";
		$ip=$r->{PrimaryIP};
		$tag="$ip:$port";

		$description{$tag}=$r->{Description};
		if($currentFailures{$tag}<=$ignoreFailures){
	   		my $sock = IO::Socket::INET->new(PeerAddr => $ip,
        	                         PeerPort => $port,
                	                 Proto    => 'tcp',
					 Blocking =>0,
					 Timeout =>2
				);
	
			#assume failure
			if (defined($currentFailures{$tag})){
				$currentFailures{$tag}++;
			}else{
				$currentFailures{$tag}=1;
			}
			
			$sel->add($sock);		
		}

		$r=$sth->fetchrow_hashref();


	}

	#print "Select Count:".$sel->count()."\n";
	while(@t=$sel->can_write()){
		foreach $sock(@t){
			if($sock->connected){
				$tag=$sock->peerhost.":".$sock->peerport;
				#print "connected to $tag\n";
				$currentFailures{$tag}=0;
				shutdown($sock, 2);

			}	
			$sel->remove($sock);
			$j++;
		}
		$i++;
		#print "Select Count ".$sel->count()."\n";
	}
	$body="";
	foreach $key(%currentFailures){
		if($currentFailures{$key}>=1){
			print "Can't connect to $key.  Failure #".$currentFailures{$key}."\n";
		}
		if(($currentFailures{$key}>=$maxFailures)&&($currentFailures{$key}<$ignoreFailures)){
			$body=$body."$key on $description{$key} is down, failure #".$currentFailures{$key}."\n";

		}
		if($currentFailures{$key}==$ignoreFailures){
			$body=$body."$key on $description{$key} is STILL down - last alert!!\n";
		}
	}
	print "BODY:\n$body\n";
	if(length($body)>0){
		SendEmail("Services Down!",$body);
	}

}
$sth->finish();
$dbh->disconnect();
print "Sleeping $sleeptime\n";
sleep($sleeptime);
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
        return ($path,$program);
}

