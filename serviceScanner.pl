#!/usr/bin/perl
##########################################################################################################################################
# Program: serviceScanner.pl
# Author:  Christopher Hanes
# Revision: 0.1.4
# Changelog:
# 10/31/01: v0.1.2 mail handling now provided by Mail::Sendmail package to provide win2k support
#	    configuration read from nodetracker.conf
# 11/01/01: v0.1.3 more config variable read from conf file; output messages now directed to logfile
# 11/09/01: v0.1.4 improved startup from different calling paths
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
use Errno;
use Date::Parse;
use Date::Format qw(time2str);

#read config file, set up global variables

### this section common to all code
($path,$program)=getPathInfo();
$commoncode=$path."common.pl";

Log("Sending notifications to $emails\n");

my $sth;
$sleeptime=$conf{"scannerInterval"};
$maxFailures=$conf{"scannerRetriesBeforeAlert"};
%currentFailures=();
while(1)
{

$dbh=DBI->connect($dsn,$user,$password);


$sql="select PrimaryIP,nmap.MAC,Port,Service,Devices.Description from nmap left join Devices using(MAC) where active=1 and RunNMAP=1 
order by PrimaryIP";
$sth=$dbh->prepare($sql);
$sth->execute();
if ($sth->rows>0){
	$r=$sth->fetchrow_hashref();
	while($r){
		$host=$r->{PrimaryIP};
		($port,$protocol)=split("\/",$r->{Port});
		
		#print $r->{PrimaryIP}."\t".$r->{Description}."\t$port $protocol\t".$r->{Service}."\n";
		$description="$host:$port ($r->{Service} on $r->{Description})";
		attemptConnection($host,$port,$description);
		$r=$sth->fetchrow_hashref();

	}
}
$sth->finish();
$dbh->disconnect();
Log("Sleeping $sleeptime\n");
sleep($sleeptime);
}

sub attemptConnection($){
	my $host=shift;
	my $port=shift;
	my $description=shift;

	my $iaddr=inet_aton($host);
	my $paddr=sockaddr_in($port,$iaddr);
	my $proto=getprotobyname('tcp');
	my $socket;
	socket($socket,PF_INET,SOCK_STREAM,$proto)||die "Unable to create socket to $description\n";
	#my $val = fcntl ($socket, F_GETFL, 0);
	#fcntl ($socket, F_SETFL, $val|O_NONBLOCK);
	if (connect($socket,$paddr)){
		$currentFailures{$description}=0;
		Log("Connection succeeded on $description\n");
		close($socket);
	}else{
		$body="Failure on $description\nWith error: ".$!;
		Log($body);
		if ($currentFailures{$description}<=$maxFailures){
			$currentFailures{$description}+=1;
		}else{
			$currentFailures{$description}=0;
			SendEmail($mailserver,"Service Down!",$body);
		}
	}
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

