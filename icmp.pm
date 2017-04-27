#!/usr/bin/perl -w
##########################################################################################################################################
# Program: icmp.pm
# Author:  Christopher Hanes
# Revision: 1.1.0
# Changelog:
# 12/15/05:v1.0.0  
# 12/16/05:v1.1.0 aggregated results into single email reports instead of sending per host notifications
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
package icmp;
use strict;
use walkfuncs;
use globals;
use Date::Format qw(time2str);

require Exporter;

our @ISA = qw(Exporter);
our @EXPORT = ('ICMPChecks');

my $dbh;

sub ICMPChecks($$)
{
	my $timeunit=shift;
	$dbh=shift;
        my $sql="select Description, PrimaryIP from Devices where active=1 and icmpscan=1 order by PrimaryIP";
        my $sth=$dbh->prepare($sql);
        $sth->execute();
        my $r=$sth->fetchrow_hashref();
	my $int_ip;
	my $now=time();
	my $str_now=time2str("%D %R",$now);
	my $intervals=2;
	my $middleTime=$now-$intervals*$timeunit;
	my $startTime=$middleTime-3600;
	my $interval1 = time2str("%R",$startTime)."-".time2str("%R",$middleTime);
	my $interval2 = time2str("%R",$middleTime)."-".time2str("%R",$now);

	my $avg1;
	my $avg2;
	my ($pl1,$pl2);
	my $diff;
	my $body;	
	
	my $bodyLatency="";
	my $bodyPL="";
        while($r){
		$int_ip=toAddress($r->{PrimaryIP});
		$diff=0;
		($avg1,$pl1)=GetLatency($int_ip,$startTime,$middleTime);
		($avg2,$pl2)=GetLatency($int_ip,$middleTime,$now);
		
		if (defined($avg1)&&defined($avg2)){
			if($avg1>0){
				$diff=sprintf("%f",($avg2-$avg1)/$avg1*100);
			}
			
			
			if(($avg1>100)&&($diff>=1000)){
				#Send Notification 
				$avg1=sprintf("%d",$avg1);
				$avg2=sprintf("%d",$avg2);
				$diff=sprintf("%d",$diff);
				$pl1=sprintf("%1.2f",$pl1);
				$pl2=sprintf("%1.2f",$pl2);
				#$subject="Latency for $r->{Description}";
				$bodyLatency=$bodyLatency."$r->{PrimaryIP}: ".$avg1."ms->".$avg2."ms  up $diff\% for $r->{Description}\n";
	                	print $r->{PrimaryIP}." latency $avg1 $avg2 $diff\n";
			}

			if($pl2>75){
                        	$pl1=sprintf("%1.2f",$pl1);
                                $pl2=sprintf("%1.2f",$pl2);
				$diff=$pl2-$pl1;
                                print $r->{PrimaryIP}." loss $pl1 $pl2\n";

				#if packet loss for previous hour was solid at 100% then don't notify
				if($pl1!=100){
					$bodyPL=$bodyPL."$r->{PrimaryIP}: ".$pl1."\%->".$pl2."\% = $diff\% for $r->{Description}\n";
				}
			}

		}
	        $r=$sth->fetchrow_hashref();

        }
	#print "pl: $bodyPL\n";
	if(length($bodyLatency)>0){
		$bodyLatency="Now: $str_now\n($interval1) VERSUS ($interval2)\n\n".$bodyLatency;
		SendEmail("Latency Issues",$bodyLatency);
	}	
	if(length($bodyPL)>0){
		$bodyPL="Now: $str_now\n($interval1) VERSUS ($interval2)\n\n".$bodyPL;
		SendEmail("Packet Loss Issues",$bodyPL);

	}
        $sth->finish();

}
sub GetLatency($$$){
	my $int_ip=shift;
	my $startTime=shift;
	my $endTime=shift;
	my $sql="select avg(mean) as a,avg(loss) as l from ICMPData where ip=$int_ip and timeblock>=$startTime and timeblock<$endTime";
	#print $sql."\n";
	my $sth=$dbh->prepare($sql);
	$sth->execute();
	my $r=$sth->fetchrow_hashref();
	my $avg1=$r->{a};
	my $avg2=$r->{l};
	$sth->finish();
	#print "avg is $avg\n";
	return ($avg1,$avg2);
	
}


1;
