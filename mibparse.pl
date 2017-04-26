#!/usr/bin/perl
use DBI;
use Socket;
use Getopt::Std;

getopts('m:d:u:p:');

#Connect to database
$driver="mysql";
$hostname="localhost";
$database=$opt_d;       #as specified on the command line
$user=$opt_u;
$password=$opt_p;
$dsn="DBI:$driver:database=$database;host=$hostname";
$dbh=DBI->connect($dsn,$user,$password);
$sth;
$missing;
$MIBS{iso}[0] = ".1";
$MIBS{org}[0] = ".1.3";
$MIBS{dod}[0] = ".1.3.6";
$MIBS{internet}[0] = ".1.3.6.1";
$MIBS{directory}[0] = ".1.3.6.1.1";
$MIBS{mgmt}[0] = ".1.3.6.1.2";
$MIBS{"mib-2"}[0]=  ".1.3.6.1.2.1";
$MIBS{experimental}[0] = ".1.3.6.1.3";
$MIBS{private}[0] = ".1.3.6.1.4";
$MIBS{enterprises}[0] = ".1.3.6.1.4.1";

open (FD,"cat  /sqldbs/nodetracker/scripts/mibs/$opt_m|") or die "Can't open file!";

DeleteOld();
@line=<FD>;

$start=-1;
$end=-2;
$blocknumber=0;
$lines= $#line;
for ($i=0;$i<$lines;$i++){
	$l=$line[$i];
	
	if( ($l=~m/^.*OBJECT.*/) ){
		if($l=~m/^\s*--.*/){
#			print "bad start $i $l";
		}else{
#			print "good start $i $l";
			$start=$i;
		}
	}else{
#		print "bad start2: $i $l";
	}
	if ($l=~m/^.*\:\:=.*\}/){
                if($l=~m/^\s*--.*/){
#                        print "bad end $i $l";  
                }else{
#                        print "good end $i $l"; 
                        $end=$i;
                }


	}

	if ($end>=$start){
#		print "$start\t$end\n";
		$blocknumber=$blocknumber+1;
		ParseBlock($start,$end,$blocknumber);

		$start=0;
		$end=-1;
	}
	

}
$sql="update SNMP_MIB set lastupdated=".time()." where filename='$opt_m'";
$sth=$dbh->prepare($sql);
$sth->execute();

$sth->finish();
$dbh->disconnect();
close(FD);
sub DeleteOld(){
	my $r,$sth,$sql;
	$sql="select baseoid from SNMP_MIB where filename='$opt_m'";
	print $sql."\n";
	$sth=$dbh->prepare($sql);
	$sth->execute();
	$r=$sth->fetchrow_hashref();
	if($r){
		$sql="delete from SNMP_Value_D where oid like '$r->{baseoid}%'";
		print $sql."\n";
		$sth=$dbh->prepare($sql);
		$sth->execute();
		
	}else{
		$missing=1;
	}
	$sth->finish();

}
sub ParseBlock($){
	my $start=shift;
	my $end=shift;
	my $blocknumber=shift;
	my $i;
	my @values;
	my $name, $parent,$id;
        if($line[$start]=~m/^\s*(\w+)\s*OBJECT.*/){
		$name=$1;

        }
        if ($line[$end]=~m/^.*\:\:=\s*\{\s*(.*)\s*\}/){
		($parent,$id)=split(/\s+/,$1);
        }
	
	$MIBS{$name}[0]=$MIBS{$parent}[0]."\.$id";
	$oid=$MIBS{$name}[0];

	for ($i=$start;$i<=$end;$i++){
		#now look for values with descriptions
		$stop=0;
		if ($line[$i]=~m/^.*SYNTAX\s*INTEGER\s*\{.*/){
			#found beginning of attribute lst;
			$i=$i+1;
			$j=$i;
			while(($i<=$end)&&($stop==0)){
				#print $line[$i];

				if($line[$i]=~m/.*\}.*/){
					$stop=1;
				}else{
				}
				$i=$i+1;
			}
			@attributes=@line[$j..($i-2)];
			for(my $k=0;$k<=$#attributes;$k++){
				###look for comments and remove from array
				if($attributes[$k]=~m/^\s*--.*/){
					print "Removing $attributes[$k]";
					splice(@attributes,$k,1);
				}else{
					#look for comment after attribute
					$commentIdx=index($attributes[$k],"--");
					#print $attributes[$k];
					if ($commentIdx>0){
						#print length($attributes[$k])."\n";
						$commentIdx=index($attributes[$k],",");
						$attributes[$k]=substr($attributes[$k],0,$commentIdx+1)."\n";
						#print "$attributes[$k]";

					}
				}

			}
			$attributes=join(//,@attributes);
			@attributes=split(/,/,$attributes);
		
			foreach $a(@attributes){
				if($a=~m/^\s*(\w+)\s*\((\d+)\).*/){
					$description=$1;
					$value=$2;
					$sql="insert into SNMP_Value_D(oid,value,description) values('$oid',$value,\"$description\")";
					print "$sql\n";

					$sth=$dbh->prepare($sql);
					$sth->execute();			

				}
			}

			#print "*******************\n";


		}


	}

	if ($blocknumber==1&&$missing==1){
		$sql="insert into SNMP_MIB(filename,baseoid,lastupdated) values('$opt_m','$MIBS{$name}[0]',".time().")";
		$sth=$dbh->prepare($sql);
		$sth->execute();
		print "$sql\n$parent\t$MIBS{$parent}[0]\t$id\t$MIBS{$name}[0]\n";
		#print "-------------------\n";
	}
}
