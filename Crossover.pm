##########################################################################################################################################
# Program: Crossover.pm
# Author:  Christopher Hanes
# Revision: 1.1.0
# Changelog:
# 08/17/04: v1.1.0 added SaveAllCrossoverDetail; crossover identification completely self-contained here
#########################################################################################################################################

package Crossover;


use strict;
use Exporter;
use globals;
our @ISA = ('Exporter');
our @EXPORT = ('FindCrossovers','getCrossOverDetail');

my $dbh;

sub FindCrossovers($){
	my $prevStatus=-1;
	$dbh=shift;
	print "FindCrossovers\n";
	PrepareMACDataTable();
	$dbh->do("update GraphData set selected=0,available=1");

	my $i=1;
	my $maxIterations=30;
	my $status=keepGoing();
	while(($status>0)&&($status!=$prevStatus)){
		print "---------------------Interation $i -------------------------\n";
		SolveBaseCase();
		
		Learn();
		
		MarkUnavailable();
		$i++;
		$prevStatus=$status;
		$status=keepGoing();
	}
	print "--------------------------- FINISHED ----------------------------\n";
	SaveAllCrossoverDetail();

}

sub keepGoing(){
	my $sql="select * from GraphData where selected=0 and available=1";
	my $sth=$dbh->prepare($sql);
	my $status;
	$sth->execute();
	$status=$sth->rows;
	return $status;
}

sub SolveBaseCase(){

	#grab those v/e who have only one possible neighbor
	my $sql="select count(*) as c, vertex,edge from GraphData where selected=0 and available=1 group by vertex,edge having c=1";
	print "SolveBaseCase: $sql\n";
	my $sth=$dbh->prepare($sql);
	$sth->execute();
	my ($sth2,$sql2,$r2);
	my $r=$sth->fetchrow_hashref();
	while($r){
		#print "$r->{vertex} $r->{edge}\n";
		$sql2="select candidate from GraphData where vertex=$r->{vertex} and edge=$r->{edge} and available=1";
		$sth2=$dbh->prepare($sql2);
		$sth2->execute();
		
		$r2=$sth2->fetchrow_hashref();
		MarkNeighbor($r->{vertex},$r->{edge},$r2->{candidate});	
		$r=$sth->fetchrow_hashref();
	}
	#$sth2->finish();
	$sth->finish;
}



sub Learn()
{

	my $sql="select distinct GraphData.vertex,GraphData.edge from GraphData 
        	where selected=0 and available=1";
	print "$sql\n";
	my $sth=$dbh->prepare($sql);
	$sth->execute();
	print "Rows: ".$sth->rows."\n";
	my $r=$sth->fetchrow_hashref();
	
	my $nvertex;
	while($r){

		$nvertex=GetNeighbor($r->{vertex},$r->{edge});
		if ($nvertex!=-1){
			MarkNeighbor($r->{vertex},$r->{edge},$nvertex);
		}
		print "Main: $r->{vertex} $r->{edge} has ne $nvertex\n";
		$r=$sth->fetchrow_hashref();	
	
	}
}


sub MarkUnavailable($){
	my $sql="select vertex,sum(selected) as s,count(distinct edge) as c from GraphData group by vertex";
	my $sth=$dbh->prepare($sql);
	my $sth2;
	$sth->execute();
	
	my $r=$sth->fetchrow_hashref();

	while($r){
		if($r->{s}==$r->{c}){
			#this vertex is finished and cannot be any other vertex's neighbor
			$sql="update GraphData set available=0 where selected=0 and candidate=$r->{vertex}";
			$sth2=$dbh->prepare($sql);
			$sth2->execute();
			$sth2->finish();
			print "MarkUnavailable: $sql\n";
		}
		$r=$sth->fetchrow_hashref();
	}

}
sub MarkNeighbor($$$){
	my $v=shift;
	my $e=shift;
	my $n=shift;
	my $sql="update GraphData set selected=1 where vertex=$v and edge=$e and candidate=$n";
	#return $sql;
	print "MarkNeighbor: $sql\n";
	my $sth=$dbh->prepare($sql);
	$sth->execute();

	$sql="update GraphData set available=0 where vertex=$v and edge=$e and candidate!=$n";
	print "MarkNeighbor: $sql\n";
	$sth=$dbh->prepare($sql);
	$sth->execute();
}

sub GetNeighbor($$){
	my $nv=shift;
	my $nedge=shift;
	print "GetNeighbor: $nv $nedge\n";
	my $sql="select vertex from GraphData where candidate=$nv and selected=1 and available=1";
	my $sth=$dbh->prepare($sql);
	my $sth2;
	my $v=-1;
	$sth->execute();
	print "GetNeighbor: $sql\n";
	print "GetNeighbor: Rows=".$sth->rows."\n";
	my $r=$sth->fetchrow_hashref();
	my $stop=0;
	while(($r)&&($stop==0)){
		$v=$r->{vertex};
		$sql="select edge from GraphData where vertex=$nv and candidate=$v and selected=1";
		$sth2=$dbh->prepare($sql);
		print "$sql\n";
		$sth2->execute();
		if($sth2->rows==1){
			#another edge already has $v as neighbor
			print "Bad!\n";
			$v=-1;
		}else{
			#this is good
			$stop=1;
		}
		$r=$sth->fetchrow_hashref();

	}

	$sth->finish();
	return $v;
}


sub PrepareMACDataTable()
{

	#we want to retain only interfaces that have multiple MACs on them
	my $sql="select count(*)as c,switch,ifnum from MACData group by switch,ifnum";
	my $sth=$dbh->prepare($sql);
	my $sth2;
	$sth->execute();
	my $r=$sth->fetchrow_hashref(); 
	while($r) 
	{
		if ($r->{c}==1){
			$sql="delete from MACData where switch='$r->{switch}' and ifnum=$r->{ifnum}";
			$sth2=$dbh->prepare($sql);
			$sth2->execute();	
		}
		$r=$sth->fetchrow_hashref();

	}

	#now we need to identify the switch that the MAC is directly attached to
	$sql="update MACData, Port set MACData.macOwner=Port.switch where MACData.MAC=Port.MAC";
	$sth=$dbh->prepare($sql);
	$sth->execute();

	#now assign integer ids (here the switch nodeIDs) that can be fed into GraphTable as vertices

	$sql="update MACData,Devices set MACData.switchID=Devices.nodeID where MACData.switch=Devices.PrimaryIP";
	$dbh->do($sql);
	$sql="update MACData,Devices set MACData.macOwnerID=Devices.nodeID where MACData.macOwner=Devices.PrimaryIP";
	$dbh->do($sql);

	$dbh->do("delete from MACData where macOwner is null");
        $dbh->do("delete from MACData where switchID=macOwnerID");

	PrepareGraphData();
	$sth->finish();
}
sub PrepareGraphData()
{
        $dbh->do("delete from GraphData");
        my $sql="insert into GraphData(vertex,edge,candidate)
                select distinct switchID,ifnum,macOwnerID from MACData where macOwnerID is not null";
        $dbh->do($sql);

}

sub SaveAllCrossoverDetail()
{
	my ($detail,$mac,$sth,$sql,$r);
	$sql="select GraphData.*, PrimaryIP from GraphData 
		left join Devices on Devices.nodeID=GraphData.vertex
		where selected=1 and available=1";
	$sth=$dbh->prepare($sql);
	$sth->execute();
	$r=$sth->fetchrow_hashref();
	while($r){
		#$mac="$r->{PrimaryIP}.$r->{edge}";
		$detail=getCrossOverDetail($r->{vertex},$r->{edge});
		SaveCrossover($r->{PrimaryIP},$r->{edge},$detail);
		
		$r=$sth->fetchrow_hashref();
	}
	$sth->finish();
}
sub SaveCrossover($$$){
	my $switch=shift;
	my $ifnum=shift;
	my $crossOverDetail=shift;
	my $now=time();

	my $sql="select * from Crossovers where Switch='$switch' and ifnum=$ifnum";
        my $sth=$dbh->prepare($sql);
        $sth->execute();
        if($sth->rows==0){
		if ($crossOverDetail eq ""){
			$crossOverDetail="Crossover";
		}
        	$sql="insert into Crossovers values('$switch',$ifnum,'$crossOverDetail',$now)";
                $sth=$dbh->prepare($sql);
                $sth->execute();


        }else{
		if ($crossOverDetail ne ""){
	        	$sql="update Crossovers set detail='$crossOverDetail',lastupdated=$now where switch='$switch' and ifnum=$ifnum";
        	        $sth=$dbh->prepare($sql);
	                $sth->execute();
		}
        }


	print "$sql\n";
}
sub getCrossOverDetail($$)
{
        my $nodeID=shift;
        my $ifnum=shift;
	my ($sql,$sth,$r);
        my $sth2;
        my $r2;
        $sql="select vertex,edge,candidate,Devices.description 
                        from GraphData 
                        left join Devices on Devices.nodeID=candidate
                        where vertex=$nodeID and edge=$ifnum and selected=1";
        $sth=$dbh->prepare($sql);
        #Log("$sql\n");
        $sth->execute();
        my $desc="";
        my $port="";
        if ($sth->rows==1){
                $r=$sth->fetchrow_hashref();
                $sql="select IFDescriptions.description from GraphData 
                        left join Devices on Devices.nodeID=GraphData.vertex
                        left join IFDescriptions on IFDescriptions.ip=Devices.PrimaryIP and IFDescriptions.ifnum=edge 
                        where vertex=$r->{candidate} and candidate=$nodeID and selected=1";
                $sth2=$dbh->prepare($sql);
                $sth2->execute();
                if ($sth2->rows==1){
                        $r2=$sth2->fetchrow_hashref();
                        $port="$r2->{description} on ";
                }
                #Log("$sql\n");
                $desc="Crossover to $port".$r->{description};
        }

        $sth->finish();
        return $desc;
}

1;
