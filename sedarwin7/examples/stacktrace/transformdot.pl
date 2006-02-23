#!/usr/bin/perl -w
# transform trace file to dot format, showing busy calls heavier
# Usage: transformdot path
#  input: output from readtrace.pl
#  output: on stdout, one line per call, format
#     routine1 -> routine2 [label="N",decorate=true,sytle="setlinewidth(x)"];]
#  uses int(1+log(N)) as line weight
#
# 07/19/04 THVV 1.0

%values = ();

$filename = shift;
open(F, $filename) or die "$filename not found";
while (<F>) {
    if (/ (\d*) ([a-zA-Z0-9_]*)\|(.*)$/) {
	$weight = $1;
	$head = $2;
	$string = $3;
	while ($string =~ /^([a-zA-Z0-9_]*)\|(.*)$/) {
	    $lhs = $1;
	    $rhs = $2;
	    &enter($head,$lhs,$weight);
	    $head = $lhs;
	    $string = $rhs;
	} # while
	&enter($head,$string,$weight);
    }
} # while F
close F;

foreach (keys %values) {
    $x = $_;
    $y = $values{$x};
    $z = int(1+log($y));
    print "$x [label=\"$y\",decorate=true,style=\"setlinewidth($z)\"];\n";    
} # foreach

sub enter {
    my $lt = shift;
    my $rt = shift;
    my $wt = shift;
    my $z = $lt.' -> '.$rt;
    $values{$z} += $wt;
} # enter
