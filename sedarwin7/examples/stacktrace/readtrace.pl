#!/usr/bin/perl -w
# process MAC trace from kernel
# Usage: readtrace path
#  input: output from the sec_trace command
#  output: on stdout, one line per trace entry, format
#     count target|routine+ofset|routine+offset ...
#
# 07/16/04 THVV 1.0

while ($#ARGV >= 0) {
    # do control args here
    $input = shift;
}

$traceline = '';
$n = 0;
$ntl = 0;
$ignored =  0;
open(INFILE, "$input") or die "$input not found";
while (<INFILE>) {
    chomp;
    if (/^  0x........ 0x........ *(.*)$/) {
	#  0x1258bd30 0x0029928c _mac_init_bsd+300
	$trace = $1;
	if ($trace eq '') {
	} elsif ($trace =~ /_act_execute_returnhandlers\+/) {
	    $ignored++;		# skip some routines that are just noise
	} elsif ($trace =~ /___sysctl\+/) {
	    $ignored++;
	} elsif ($trace =~ /_start_kernel_threads\+/) {
	    $ignored++;
	} elsif ($trace =~ /_bsd_init\+/) {
	    $ignored++;
	} elsif ($trace =~ /_shandler\+/) {
	    $ignored++;
	} elsif ($trace =~ /_unix_syscall\+/) {
	    $ignored++;
	} elsif ($trace =~ /_thread_exception_return\+/) {
	    $ignored++;
	} elsif ($trace =~ /_mac_.*\+/) {
	    $ignored++;
	} elsif ($trace =~ /_crget\+/) {
	    $ignored++;
	} elsif ($trace =~ /_special_handler\+/) {
	    $ignored++;
	} elsif ($trace =~ /^_(.*)\+\d+/) {
	    # keeper
	    $ntl++;
	    $traceline .= '|'. $1; # add the routine name to the trace string
	} else {
	    $ignored++;
	    print "\#\#\#$_\n";	# invalid
	}
    } elsif (/^  0x........ 0000000000 *$/) {
	$ignored++;		# no return ptr
    } elsif (/^[\w]+$/) {	# routine name
	if ($traceline ne '') {
	    $tra[$n] = $traceline; # save old
	    $n++;
	}
	#init_bsd
	$traceline = $_;
    } else {			# header or garbage, print it
	$ignored++;
	#204541 calls 0 wraps, max depth 1
	print "\# $_\n";		# invalid
    }
} # while infile
close(INFILE);
if ($traceline ne '') {
    $tra[$n] = $traceline;
    $n++;
}
print "\# calls $n, tracelines $ntl, ignored $ignored\n";

# find runs of consecutive identicals
$i = 0;
while ($i<$n) {
    $runlth[$i] = 1;		# this is a run of 1
    $j = 1;
    while (($i+$j < $n) && ($tra[$i] eq $tra[$i+$j])) {
	$runlth[$i]++;		# another one in this run
	$runlth[$i+$j] = -1;	# this is a dupe
	$j++;
    }
    $i += $runlth[$i];
}

# write out compressed file
for ($i=0; $i<$n; $i++) {
    if ($runlth[$i] == 1) {
	print "1 $tra[$i]\n";
   } elsif ($runlth[$i] > 1) {
	# head of a run
	print "$runlth[$i] $tra[$i]\n";
    } elsif ($runlth[$i] == -1) {
	# dupe
    } else {
	#error
    }
}
# end
