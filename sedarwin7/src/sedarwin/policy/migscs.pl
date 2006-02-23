#!/usr/bin/perl

open (OUT, "> sebsd_migscs") || die ("cant open sebsd_migscs");
my %scs;
my $curclass = 0;

while (<>) {
  if (/^class .*subsystem +([0-9]+)/) {
    $curclass++;
    if (@$scs{$1}) {
      push @{$scs{$1}}, $curclass;
    } else {
      $scs{$1} = [$curclass];
    }
  }
  elsif (/^class/) { $curclass++; }
}

print "$curclass classes\n";
my $out;

foreach my $c (keys %scs) {
  my @ca = @{$scs{$c}};
  $out .= pack ('III', $c, 1+$#ca, 100);
  foreach my $c (@ca) { $out .= pack ('I', $c); }
}

print OUT $out;
close (OUT);

