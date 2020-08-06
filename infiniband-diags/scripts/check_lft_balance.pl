#!/usr/bin/perl
#
# Copyright (C) 2001-2003 The Regents of the University of California.
# Copyright (c) 2006 The Regents of the University of California.
# Copyright (c) 2007-2008 Voltaire, Inc. All rights reserved.
#
# Produced at Lawrence Livermore National Laboratory.
# Written by Ira Weiny <weiny2@llnl.gov>
#            Jim Garlick <garlick@llnl.gov>
#            Albert Chu <chu11@llnl.gov>
#
# This software is available to you under a choice of one of two
# licenses.  You may choose to be licensed under the terms of the GNU
# General Public License (GPL) Version 2, available from the file
# COPYING in the main directory of this source tree, or the
# OpenIB.org BSD license below:
#
#     Redistribution and use in source and binary forms, with or
#     without modification, are permitted provided that the following
#     conditions are met:
#
#      - Redistributions of source code must retain the above
#        copyright notice, this list of conditions and the following
#        disclaimer.
#
#      - Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials
#        provided with the distribution.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

use strict;

use Getopt::Std;

my $ibnetdiscover_cache = "";
my $dump_lft_file       = "";
my $verbose             = 0;

my $switch_lid                            = undef;
my $switch_guid                           = undef;
my $switch_name                           = undef;
my %switch_port_count                     = ();
my @switch_maybe_directly_connected_hosts = ();
my $host                                  = undef;
my @host_ports                            = ();

my @lft_lines = ();
my $lft_line;

my $lids_per_port;
my $lids_per_port_calculated;

my $heuristic_flag = 0;

sub usage
{
	my $prog = `basename $0`;

	chomp($prog);
	print "Usage: $prog -l lft-output -i ibnetdiscover-cache [-e] [-v]\n";
	print "  Generate lft-output via \"dump_lfts.sh > lft-output\"\n";
	print "  Generate ibnetdiscover-cache via \"ibnetdiscover --cache ibnetdiscover-cache\"\n";
	print "  -e turn on heuristic(s) to look at switch balances deeper\n";
	print "  -v verbose output, output all switches\n";
	exit 2;
}

sub is_port_up
{
	my $iblinkinfo_output = $_[0];
	my $port              = $_[1];
	my $decport;
	my @lines;
	my $line;

	$port =~ /0+(.+)/;
	$decport = $1;

	# Add a space if necessary
	if ($decport >= 1 && $decport <= 9) {
		$decport = " $decport";
	}

	@lines = split("\n", $iblinkinfo_output);
	foreach $line (@lines) {
		if ($line =~ /$decport\[..\] ==/) {
			if ($line =~ /Down/) {
				return 0;
			}
			else {
				return 1;
			}
		}
	}

	# return 0 if not found
	return 0;
}

sub is_directly_connected
{
	my $iblinkinfo_output = $_[0];
	my $port              = $_[1];
	my $decport;
	my $str;
	my $rv = 0;
	my $host_tmp;
	my @lines;
	my $line;

	if (($switch_port_count{$port} != $lids_per_port)
		|| !(@switch_maybe_directly_connected_hosts))
	{
		return $rv;
	}

	$port =~ /0+(.+)/;
	$decport = $1;

	# Add a space if necessary
	if ($decport >= 1 && $decport <= 9) {
		$decport = " $decport";
	}

	@lines = split("\n", $iblinkinfo_output);
	foreach $line (@lines) {
		if ($line =~ /$decport\[..\] ==/) {
			$str = $line;
		}
	}

	if ($str =~ "Active") {
		$str =~
/[\d]+[\s]+[\d]+\[.+\]  \=\=.+\=\=>[\s]+[\d]+[\s]+[\d]+\[.+\] \"(.+)\".+/;
		for $host_tmp (@switch_maybe_directly_connected_hosts) {
			if ($1 == $host_tmp) {
				$rv = 1;
				last;
			}
		}
	}

	return $rv;
}

sub output_switch_port_usage
{
	my $min_usage = 999999;
	my $max_usage = 0;
	my $min_usage2 = 999999;
	my $max_usage2 = 0;
	my @ports     = (
		"001", "002", "003", "004", "005", "006", "007", "008",
		"009", "010", "011", "012", "013", "014", "015", "016",
		"017", "018", "019", "020", "021", "022", "023", "024",
		"025", "026", "027", "028", "029", "030", "031", "032",
		"033", "034", "035", "036"
	);
	my @output_ports = ();
	my @double_check_ports = ();
	my $port;
	my $iblinkinfo_output;
	my $is_unbalanced = 0;
	my $ports_on_switch = 0;
	my $all_zero_flag = 1;
	my $ret;

        $iblinkinfo_output = `iblinkinfo --load-cache $ibnetdiscover_cache -S $switch_guid`;

	for $port (@ports) {
		if (!defined($switch_port_count{$port})) {
			$switch_port_count{$port} = 0;
		}

		if ($switch_port_count{$port} == 0) {
			# If port is down, don't use it in this calculation
			$ret = is_port_up($iblinkinfo_output, $port);
			if ($ret == 0) {
				next;
			}
		}

		$ports_on_switch++;

		# If port is directly connected to a node, don't use
		# it in this calculation.
		if (is_directly_connected($iblinkinfo_output, $port) == 1) {
			next;
		}

		# Save off ports that should be output later
		push(@output_ports, $port);

		if ($switch_port_count{$port} < $min_usage) {
			$min_usage = $switch_port_count{$port};
		}
		if ($switch_port_count{$port} > $max_usage) {
			$max_usage = $switch_port_count{$port};
		}
	}

	if ($max_usage > ($min_usage + 1)) {
		$is_unbalanced = 1;
	}

	# In the event this is a switch lineboard, it will almost always never
	# balanced.  Half the ports go up to the spine, and the rest of the ports
	# go down to HCAs.  So we will do a special heuristic:
	#
	# If about 1/2 of the remaining ports are balanced, then we will consider the
	# entire switch balanced.
	#
	# Also, we do this only if there are enough alive ports on the switch to care.
	# I picked 12 somewhat randomly
	if ($heuristic_flag == 1
	    && $is_unbalanced == 1
	    && $ports_on_switch > 12) {

		@double_check_ports = ();

		for $port (@output_ports) {
			if ($switch_port_count{$port} == $max_usage
			    || $switch_port_count{$port} == ($max_usage - 1)
			    || $switch_port_count{$port} == 0) {
				next;
			}

			push(@double_check_ports, $port);
		}

		# we'll call half +/- 1 "about half"
		if (@double_check_ports == int($ports_on_switch / 2)
		    || @double_check_ports == int($ports_on_switch / 2) + 1
		    || @double_check_ports == int($ports_on_switch / 2) - 1) {
			for $port (@double_check_ports) {
				if ($switch_port_count{$port} < $min_usage2) {
					$min_usage2 = $switch_port_count{$port};
				}
				if ($switch_port_count{$port} > $max_usage2) {
					$max_usage2 = $switch_port_count{$port};
				}
			}

			if (!($max_usage2 > ($min_usage2 + 1))) {
				$is_unbalanced = 0;
			}
		}
	}

	# Another special case is when you have a non-fully-populated switch
	# Many ports will be zero.  So if all active ports != max or max-1 are = 0
	# we will also consider this balanced.
	if ($heuristic_flag == 1
	    && $is_unbalanced == 1
	    && $ports_on_switch > 12) {

		@double_check_ports = ();

		for $port (@output_ports) {
			if ($switch_port_count{$port} == $max_usage
			    || $switch_port_count{$port} == ($max_usage - 1)) {
				next;
			}

			push(@double_check_ports, $port);
		}

		for $port (@double_check_ports) {
			if ($switch_port_count{$port} != 0) {
				$all_zero_flag = 0;
				last;
			}
		}

		if ($all_zero_flag == 1) {
			$is_unbalanced = 0;
		}
	}

	if ($verbose || $is_unbalanced == 1) {
		if ($is_unbalanced == 1) {
			print "Unbalanced Switch Port Usage: ";
			print "$switch_name, $switch_guid\n";
		} else {
			print
			  "Switch Port Usage: $switch_name, $switch_guid\n";
		}
		for $port (@output_ports) {
			print "Port $port: $switch_port_count{$port}\n";
		}
	}
}

sub process_host_ports
{
	my $test_port;
	my $tmp;
	my $flag = 0;

	if (@host_ports == $lids_per_port) {
		# Are all the host ports identical?
		$test_port = $host_ports[0];
		for $tmp (@host_ports) {
			if ($tmp != $test_port) {
				$flag = 1;
				last;
			}
		}
		# If all host ports are identical, maybe its directly
		# connected to a host.
		if ($flag == 0) {
			push(@switch_maybe_directly_connected_hosts, $host);
		}
	}
}

if (!getopts("hl:i:ve")) {
	usage();
}

if (defined($main::opt_h)) {
	usage();
}

if (defined($main::opt_l)) {
	$dump_lft_file = $main::opt_l;
} else {
	print STDERR ("Must specify dump lfts file\n");
	usage();
	exit 1;
}

if (defined($main::opt_i)) {
	$ibnetdiscover_cache = $main::opt_i;
} else {
	print STDERR ("Must specify ibnetdiscover cache\n");
	usage();
	exit 1;
}

if (defined($main::opt_v)) {
	$verbose = 1;
}

if (defined($main::opt_e)) {
	$heuristic_flag = 1;
}

if (!open(FH, "< $dump_lft_file")) {
	print STDERR ("Couldn't open dump lfts file: $dump_lft_file: $!\n");
}

@lft_lines = <FH>;

foreach $lft_line (@lft_lines) {
	chomp($lft_line);
	if ($lft_line =~ /Unicast/) {
		if (@host_ports) {
			process_host_ports();
		}
		if (defined($switch_name)) {
			output_switch_port_usage();
		}
		if ($lft_line =~ /Unicast lids .+ of switch DR path slid .+ guid (.+) \((.+)\)/) {
			$switch_guid                           = $1;
			$switch_name                           = $2;
		}
		if ($lft_line =~ /Unicast lids .+ of switch Lid .+ guid (.+) \((.+)\)/) {
			$switch_guid                           = $1;
			$switch_name                           = $2;
		}
		@switch_maybe_directly_connected_hosts = ();
		%switch_port_count                     = ();
		@host_ports                            = ();
		$lids_per_port                         = 0;
		$lids_per_port_calculated              = 0;
	} elsif ($lft_line =~ /Channel/ || $lft_line =~ /Router/) {
		$lft_line =~ /.+ (.+) : \(.+ portguid .+: '(.+)'\)/;
		$host = $2;
		$switch_port_count{$1}++;
		if (@host_ports) {
			process_host_ports();
		}
		@host_ports = ($1);

		if ($lids_per_port == 0) {
			$lids_per_port++;
		} else {
			$lids_per_port_calculated++;
		}
	} elsif ($lft_line =~ /path/) {
		$lft_line =~ /.+ (.+) : \(path #. out of .: portguid .+\)/;
		$switch_port_count{$1}++;
		if ($lids_per_port_calculated == 0) {
			$lids_per_port++;
		}
		push(@host_ports, $1);
	} else {
		if ($lids_per_port) {
			$lids_per_port_calculated++;
		}
		next;
	}
}

if (@host_ports) {
	process_host_ports();
}
output_switch_port_usage();
