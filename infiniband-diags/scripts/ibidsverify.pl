#!/usr/bin/perl
#
# Copyright (c) 2007-2008 Voltaire, Inc. All rights reserved.
# Copyright (c) 2006 The Regents of the University of California.
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
use IBswcountlimits;

my $return_code = 0;

sub usage_and_exit
{
	my $prog = $_[0];
	print "Usage: $prog [-Rh]\n";
	print
"   Validate LIDs and GUIDs (check for zero and duplicates) in the local subnet\n";
	print "   -h This help message\n";
	print
"   -R Recalculate ibnetdiscover information (Default is to reuse ibnetdiscover output)\n";
	print "   -C <ca_name> use selected Channel Adaptor name for queries\n";
	print "   -P <ca_port> use selected channel adaptor port for queries\n";
	exit 2;
}

my $argv0          = `basename $0`;
my $regenerate_map = undef;
my $ca_name        = "";
my $ca_port        = "";

chomp $argv0;
if (!getopts("hRC:P:"))          { usage_and_exit $argv0; }
if (defined $Getopt::Std::opt_h) { usage_and_exit $argv0; }
if (defined $Getopt::Std::opt_R) { $regenerate_map = $Getopt::Std::opt_R; }
if (defined $Getopt::Std::opt_C) { $ca_name        = $Getopt::Std::opt_C; }
if (defined $Getopt::Std::opt_P) { $ca_port        = $Getopt::Std::opt_P; }

sub validate_non_zero_lid
{
	my ($lid)      = shift(@_);
	my ($nodeguid) = shift(@_);
	my ($nodetype) = shift(@_);

	if ($lid eq 0) {
		print "LID 0 found for $nodetype NodeGUID $nodeguid\n";
		return 1;
	}
	return 0;
}

sub validate_non_zero_guid
{
	my ($lid)      = shift(@_);
	my ($guid)     = shift(@_);
	my ($nodetype) = shift(@_);

	if ($guid eq 0x0) {
		print "$nodetype GUID 0x0 found with LID $lid\n";
		return 1;
	}
	return 0;
}

$insert_lid::lids           = undef;
$insert_nodeguid::nodeguids = undef;
$insert_portguid::portguids = undef;

sub insert_lid
{
	my ($lid)      = shift(@_);
	my ($nodeguid) = shift(@_);
	my ($nodetype) = shift(@_);
	my $rec        = undef;
	my $status     = "";

	$status = validate_non_zero_lid($lid, $nodeguid, $nodetype);
	if ($status eq 0) {
		if (defined($insert_lid::lids{$lid})) {
			print
"LID $lid already defined for NodeGUID $insert_lid::lids{$lid}->{nodeguid}\n";
			$return_code = 1;
		} else {
			$rec = {lid => $lid, nodeguid => $nodeguid};
			$insert_lid::lids{$lid} = $rec;
		}
	} else {
		$return_code = $status;
	}
}

sub insert_nodeguid
{
	my ($lid)      = shift(@_);
	my ($nodeguid) = shift(@_);
	my ($nodetype) = shift(@_);
	my $rec        = undef;
	my $status     = "";

	$status = validate_non_zero_guid($lid, $nodeguid, $nodetype);
	if ($status eq 0) {
		if (defined($insert_nodeguid::nodeguids{$nodeguid})) {
			print
"NodeGUID $nodeguid already defined for LID $insert_nodeguid::nodeguids{$nodeguid}->{lid}\n";
			$return_code = 1;
		} else {
			$rec = {lid => $lid, nodeguid => $nodeguid};
			$insert_nodeguid::nodeguids{$nodeguid} = $rec;
		}
	} else {
		$return_code = $status;
	}
}

sub validate_portguid
{
	my ($portguid)  = shift(@_);
	my ($nodeguid)  = shift(@_);

	if (($nodeguid ne $portguid)
		&& defined($insert_nodeguid::nodeguids{$portguid})) {
		print "PortGUID $portguid is an invalid duplicate of a NodeGUID\n";
		$return_code = 1;
	}
}

sub insert_portguid
{
	my ($lid)       = shift(@_);
	my ($portguid)  = shift(@_);
	my ($nodetype)  = shift(@_);
	my ($nodeguid)  = shift(@_);
	my $rec         = undef;
	my $status      = "";

	$status = validate_non_zero_guid($lid, $portguid, $nodetype);
	if ($status eq 0) {
		if (defined($insert_portguid::portguids{$portguid})) {
			print
"PortGUID $portguid already defined for LID $insert_portguid::portguids{$portguid}->{lid}\n";
			$return_code = 1;
		} else {
			$rec = {lid => $lid, portguid => $portguid};
			$insert_portguid::portguids{$portguid} = $rec;
			validate_portguid($portguid, $nodeguid);
		}
	} else {
		$return_code = $status;
	}
}

sub main
{
	my $cache_file = get_cache_file($ca_name, $ca_port);

	if ($regenerate_map || !(-f "$cache_file")) {
		generate_ibnetdiscover_topology($ca_name, $ca_port);
	}
	open IBNET_TOPO, "<$cache_file"
	  or die "Failed to open ibnet topology: $!\n";

	my $nodetype  = "";
	my $nodeguid  = "";
	my $portguid  = "";
	my $lid       = "";
	my $line      = "";
	my $firstport = "";

	while ($line = <IBNET_TOPO>) {

		if ($line =~ /^caguid=(.*)/ || $line =~ /^rtguid=(.*)/) {
			$nodeguid = $1;
			$nodetype = "";
		}

		if ($line =~ /^switchguid=(.*)/) {
			$nodeguid = $1;
			$portguid = "";
			$nodetype = "";
		}
		if ($line =~ /^switchguid=(.*)\((.*)\)/) {
			$nodeguid = $1;
			$portguid = "0x" . $2;
		}

		if ($line =~ /^Switch.*\"S-(.*)\"\s+# (.*) port.* lid (\d+) .*/) {
			$nodetype  = "switch";
			$firstport = "yes";
			$lid       = $3;
			insert_lid($lid, $nodeguid, $nodetype);
			insert_nodeguid($lid, $nodeguid, $nodetype);
			if ($portguid ne "") {
				insert_portguid($lid, $portguid, $nodetype, $nodeguid);
			}
		}
		if ($line =~ /^Ca.*/) {
			$nodetype  = "ca";
			$firstport = "yes";
		}
		if ($line =~ /^Rt.*/) {
			$nodetype  = "router";
			$firstport = "yes";
		}

		if ($nodetype eq "ca" || $nodetype eq "router") {
			if ($line =~ /"S-(.*)\# lid (\d+) .*/) {
				$lid = $2;
				insert_lid($lid, $nodeguid, $nodetype);
				if ($firstport eq "yes") {
					insert_nodeguid($lid, $nodeguid, $nodetype);
					$firstport = "no";
				}
			}
			if ($line =~ /^.*"H-(.*)\# lid (\d+) .*/) {
				$lid = $2;
				insert_lid($lid, $nodeguid, $nodetype);
				if ($firstport eq "yes") {
					insert_nodeguid($lid, $nodeguid, $nodetype);
					$firstport = "no";
				}
			}
			if ($line =~ /^.*"R-(.*)\# lid (\d+) .*/) {
				$lid = $2;
				insert_lid($lid, $nodeguid, $nodetype);
				if ($firstport eq "yes") {
					insert_nodeguid($lid, $nodeguid, $nodetype);
					$firstport = "no";
				}
			}
			if ($line =~ /^\[(\d+)\]\((.*)\)/) {
				$portguid = "0x" . $2;
				insert_portguid($lid, $portguid, $nodetype, $nodeguid);
			}
		}

	}

	close IBNET_TOPO;
}
main;

exit ($return_code);

