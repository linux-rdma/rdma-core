#!/usr/bin/perl
#
# Copyright (c) 2006 The Regents of the University of California.
#
# Produced at Lawrence Livermore National Laboratory.
# Written by Ira Weiny <weiny2@llnl.gov>.
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

my $print_action = "no";
my $report_port_info = undef;
my $single_switch = undef;
my $include_data_counters = undef;

# =========================================================================
#
sub report_counts
{
   my $addr = $_[0];
   my $port = $_[1];

   if (any_counts())
   {
      print ("   GUID $addr port $port:");
      check_counters($print_action);
      if ($include_data_counters)
      {
         check_data_counters($print_action);
      }
      print ("\n");

      if ($report_port_info) {
         my $lid = "";
         my $speed = "";
         my $width = "";
         my $data = `smpquery -G portinfo $addr $port`;
         my @lines = split("\n", $data);
         foreach my $line (@lines) {
            if ($line =~ /^# Port info: Lid (\w+) port.*/) { $lid = $1; }
            if ($line =~ /^LinkSpeedActive:\.+(.*)/) { $speed = $1; }
            if ($line =~ /^LinkWidthActive:\.+(.*)/) { $width = $1; }
         }
         my $hr = $IBswcountlimits::link_ends{"$addr"}{$port};
	 if ($hr)
	 {
	     printf ("         Link info: %6s %4s[%2s]  ==(%3s %s)==>  %18s %4s[%2s] \"%s\"\n",
		     $lid, $port, $hr->{loc_ext_port}, $width, $speed,
		     $hr->{rem_guid}, $hr->{rem_port}, $hr->{rem_ext_port}, $hr->{rem_desc});
	 }
	 else
	 {
	     printf ("         Link info: %6s %4s[  ]  ==(%3s %s)==>     (Disconnected)\n",
		     $lid, $port, $width, $speed);
	 }
      }
   }
}

# =========================================================================
# use perfquery to get the counters.
sub get_counts
{
   my $addr = $_[0];
   my $port = $_[1];
   my $data = `perfquery -G $addr $port`;
   my @lines = split("\n", $data);
   foreach my $line (@lines)
   {
      foreach my $count (@IBswcountlimits::counters)
      {
         if ($line =~ /^$count:\.+(\d+)/)
         {
            $IBswcountlimits::cur_counts{$count} = $1;
         }
      }
   }
}

# =========================================================================
#
my %switches = ();
sub get_switches
{
   my $data = `ibswitches $IBswcountlimits::cache_dir/ibnetdiscover.topology`;
   my @lines = split("\n", $data);
   foreach my $line (@lines) {
      if ($line =~ /^Switch\s+:\s+(\w+)\s+ports\s+(\d+)\s+.*/)
      {
         $switches{$1} = $2;
      }
   }
}

# =========================================================================
#
sub usage_and_exit
{
   my $prog = $_[0];
   print "Usage: $prog [-a -c -r -R -s <err1,err2,...> -S <switch_guid> -d]\n";
   print "   Report counters on all switches in subnet\n";
   print "   -a Report an action to take\n";
   print "   -c suppress some of the common counters\n";
   print "   -r report port configuration information\n";
   print "   -R Recalculate ibnetdiscover information\n";
   print "   -s <err1,err2,...> suppress errors listed\n";
   print "   -S <switch_guid> query only <switch_guid>\n";
   print "   -d include the data counters in the output\n";
   exit 0;
}

my $argv0 = `basename $0`;
my $regenerate_map = undef;
my $single_switch = undef;

chomp $argv0;
if (!getopts("has:crRS:d")) { usage_and_exit $argv0; }
if (defined $Getopt::Std::opt_h) { usage_and_exit $argv0; }
if (defined $Getopt::Std::opt_a) { $print_action = "yes"; }
if (defined $Getopt::Std::opt_s) { @IBswcountlimits::suppress_errors = split (",", $Getopt::Std::opt_s); }
if (defined $Getopt::Std::opt_c)
{
   @IBswcountlimits::suppress_errors = split (",", "RcvSwRelayErrors");
}
if (defined $Getopt::Std::opt_r) { $report_port_info = $Getopt::Std::opt_r; }
if (defined $Getopt::Std::opt_R) { $regenerate_map = $Getopt::Std::opt_R; }
if (defined $Getopt::Std::opt_S) { $single_switch = $Getopt::Std::opt_S; }
if (defined $Getopt::Std::opt_d) { $include_data_counters = $Getopt::Std::opt_d; }

sub main
{
   if (@IBswcountlimits::suppress_errors)
   {
      my $msg = join(",", @IBswcountlimits::suppress_errors);
      print "Suppressing: $msg\n";
   }
   if ($regenerate_map || !(-f "$IBswcountlimits::cache_dir/ibnetdiscover.topology")) { generate_ibnetdiscover_topology; }
   get_switches;
   get_link_ends;
   foreach my $sw_addr (keys %switches) {
      if ($single_switch && $sw_addr ne "$single_switch") { next; }

      my $switch_prompt = "no";
      foreach my $sw_port (1 .. $switches{$sw_addr}) {
         clear_counters;
         get_counts($sw_addr, $sw_port);
         if (any_counts() && $switch_prompt eq "no")
         {
            my $hr = $IBswcountlimits::link_ends{"$sw_addr"}{$sw_port};
            printf ("Errors for %18s \"%s\"\n", $sw_addr, $hr->{loc_desc});
            $switch_prompt = "yes";
         }
         report_counts($sw_addr, $sw_port);
      }
   }
}
main;

