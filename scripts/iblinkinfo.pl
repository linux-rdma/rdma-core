#!/usr/bin/perl
#
# Copyright (c) 2006 The Regents of the University of California.
# Copyright (c) 2007 Voltaire, Inc. All rights reserved. 
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

sub usage_and_exit
{
   my $prog = $_[0];
   print "Usage: $prog [-Rhclp -S <guid>]\n";
   print "   Report link speed and connection for each port of each switch which is active\n";
   print "   -h This help message\n";
   print "   -R Recalculate ibnetdiscover information (Default is to reuse ibnetdiscover output)\n";
   print "   -S <guid> output only the switch specified by guid\n";
   print "   -d print only down links\n";
   print "   -l (line mode) print all information for each link on each line\n";
   print "   -p print additional switch settings (PktLifeTime,HoqLife,VLStallCount)\n";
   print "   -c print port capabilities (enabled/supported values)\n";
   exit 0;
}

my $argv0 = `basename $0`;
my $regenerate_map = undef;
my $single_switch = undef;
my $line_mode = undef;
my $print_add_switch = undef;
my $print_extended_cap = undef;
my $only_down_links = undef;
chomp $argv0;

if (!getopts("hcpldRS:")) { usage_and_exit $argv0; }
if (defined $Getopt::Std::opt_h) { usage_and_exit $argv0; }
if (defined $Getopt::Std::opt_R) { $regenerate_map = $Getopt::Std::opt_R; }
if (defined $Getopt::Std::opt_S) { $single_switch = $Getopt::Std::opt_S; }
if (defined $Getopt::Std::opt_d) { $only_down_links = $Getopt::Std::opt_d; }
if (defined $Getopt::Std::opt_l) { $line_mode = $Getopt::Std::opt_l; }
if (defined $Getopt::Std::opt_p) { $print_add_switch = $Getopt::Std::opt_p; }
if (defined $Getopt::Std::opt_c) { $print_extended_cap = $Getopt::Std::opt_c; }

sub main
{
   if ($regenerate_map) { generate_ibnetdiscover_topology; }
   get_link_ends;
   foreach my $switch (sort (keys (%IBswcountlimits::link_ends))) {
      if ($single_switch && $switch ne $single_switch)
      {
         next;
      }
      my $switch_prompt = "no";
      my $num_ports = get_num_ports($switch);
      if ($num_ports == 0) {
            printf("ERROR: switch $switch has 0 ports???\n");
      }
      my @output_lines = undef;
      my $pkt_lifetime = "";
      my $pkt_life_prompt = "";
      my $port_timeouts = "";
      my $print_switch = "yes";
      if ($only_down_links) { $print_switch = "no"; }
      if ($print_add_switch)
      {
         my $data = `smpquery -G switchinfo $switch`;
         if ($data eq "") {
            printf("ERROR: failed to get switchinfo for $switch\n");
         }
         my @lines = split("\n", $data);
         foreach my $line (@lines) { if ($line =~ /^LifeTime:\.+(.*)/) { $pkt_lifetime = $1; } }
         $pkt_life_prompt = sprintf(" (LT: %s)", $pkt_lifetime);
      }
      foreach my $port (1 .. $num_ports) {
         my $hr = $IBswcountlimits::link_ends{$switch}{$port};
         if ($switch_prompt eq "no" && !$line_mode)
         {
            push (@output_lines,
                sprintf ("Switch %18s %s%s:\n", $switch, $hr->{loc_desc}, $pkt_life_prompt));
            $switch_prompt = "yes";
         }
         my $data = `smpquery -G portinfo $switch $port`;
         if ($data eq "") {
            printf("ERROR: failed to get portinfo for $switch port $port\n");
         }
         my @lines = split("\n", $data);
         my $speed = "";
         my $speed_sup = "";
         my $speed_enable = "";
         my $width = "";
         my $width_sup = "";
         my $width_enable = "";
         my $state = "";
         my $hoq_life = "";
         my $vl_stall = "";
         my $phy_link_state = "";
         foreach my $line (@lines) {
            if ($line =~ /^LinkSpeedActive:\.+(.*)/) { $speed = $1; }
            if ($line =~ /^LinkSpeedEnabled:\.+(.*)/)   { $speed_enable = $1; }
            if ($line =~ /^LinkSpeedSupported:\.+(.*)/) { $speed_sup = $1; }
            if ($line =~ /^LinkWidthActive:\.+(.*)/) { $width = $1; }
            if ($line =~ /^LinkWidthEnabled:\.+(.*)/)   { $width_enable = $1; }
            if ($line =~ /^LinkWidthSupported:\.+(.*)/) { $width_sup = $1; }
            if ($line =~ /^LinkState:\.+(.*)/)          { $state = $1; }
            if ($line =~ /^HoqLife:\.+(.*)/)            { $hoq_life = $1; }
            if ($line =~ /^VLStallCount:\.+(.*)/)       { $vl_stall = $1; }
            if ($line =~ /^PhysLinkState:\.+(.*)/)      { $phy_link_state = $1; }
         }
         my $rem_guid = $hr->{rem_guid};
         my $rem_port = $hr->{rem_port};
         my $rem_lid = $hr->{rem_lid};
         my $rem_speed_sup = "";
         my $rem_speed_enable = "";
         my $rem_width_sup = "";
         my $rem_width_enable = "";
         if ($rem_lid ne "" && $rem_port ne "")
         {
            $data = `smpquery portinfo $rem_lid $rem_port`;
            if ($data eq "") {
               printf("ERROR: failed to get portinfo for $switch port $port\n");
            }
            my @lines = split("\n", $data);
            foreach my $line (@lines) {
               if ($line =~ /^LinkSpeedEnabled:\.+(.*)/)   { $rem_speed_enable = $1; }
               if ($line =~ /^LinkSpeedSupported:\.+(.*)/) { $rem_speed_sup = $1; }
               if ($line =~ /^LinkWidthEnabled:\.+(.*)/)   { $rem_width_enable = $1; }
               if ($line =~ /^LinkWidthSupported:\.+(.*)/) { $rem_width_sup = $1; }
            }
         }
	 my $line_begin = "";
	 my $ext_guid = "";
         if ($line_mode)
         {
            $line_begin = sprintf ("%18s \"%s\"%s", $switch, $hr->{loc_desc}, $pkt_life_prompt);
            $ext_guid = sprintf ("%18s", $hr->{rem_guid});
         }
	 my $capabilities = "";
	 if ($print_extended_cap)
	 {
	 	$capabilities = sprintf("(%3s %s %6s/%s [%s/%s][%s/%s])",
				$width, $speed, $state, $phy_link_state,
				$width_enable, $width_sup,
				$speed_enable, $speed_sup);
         }
	 else
	 {
	 	$capabilities = sprintf("(%3s %s %6s/%s)",
                                        $width, $speed, $state, $phy_link_state);
	 }
	 if ($print_add_switch)
	 {
                $port_timeouts = sprintf (" (HOQ:%s VL_Stall:%s)", $hoq_life, $vl_stall);
	 }
         if (!$only_down_links || ($only_down_links && $state eq "Down"))
         {
	        my $width_msg = "";
	        my $speed_msg = "";
	        if ($rem_width_enable ne "" && $rem_width_sup ne "")
	        {
	           if ($width_enable =~ /12X/ && $rem_width_enable =~ /12X/ && $width !~ /12X/) {
	              $width_msg = "Could be 12X";
	           } else {
	              if ($width_enable =~ /8X/ && $rem_width_enable =~ /8X/ && $width !~ /8X/) {
	                 $width_msg = "Could be 8X";
	              } else {
	                 if ($width_enable =~ /4X/ && $rem_width_enable =~ /4X/ && $width !~ /4X/) {
	                    $width_msg = "Could be 4X";
	                 }
	              }
	           }
	        }
	        if ($rem_speed_enable ne "" && $rem_speed_sup ne "")
	        {
	           if ($speed_enable =~ /10\.0/ && $rem_speed_enable =~ /10\.0/&& $speed !~ /10\.0/) {
	              $speed_msg = "Could be 10.0 Gbps";
	           } else {
	              if ($speed_enable =~ /5\.0/ && $rem_speed_enable =~ /5\.0/&& $speed !~ /5\.0/) {
	                 $speed_msg = "Could be 5.0 Gbps";
	              }
	           }
	        }

	        push (@output_lines, sprintf ("   %s %6s %4s[%2s]  ==%s%s==>  %s %6s %4s[%2s] \"%s\" ( %s %s)\n",
	    	        $line_begin,
                        $hr->{loc_sw_lid}, $port, $hr->{loc_ext_port},
		        $capabilities, $port_timeouts,
                        $ext_guid, $hr->{rem_lid}, $hr->{rem_port}, $hr->{rem_ext_port},
                        $hr->{rem_desc}, $width_msg, $speed_msg));
                $print_switch = "yes";
         }
      }
      if ($print_switch eq "yes")
      {
        foreach my $line (@output_lines) { print $line; }
      }
   }
}
main;

