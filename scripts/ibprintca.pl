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

# =========================================================================
#
sub usage_and_exit
{
   my $prog = $_[0];
   print "Usage: $prog [-R -l] [<ca_guid|node_name>]\n";
   print "   print only the ca specified from the ibnetdiscover output\n";
   print "   -R Recalculate ibnetdiscover information\n";
   print "   -l list cas\n";
   exit 0;
}

my $argv0 = `basename $0`;
my $regenerate_map = undef;
my $list_hcas = undef;
chomp $argv0;
if (!getopts("hRl")) { usage_and_exit $argv0; }
if (defined $Getopt::Std::opt_h) { usage_and_exit $argv0; }
if (defined $Getopt::Std::opt_R) { $regenerate_map = $Getopt::Std::opt_R; }
if (defined $Getopt::Std::opt_l) { $list_hcas = $Getopt::Std::opt_l; }

my $target_hca = $ARGV[0];

if ($regenerate_map || !(-f "$IBswcountlimits::cache_dir/ibnetdiscover.topology")) { generate_ibnetdiscover_topology; }

if ($list_hcas)
{
   system ("ibhosts $IBswcountlimits::cache_dir/ibnetdiscover.topology");
   exit 1;
}

if ($target_hca eq "")
{
   usage_and_exit $argv0;
}

# =========================================================================
#
sub main
{
   my $found_hca = undef;
   open IBNET_TOPO, "<$IBswcountlimits::cache_dir/ibnetdiscover.topology" or die "Failed to open ibnet topology\n";
   my $in_hca = "no";
   my %ports = undef;
   while (my $line = <IBNET_TOPO>)
   {
      if ($line =~ /^Ca.*\"H-(.*)\"\s+# (.*)/)
      {
         my $guid = $1;
         my $desc = $2;
         if ($in_hca eq "yes")
         {
            $in_hca = "no";
            goto DONE;
         }
         if ("0x$guid" eq $target_hca || $desc =~ /.*$target_hca$/)
         {
            print $line;
            $in_hca = "yes";
            $found_hca = "yes";
         }
      }
      if ($line =~ /^Switch.*/ || $line =~ /^Rt.*/) { $in_hca = "no"; }

      if ( $line =~ /^\[(\d+)\].*/ && $in_hca eq "yes" )
      {
         $ports{$1} = $line;
      }

   }
DONE:
   foreach my $port (sort { $a <=> $b } (keys %ports)) {
      print $ports{$port};
   }
   if (! $found_hca)
   {
      print "\"$target_hca\" not found\n";
      print "   Try running with the \"-R\" option.\n";
      print "   If still not found the node is probably down.\n";
   }
   close IBNET_TOPO;
}
main

