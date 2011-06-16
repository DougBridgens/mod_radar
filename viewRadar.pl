#!/usr/bin/perl -w
#
# perl viewRadar.pl
#
# tool to dump out the contents of the mod_radar database file.
#
# suggestion:
# while:;do clear;perl viewRadar.pl;sleep 2;done
#
# database file fields :
# runfor - http request start time (microseconds)
# pid - process id
# client_ip 
# post_read
# translate_name
# map_to_storage
# header_parser
# access_checker
# check_user_id
# auth_checker
# type_checker
# fixups
# log_transaction
# uri

use Data::Dumper;
use DB_File qw($DB_HASH);
use Fcntl;
use strict;

my $db_file = "/tmp/radar.db";
my $db_ref;
my %db;
my %rows;
my $requests;
my $slowrequests;

if (tie(%db, 'DB_File', $db_file, O_RDONLY)) {
  for my $pid (keys %db) {
    my $tmp = $db{$pid};
    $tmp =~ s/\s+//g;
    my ($client_ip, $time_started, $post_read, $translate_name, $map_to_storage, $header_parser, $access_checker, $check_user_id, $auth_checker, $type_checker, $fixups, $log_transaction, $uri) = split(/\,/, $tmp);

      $requests++;
      my $runfor = int($time_started / 1000000);
      $runfor = time() - $runfor;
      if ($runfor > 10) { $slowrequests++; }
      $fixups = ($fixups / 1000000);
      my $row = sprintf("%-8d  %15s  %11.3f  %10d  %s\n", $pid, $client_ip, $fixups, $runfor, $uri);
      $rows{$runfor} = $row;
    }
}
untie %db;

printf(":: mod_radar ::\n\n%-8s  %15s  %11s  %10s  %s\n", "pid", "client ip", "pre-process", "processing", "uri");

foreach my $r (sort { $b <=> $a} keys %rows) {
  print $rows{$r};
}
