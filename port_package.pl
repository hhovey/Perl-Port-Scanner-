#!/usr/bin/env perl
use strict;
use warnings;

BEGIN { $SIG{INT} = $SIG{TERM} = sub { exit 0 } }

use Getopt::Long;
use Pod::Usage;

GetOptions (
  'help|?'    => sub { pod2usage(2) },
  'ip=s'        => \my $target_ip,
);

# validate required args are given
die "Missing --ip parameter, try --help\n" unless $target_ip;

use Net::Address::IP::Local;
#if there is any trouble  with the use Net:: you need to download the it in Linux such as Ubuntu or Debian under...
# sudo apt-update -y
# sudo apt-get install -y libnet-address-ip-local-perl  
use IO::Socket::INET;

my $local_ip   = Net::Address::IP::Local->public;

# find a random free port by opening a socket using the protocol
my $local_port = do {
  my $socket = IO::Socket::INET->new(Proto => 'tcp', LocalAddr => $local_ip);
  my $socket_p = $socket->sockport();
  $socket->close;
  $socket_p;
};

use List::Util 'shuffle';

my %port_directory;
open my $port_f, '<', 'data/nmap-services.txt'
  or die "Error reading data/nmap-services.txt $!\n";

while (<$port_f>)
{
  next if /^#/; # skip comments
  chomp;
  my ($name, $number_protocol, $probability, $comments) = split /\t/;
  my ($port, $proto) = split /\//, $number_protocol;

  $port_directory{$number_protocol} = {
    port        => $port,
    proto       => $proto,
    name        => $name,
    probability => $probability,
    comments    => $comments,
  };
}

my @ports = shuffle do {
    map { $port_dir$_}->{port} }
      grep { $port_dir{$_}->{name} !~ /^unknown$/
             && $port_dir{$_}->{proto} eq 'tcp' } keys %port_dir;
};

use Net::Pcap;
use POSIX qw/WNOHANG ceil/;

# apportion the ports to scan between processes
my $procs = 50;
my $batch_size = ceil(@ports / $procs);
my %total_ports = map { $_ => 'filtered' } @ports; # for reporting
my @child_pids;

for (1..$procs)
{
  my @ports_to_scan = splice @ports, 0, $batch_size;
  my $parent = fork;
  die "unable to fork!\n" unless defined ($parent);

  if ($parent)
  {
    push(@child_pids, $parent);
    next;
  }

  # child waits until the parent signals to continue
  my $continue = 0;
  local $SIG{CONT} = sub { $continue = 1};
  until ($continue) {}

  for my $target_p (@ports_to_scan)
  {
    sleep(1);
    send_packet($target_p);
  }
  exit 0; # exit child
}

# setup parent packet capture
my $device_name = pcap_lookupdev(\my $err);
pcap_lookupnet($device_name, \my $net, \my $mask, \$err);
my $pcap = pcap_open_live($device_name, 1024, 0, 1000, \$err);
pcap_compile(
  $pcap,
  \my $filter,
  "(src net $target_ip) && (dst port $local_p)",
  0,
  $mask
);
pcap_setfilter($pcap,$filter);

# signal the child pids to start sending
kill CONT => $_ for @child_pids;

until (waitpid(-1, WNOHANG) == -1) # until all children exit
{
  my $p_c = pcap_next_ex($pcap,\my %header,\my $packet);

  if($p_c == 1)
  {
    read_packet($packet);
  }
  elsif ($p_c == -1)
  {
    warn "libpcap errored while reading a packet\n";
  }
}

use Net::RawIP;

sub send_packet
{
  my ($target_p) = @_;

  Net::RawIP->new({ ip => {
                      saddr => $local_ip,
                      daddr => $target_ip,
                    },
                    tcp => {
                      source => $local_p,
                      dest   => $target_p,
                      syn => 1,
                    },
                  })->send;
}

use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;

sub read_packet
{
  my ($raw_data) = @_;
  my $ip_data = NetPacket::Ethernet::strip($raw_data);
  my $ip_packet = NetPacket::IP->decode($ip_data);

  # is it TCP
  if ($ip_packet->{proto} == 6)
  {
    my $tcp = NetPacket::TCP->decode(NetPacket::IP::strip($ip_data));
    my $port = $tcp->{src_port};
    my $port_name = exists $port_directory{"$port/tcp"}
      ? $port_directory{"$port/tcp"}->{name}
      : '';

    if ($tcp->{flags} & SYN)
    {
      printf " %5d %-20s %-20s\n", $port, 'open', $port_name;
      $total_ports{$port} = 'open';
    }
    elsif ($tcp->{flags} & RST)
    {
      printf " %5d %-20s %-20s\n", $port, 'closed', $port_name;
      $total_ports{$port} = 'closed';
    }
  }
}

printf "\n %d ports scanned, %d filtered, %d closed, %d open\n",
  scalar(keys %total_ports),
  scalar(grep { $total_ports{$_} eq 'filtered' } keys %total_ports),
  scalar(grep { $total_ports{$_} eq 'closed'   } keys %total_ports),
  scalar(grep { $total_ports{$_} eq 'open'     } keys %total_ports);

END { pcap_close($pcap) if $pcap }

__END__

=head1 NAME
port_scanner - a concurrent randomized tcp/udp port scanner written in Perl
=head1 SYNOPSIS
port_scanner [options]
 Options:
  --ip,     -i   ip address to scan e.g. 10.30.1.52
  --help,   -h   display this help text
