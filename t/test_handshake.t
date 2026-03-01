#!/usr/bin/env perl

use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use POSIX ":sys_wait_h";
use Scope::Guard qw(scope_guard);
use Test::More;
use Time::HiRes qw(sleep);

my $server = "./test-neverbleed";
my $port = empty_port();
my $crt = "./t/assets/test.crt";
my $key = "./t/assets/test.key";

sub spawn_server {
    my $pid = fork;
    die "fork failed:$!"
        unless defined $pid;
    if ($pid == 0) {
        exec $server, "privsep", $port, $crt, $key;
        die "failed to exec $server:$!";
    }
    while (!check_port($port)) {
        sleep 0.1;
    }
    return scope_guard(sub {
        kill 9, $pid;
        while (waitpid($pid, 0) != $pid) {}
    });
}

subtest "handshake" => sub {
    my $guard = spawn_server();
    
    open my $fh, "-|", "printf 'GET / HTTP/1.0\\r\\n\\r\\n' | openssl s_client -connect 127.0.0.1:$port -CAfile $crt -verify_return_error -ign_eof 2>&1"
        or die "failed to start s_client:$!";
    my $content = do { local $/; <$fh> };
    close $fh;
    
    like($content, qr/Verification: OK/, "TLS verification passed");
    like($content, qr/HTTP\/1\.0 200 OK/, "HTTP 200 response received");
    like($content, qr/hello/, "Response contains expected content");
};

done_testing;