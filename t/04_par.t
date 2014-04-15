#!perl
#===============================================================================
#
# t/04_par.t
#
# DESCRIPTION
#   Test script to check PAR::Filter::Crypto module (and decryption filter).
#
# COPYRIGHT
#   Copyright (c) 2004, Steve Hay.  All rights reserved.
#
# LICENCE
#   You may distribute under the terms of either the GNU General Public License
#   or the Artistic License, as specified in the LICENCE file.
#
#===============================================================================

use 5.006000;

use strict;
use warnings;

use Config;
use Cwd qw(abs_path);
use File::Spec::Functions qw(canonpath catdir catfile updir);
use FindBin;
use Test;

#===============================================================================
# INITIALISATION
#===============================================================================

my $num_tests;

BEGIN {
    $num_tests = 6;
    plan tests => $num_tests;           # Number of tests to be executed
}

#===============================================================================
# MAIN PROGRAM
#===============================================================================

MAIN: {
                                        # Test 1: Did we make it this far OK?
    ok(1);

    my $top_dir = canonpath(abs_path(catdir($FindBin::Bin, updir())));
    my $lib_dir = catfile($top_dir, 'blib', 'lib', 'Filter', 'Crypto');

    unless (-f catfile($lib_dir, 'CryptFile.pm')) {
        for (2 .. $num_tests) {
            skip('Skip CryptFile component not built', 1);
        }
        exit;
    }

    unless (-f catfile($lib_dir, 'Decrypt.pm')) {
        for (2 .. $num_tests) {
            skip('Skip Decrypt component not built', 1);
        }
        exit;
    }

    unless (eval { require PAR::Filter; 1 }) {
        for (2 .. $num_tests) {
            skip('Skip PAR::Filter required to test PAR::Filter::Crypto', 1);
        }
        exit;
    }

    my @keys = qw(
        installsitescript installvendorscript installscript
        installsitebin    installvendorbin    installbin
    );

    my $pp;
    foreach my $key (@keys) {
        next unless exists $Config{$key} and $Config{$key} ne '';
        next unless -d $Config{$key};
        $pp = catfile($Config{$key}, 'pp');
        last if -f $pp;
        undef $pp;
    }

    unless (defined $pp) {
        for (2 .. $num_tests) {
            skip("Skip 'pp' required to test PAR::Filter::Crypto", 1);
        }
        exit;
    }

    my $ifile = 'test.pl';
    my $ofile = "test$Config{_exe}";
    my $str   = 'Hello, world.';
    my $prog  = qq[print "$str\\n";\n];
    my $head  = 'use Filter::Crypto::Decrypt;';

    my $perl;
    if ($] < 5.007003) {
        # Prior to 5.7.3, -Mblib emitted a "Using ..." message on STDERR which
        # looks ugly when we spawn a child perl process.
        $perl = qq["$^X" -Iblib/arch -Iblib/lib];
    }
    else {
        $perl = qq["$^X" -Mblib];
    }

    my $have_archive_zip = eval { require Archive::Zip; 1 };

    my($fh, $line);

    unlink $ifile or die "Can't delete file '$ifile': $!\n" if -e $ifile;
    unlink $ofile or die "Can't delete file '$ofile': $!\n" if -e $ofile;

    open $fh, ">$ifile" or die "Can't create file '$ifile': $!\n";
    print $fh $prog;
    close $fh;

                                        # Tests 2-3: Check creating PAR archive
    qx{$perl $pp -f Crypto -M Filter::Crypto::Decrypt -o $ofile $ifile};
    ok($? == 0);
    ok(-s $ofile);

                                        # Tests 4-5: Inspect PAR archive
    if ($have_archive_zip) {
        my $zip = Archive::Zip->new() or die "Can't create new Archive::Zip\n";
        my $ret = eval { $zip->read($ofile) };
        ok(not $@ and $ret == Archive::Zip::AZ_OK());
        ok($zip->contents("script/$ifile") =~ /^\Q$head\E/);
    }
    else {
        for (1 .. 2) {
            skip('Skip Archive::Zip required to inspect PAR archive', 1);
        }
    }

                                        # Test 6: Check running PAR archive
    chomp($line = qx{$ofile});
    ok($line eq $str);

    unlink $ifile;
    unlink $ofile;
}
