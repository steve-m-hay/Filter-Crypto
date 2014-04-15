#!perl
#===============================================================================
#
# t/04_par.t
#
# DESCRIPTION
#   Test script to check PAR::Filter::Crypto module (and decryption filter).
#
# COPYRIGHT
#   Copyright (C) 2004-2006 Steve Hay.  All rights reserved.
#
# LICENCE
#   You may distribute under the terms of either the GNU General Public License
#   or the Artistic License, as specified in the LICENCE file.
#
#===============================================================================

use 5.006000;

use strict;
use warnings;

use Config qw(%Config);
use Cwd qw(abs_path);
use File::Spec::Functions qw(canonpath catdir catfile curdir updir);
use FindBin qw($Bin);
use Test::More;

#===============================================================================
# INITIALIZATION
#===============================================================================

my($pp);

BEGIN {
    my $top_dir = canonpath(abs_path(catdir($Bin, updir())));
    my $lib_dir = catfile($top_dir, 'blib', 'lib', 'Filter', 'Crypto');

    unless (-f catfile($lib_dir, 'CryptFile.pm')) {
        plan skip_all => 'CryptFile component not built';
    }

    unless (-f catfile($lib_dir, 'Decrypt.pm')) {
        plan skip_all => 'Decrypt component not built';
    }

    unless (eval { require PAR::Filter; 1 }) {
        plan skip_all => 'PAR::Filter required to test PAR::Filter::Crypto';
    }

    my @keys = qw(
        installsitescript installvendorscript installscript
        installsitebin    installvendorbin    installbin
    );

    foreach my $key (@keys) {
        next unless exists $Config{$key} and $Config{$key} ne '';
        next unless -d $Config{$key};
        $pp = catfile($Config{$key}, 'pp');
        last if -f $pp;
        undef $pp;
    }

    if (defined $pp) {
        plan tests => 6;
    }
    else {
        plan skip_all => "'pp' required to test PAR::Filter::Crypto";
    }
}

#===============================================================================
# MAIN PROGRAM
#===============================================================================

MAIN: {
    my $ifile = 'test.pl';
    my $ofile = "test$Config{_exe}";
    my $str   = 'Hello, world.';
    my $prog  = qq[print "$str\\n";\n];
    my $head  = 'use Filter::Crypto::Decrypt;';

    my $perl;
    my $perl_exe = $^X =~ / /o ? qq["$^X"] : $^X;
    if ($] < 5.007003) {
        # Before 5.7.3, -Mblib emitted a "Using ..." message on STDERR, which
        # looks ugly when we spawn a child perl process.
        $perl = qq[$perl_exe -Iblib/arch -Iblib/lib];
    }
    else {
        $perl = qq[$perl_exe -Mblib];
    }

    my $have_archive_zip = eval { require Archive::Zip; 1 };

    my($fh, $line, $cur_ofile);

    unlink $ifile or die "Can't delete file '$ifile': $!\n" if -e $ifile;
    unlink $ofile or die "Can't delete file '$ofile': $!\n" if -e $ofile;

    open $fh, ">$ifile" or die "Can't create file '$ifile': $!\n";
    print $fh $prog;
    close $fh;

    qx{$perl $pp -f Crypto -M Filter::Crypto::Decrypt -o $ofile $ifile};
    is($?, 0, 'pp exited successfully');
    cmp_ok(-s $ofile, '>', 0, '... and created a non-zero size PAR archive');

    SKIP: {
        skip 'Archive::Zip required to inspect PAR archive', 3
            unless $have_archive_zip;

        my $zip = Archive::Zip->new() or die "Can't create new Archive::Zip\n";
        my $ret = eval { $zip->read($ofile) };
        is($@, '', 'No exceptions were thrown reading the PAR archive');
        is($ret, Archive::Zip::AZ_OK(), '... and read() returned OK');
        like($zip->contents("script/$ifile"), qr/^\Q$head\E/,
             '... and the contents are as expected');
    }

    # Some platforms search the directories in PATH before the current directory
    # so be explicit which file we want to run.
    $cur_ofile = catfile(curdir(), $ofile);
    chomp($line = qx{$cur_ofile});
    is($line, $str, 'Running the PAR archive produces the expected output');

    unlink $ifile;
    unlink $ofile;
}
