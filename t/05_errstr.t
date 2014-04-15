#!perl
#===============================================================================
#
# t/05_errstr.t
#
# DESCRIPTION
#   Test script to check $ErrStr variable in Filter::Crypto::CryptFile.
#
# COPYRIGHT
#   Copyright (C) 2004-2005 Steve Hay.  All rights reserved.
#
# LICENCE
#   You may distribute under the terms of either the GNU General Public License
#   or the Artistic License, as specified in the LICENCE file.
#
#===============================================================================

use 5.006000;

use strict;
use warnings;

use Cwd qw(abs_path);
use File::Spec::Functions qw(canonpath catdir catfile updir);
use FindBin;
use Test;

#===============================================================================
# INITIALISATION
#===============================================================================

my($have_cryptfile, $num_tests, $top_dir);
our($ErrStr);

BEGIN {
    $num_tests = 5;
    plan tests => $num_tests;           # Number of tests to be executed

    $top_dir = canonpath(abs_path(catdir($FindBin::Bin, updir())));
    my $lib_dir = catfile($top_dir, 'blib', 'lib', 'Filter', 'Crypto');

    if (-f catfile($lib_dir, 'CryptFile.pm')) {
        require Filter::Crypto::CryptFile;
        Filter::Crypto::CryptFile->import(qw(:DEFAULT $ErrStr));
        $have_cryptfile = 1;
    }
    else {
        $have_cryptfile = 0;
    }

}

#===============================================================================
# MAIN PROGRAM
#===============================================================================

MAIN: {
                                        # Test 1: Did we make it this far OK?
    ok(1);

    unless ($have_cryptfile) {
        for (2 .. $num_tests) {
            skip('Skip CryptFile component not built', 1);
        }
        exit;
    }

    my $iofile = 'test.pl';

    my $crypt_file = catfile($top_dir, 'blib', 'script', 'crypt_file');

    my $fh;

                                        # Tests 2-5: Check CryptFile module
    open $fh, ">$iofile";
    close $fh;

    crypt_file($iofile, CRYPT_MODE_DECRYPTED());
    ok($ErrStr eq 'Input data was already decrypted');

    crypt_file($iofile);
    ok($ErrStr eq '');

    crypt_file($iofile, CRYPT_MODE_ENCRYPTED());
    ok($ErrStr eq 'Input data was already encrypted');

    unlink $iofile;

    crypt_file($iofile);
    ok($ErrStr =~ /^Can't open file '\Q$iofile\E'/);
}

#===============================================================================
