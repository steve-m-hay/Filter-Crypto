#!perl
#===============================================================================
#
# t/01_constants.t
#
# DESCRIPTION
#   Test script to check autoloading of constants.
#
# COPYRIGHT
#   Copyright (C) 2004 Steve Hay.  All rights reserved.
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

my($have_cryptfile, $num_tests);

BEGIN {
    $num_tests = 6;
    plan tests => $num_tests;           # Number of tests to be executed

    my $top_dir = canonpath(abs_path(catdir($FindBin::Bin, updir())));
    my $lib_dir = catfile($top_dir, 'blib', 'lib', 'Filter', 'Crypto');

    if (-f catfile($lib_dir, 'CryptFile.pm')) {
        require Filter::Crypto::CryptFile;
        Filter::Crypto::CryptFile->import();
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

                                        # Tests 2-6: Check CRYPT_MODE_* flags
    ok(eval { CRYPT_MODE_AUTO();      1 });
    ok(eval { CRYPT_MODE_DECRYPT();   1 });
    ok(eval { CRYPT_MODE_ENCRYPT();   1 });
    ok(eval { CRYPT_MODE_DECRYPTED(); 1 });
    ok(eval { CRYPT_MODE_ENCRYPTED(); 1 });
}

#===============================================================================
