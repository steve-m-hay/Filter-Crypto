#!perl
#===============================================================================
#
# t/01_constants.t
#
# DESCRIPTION
#   Test script to check autoloading of constants.
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

use Cwd qw(abs_path);
use File::Spec::Functions qw(canonpath catdir catfile updir);
use FindBin qw($Bin);
use Test::More;

#===============================================================================
# INITIALIZATION
#===============================================================================

BEGIN {
    my $top_dir = canonpath(abs_path(catdir($Bin, updir())));
    my $lib_dir = catfile($top_dir, 'blib', 'lib', 'Filter', 'Crypto');

    if (-f catfile($lib_dir, 'CryptFile.pm')) {
        require Filter::Crypto::CryptFile;
        Filter::Crypto::CryptFile->import();
        plan tests => 5;
    }
    else {
        plan skip_all => 'CryptFile component not built';
    }
}

#===============================================================================
# MAIN PROGRAM
#===============================================================================

MAIN: {
    ok(eval { CRYPT_MODE_AUTO();      1 }, 'CRYPT_MODE_AUTO flag');
    ok(eval { CRYPT_MODE_DECRYPT();   1 }, 'CRYPT_MODE_DECRYPT flag');
    ok(eval { CRYPT_MODE_ENCRYPT();   1 }, 'CRYPT_MODE_ENCRYPT flag');
    ok(eval { CRYPT_MODE_DECRYPTED(); 1 }, 'CRYPT_MODE_DECRYPTED flag');
    ok(eval { CRYPT_MODE_ENCRYPTED(); 1 }, 'CRYPT_MODE_ENCRYPTED flag');
}

#===============================================================================
