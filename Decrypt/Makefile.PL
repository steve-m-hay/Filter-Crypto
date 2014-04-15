#!perl
#===============================================================================
#
# Decrypt/Makefile.PL
#
# DESCRIPTION
#   Makefile creation script.
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

use ExtUtils::MakeMaker;
use File::Spec::Functions qw(catfile updir);

#===============================================================================
# MAIN PROGRAM
#===============================================================================

MAIN: {
    my $config_h  = catfile(updir(), 'CipherConfig.h');
    my $common_c  = catfile(updir(), 'CryptoCommon-c.inc');
    my $common_xs = catfile(updir(), 'CryptoCommon-xs.inc');

    WriteMakefile(
        NAME         => 'Filter::Crypto::Decrypt',
        VERSION_FROM => 'lib/Filter/Crypto/Decrypt.pm',

        DEFINE       => $ENV{__SHAY_PRIVATE_DEFINE},
        INC          => $ENV{__SHAY_PRIVATE_INC},
        LIBS         => $ENV{__SHAY_PRIVATE_LIBS},

        depend => {
            '$(C_FILES)' => "$config_h $common_c $common_xs"
        }
    );
}

#===============================================================================
