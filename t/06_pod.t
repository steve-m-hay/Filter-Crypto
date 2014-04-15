#!perl
#===============================================================================
#
# t/06_pod.t
#
# DESCRIPTION
#   Test script to check POD.
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

use Test;

#===============================================================================
# MAIN PROGRAM
#===============================================================================

MAIN: {
    eval {
        require Test::Pod;
        Test::Pod->import();
    };

    if ($@) {
        plan tests => 1;
        skip('Skip Test::Pod required to test POD', 1);
    }
    elsif ($Test::Pod::VERSION < 1.00) {
        plan tests => 1;
        skip('Skip Test::Pod 1.00 required to test POD', 1);
    }
    else {
        all_pod_files_ok();
    }
}

#===============================================================================
