#!perl
#===============================================================================
#
# t/02_function.t
#
# DESCRIPTION
#   Test script to check crypt_file() function (and decryption filter).
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

use Cwd qw(abs_path);
use File::Spec::Functions qw(canonpath catdir catfile updir);
use FindBin;
use Test;

#===============================================================================
# INITIALISATION
#===============================================================================

my($have_cryptfile, $have_decrypt, $num_tests);

BEGIN {
    $num_tests = 290;
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

    $have_decrypt = -f catfile($lib_dir, 'Decrypt.pm');
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

    my $ifile  = 'test.pl';
    my $ofile  = 'test.enc.pl';
    my $iofile = $ifile;
    my $str    = 'Hello, world.';
    my $prog   = qq[print "$str\\n";\n];
    my $head   = 'use Filter::Crypto::Decrypt;';

    my $perl;
    if ($] < 5.007003) {
        # Prior to 5.7.3, -Mblib emitted a "Using ..." message on STDERR which
        # looks ugly when we spawn a child perl process.
        $perl = qq["$^X" -Iblib/arch -Iblib/lib];
    }
    else {
        $perl = qq["$^X" -Mblib];
    }

    my($fh, $ifh, $ofh, $iofh, $contents, $saved_contents, $line, $i);

    unlink $ifile or die "Can't delete file '$ifile': $!\n" if -e $ifile;
    unlink $ofile or die "Can't delete file '$ofile': $!\n" if -e $ofile;

    open $fh, ">$ifile" or die "Can't create file '$ifile': $!\n";
    print $fh $prog;
    close $fh;

                                        # Tests 2-4: Check 1-arg (1)
    open $iofh, "+<$iofile" or die "Can't update file '$iofile': $!\n";
    binmode $iofh;
    ok(crypt_file($iofh));
    close $iofh;

    open $fh, $iofile or die "Can't read file '$iofile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents =~ /^\Q$head\E/);

    if ($have_decrypt) {
        chomp($line = qx{$perl $iofile});
        ok($line eq $str);
    }
    else {
        skip('Skip Decrypt component not built', 1);
    }

                                        # Tests 5-7: Check 1-arg (2)
    ok(crypt_file($iofile));

    open $fh, $iofile or die "Can't read file '$iofile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents eq $prog);

    if ($have_decrypt) {
        chomp($line = qx{$perl $iofile});
        ok($line eq $str);
    }
    else {
        skip('Skip Decrypt component not built', 1);
    }

                                        # Tests 8-10: Check 2-arg (1)
    open $iofh, "+<$iofile" or die "Can't update file '$iofile': $!\n";
    binmode $iofh;
    ok(crypt_file($iofh, CRYPT_MODE_AUTO()));
    close $iofh;

    open $fh, $iofile or die "Can't read file '$iofile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents =~ /^\Q$head\E/);

    if ($have_decrypt) {
        chomp($line = qx{$perl $iofile});
        ok($line eq $str);
    }
    else {
        skip('Skip Decrypt component not built', 1);
    }

                                        # Tests 11-13: Check 2-arg (2)
    ok(crypt_file($iofile, CRYPT_MODE_AUTO()));

    open $fh, $iofile or die "Can't read file '$iofile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents eq $prog);

    if ($have_decrypt) {
        chomp($line = qx{$perl $iofile});
        ok($line eq $str);
    }
    else {
        skip('Skip Decrypt component not built', 1);
    }

                                        # Tests 14-16: Check 2-arg (3)
    open $iofh, "+<$iofile" or die "Can't update file '$iofile': $!\n";
    binmode $iofh;
    ok(crypt_file($iofh, CRYPT_MODE_ENCRYPT()));
    close $iofh;

    open $fh, $iofile or die "Can't read file '$iofile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents =~ /^\Q$head\E/);

    if ($have_decrypt) {
        chomp($line = qx{$perl $iofile});
        ok($line eq $str);
    }
    else {
        skip('Skip Decrypt component not built', 1);
    }

    $saved_contents = $contents;

                                        # Tests 17-19: Check 2-arg (4)
    open $iofh, "+<$iofile" or die "Can't update file '$iofile': $!\n";
    binmode $iofh;
    ok(crypt_file($iofh, CRYPT_MODE_ENCRYPTED()));
    close $iofh;

    open $fh, $iofile or die "Can't read file '$iofile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents eq $saved_contents);

    if ($have_decrypt) {
        chomp($line = qx{$perl $iofile});
        ok($line eq $str);
    }
    else {
        skip('Skip Decrypt component not built', 1);
    }

                                        # Tests 20-22: Check 2-arg (5)
    ok(crypt_file($iofile, CRYPT_MODE_DECRYPT()));

    open $fh, $iofile or die "Can't read file '$iofile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents eq $prog);

    if ($have_decrypt) {
        chomp($line = qx{$perl $iofile});
        ok($line eq $str);
    }
    else {
        skip('Skip Decrypt component not built', 1);
    }

                                        # Tests 23-25: Check 2-arg (6)
    ok(crypt_file($iofile, CRYPT_MODE_DECRYPTED()));

    open $fh, $iofile or die "Can't read file '$iofile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents eq $prog);

    if ($have_decrypt) {
        chomp($line = qx{$perl $iofile});
        ok($line eq $str);
    }
    else {
        skip('Skip Decrypt component not built', 1);
    }

                                        # Tests 26-29: Check 2-arg (7)
    open $ifh, $ifile or die "Can't read file '$ifile': $!\n";
    binmode $ifh;
    open $ofh, ">$ofile" or die "Can't write file '$ofile': $!\n";
    binmode $ofh;
    ok(crypt_file($ifh, $ofh));
    close $ofh;
    close $ifh;

    open $fh, $ifile or die "Can't read file '$ifile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents eq $prog);
    open $fh, $ofile or die "Can't read file '$ofile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents =~ /^\Q$head\E/);

    if ($have_decrypt) {
        chomp($line = qx{$perl $ofile});
        ok($line eq $str);
    }
    else {
        skip('Skip Decrypt component not built', 1);
    }

    unlink $ifile;

                                        # Tests 30-33: Check 2-arg (8)
    open $ofh, $ofile or die "Can't read file '$ofile': $!\n";
    binmode $ofh;
    ok(crypt_file($ofh, $ifile));
    close $ofh;

    open $fh, $ifile or die "Can't read file '$ifile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents eq $prog);
    open $fh, $ofile or die "Can't read file '$ofile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents =~ /^\Q$head\E/);

    if ($have_decrypt) {
        chomp($line = qx{$perl $ifile});
        ok($line eq $str);
    }
    else {
        skip('Skip Decrypt component not built', 1);
    }

    unlink $ofile;

                                        # Tests 34-37: Check 2-arg (9)
    open $ofh, ">$ofile" or die "Can't write file '$ofile': $!\n";
    binmode $ofh;
    ok(crypt_file($ifile, $ofh));
    close $ofh;

    open $fh, $ifile or die "Can't read file '$ifile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents eq $prog);
    open $fh, $ofile or die "Can't read file '$ofile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents =~ /^\Q$head\E/);

    if ($have_decrypt) {
        chomp($line = qx{$perl $ofile});
        ok($line eq $str);
    }
    else {
        skip('Skip Decrypt component not built', 1);
    }

    unlink $ifile;

                                        # Tests 38-41: Check 2-arg (10)
    ok(crypt_file($ofile, $ifile));

    open $fh, $ifile or die "Can't read file '$ifile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents eq $prog);
    open $fh, $ofile or die "Can't read file '$ofile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents =~ /^\Q$head\E/);

    if ($have_decrypt) {
        chomp($line = qx{$perl $ifile});
        ok($line eq $str);
    }
    else {
        skip('Skip Decrypt component not built', 1);
    }

    unlink $ofile;

                                        # Tests 42-45: Check 3-arg (1)
    open $ifh, $ifile or die "Can't read file '$ifile': $!\n";
    binmode $ifh;
    open $ofh, ">$ofile" or die "Can't write file '$ofile': $!\n";
    binmode $ofh;
    ok(crypt_file($ifh, $ofh, CRYPT_MODE_AUTO()));
    close $ofh;
    close $ifh;

    open $fh, $ifile or die "Can't read file '$ifile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents eq $prog);
    open $fh, $ofile or die "Can't read file '$ofile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents =~ /^\Q$head\E/);

    if ($have_decrypt) {
        chomp($line = qx{$perl $ofile});
        ok($line eq $str);
    }
    else {
        skip('Skip Decrypt component not built', 1);
    }

    unlink $ifile;

                                        # Tests 46-49: Check 3-arg (2)
    open $ofh, $ofile or die "Can't read file '$ofile': $!\n";
    binmode $ofh;
    ok(crypt_file($ofh, $ifile, CRYPT_MODE_AUTO()));
    close $ofh;

    open $fh, $ifile or die "Can't read file '$ifile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents eq $prog);
    open $fh, $ofile or die "Can't read file '$ofile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents =~ /^\Q$head\E/);

    if ($have_decrypt) {
        chomp($line = qx{$perl $ifile});
        ok($line eq $str);
    }
    else {
        skip('Skip Decrypt component not built', 1);
    }

    unlink $ofile;

                                        # Tests 50-53: Check 3-arg (3)
    open $ofh, ">$ofile" or die "Can't write file '$ofile': $!\n";
    binmode $ofh;
    ok(crypt_file($ifile, $ofh, CRYPT_MODE_AUTO()));
    close $ofh;

    open $fh, $ifile or die "Can't read file '$ifile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents eq $prog);
    open $fh, $ofile or die "Can't read file '$ofile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents =~ /^\Q$head\E/);

    if ($have_decrypt) {
        chomp($line = qx{$perl $ofile});
        ok($line eq $str);
    }
    else {
        skip('Skip Decrypt component not built', 1);
    }

    unlink $ifile;

                                        # Tests 54-57: Check 3-arg (4)
    ok(crypt_file($ofile, $ifile, CRYPT_MODE_AUTO()));
    close $ofh;

    open $fh, $ifile or die "Can't read file '$ifile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents eq $prog);
    open $fh, $ofile or die "Can't read file '$ofile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents =~ /^\Q$head\E/);

    if ($have_decrypt) {
        chomp($line = qx{$perl $ifile});
        ok($line eq $str);
    }
    else {
        skip('Skip Decrypt component not built', 1);
    }

    unlink $ofile;

                                        # Tests 58-61: Check 3-arg (5)
    open $ifh, $ifile or die "Can't read file '$ifile': $!\n";
    binmode $ifh;
    open $ofh, ">$ofile" or die "Can't write file '$ofile': $!\n";
    binmode $ofh;
    ok(crypt_file($ifh, $ofh, CRYPT_MODE_ENCRYPT()));
    close $ofh;
    close $ifh;

    open $fh, $ifile or die "Can't read file '$ifile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents eq $prog);
    open $fh, $ofile or die "Can't read file '$ofile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents =~ /^\Q$head\E/);

    if ($have_decrypt) {
        chomp($line = qx{$perl $ofile});
        ok($line eq $str);
    }
    else {
        skip('Skip Decrypt component not built', 1);
    }

    unlink $ofile;

                                        # Tests 62-65: Check 3-arg (6)
    open $ifh, $ifile or die "Can't read file '$ifile': $!\n";
    binmode $ifh;
    open $ofh, ">$ofile" or die "Can't write file '$ofile': $!\n";
    binmode $ofh;
    ok(crypt_file($ifh, $ofh, CRYPT_MODE_ENCRYPTED()));
    close $ofh;
    close $ifh;

    open $fh, $ifile or die "Can't read file '$ifile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents eq $prog);
    open $fh, $ofile or die "Can't read file '$ofile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents =~ /^\Q$head\E/);

    if ($have_decrypt) {
        chomp($line = qx{$perl $ofile});
        ok($line eq $str);
    }
    else {
        skip('Skip Decrypt component not built', 1);
    }

    unlink $ifile;

                                        # Tests 66-69: Check 3-arg (7)
    open $ofh, $ofile or die "Can't read file '$ofile': $!\n";
    binmode $ofh;
    ok(crypt_file($ofh, $ifile, CRYPT_MODE_DECRYPT()));
    close $ofh;

    open $fh, $ifile or die "Can't read file '$ifile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents eq $prog);
    open $fh, $ofile or die "Can't read file '$ofile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents =~ /^\Q$head\E/);

    if ($have_decrypt) {
        chomp($line = qx{$perl $ifile});
        ok($line eq $str);
    }
    else {
        skip('Skip Decrypt component not built', 1);
    }

    unlink $ifile;

                                        # Tests 70-73: Check 3-arg (8)
    open $ofh, $ofile or die "Can't read file '$ofile': $!\n";
    binmode $ofh;
    ok(crypt_file($ofh, $ifile, CRYPT_MODE_DECRYPTED()));
    close $ofh;

    open $fh, $ifile or die "Can't read file '$ifile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents eq $prog);
    open $fh, $ofile or die "Can't read file '$ofile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents =~ /^\Q$head\E/);

    if ($have_decrypt) {
        chomp($line = qx{$perl $ifile});
        ok($line eq $str);
    }
    else {
        skip('Skip Decrypt component not built', 1);
    }

    unlink $ofile;

                                        # Tests 74-77: Check 3-arg (9)
    open $ofh, ">$ofile" or die "Can't write file '$ofile': $!\n";
    binmode $ofh;
    ok(crypt_file($ifile, $ofh, CRYPT_MODE_ENCRYPT()));
    close $ofh;

    open $fh, $ifile or die "Can't read file '$ifile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents eq $prog);
    open $fh, $ofile or die "Can't read file '$ofile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents =~ /^\Q$head\E/);

    if ($have_decrypt) {
        chomp($line = qx{$perl $ofile});
        ok($line eq $str);
    }
    else {
        skip('Skip Decrypt component not built', 1);
    }

    unlink $ofile;

                                        # Tests 78-81: Check 3-arg (10)
    open $ofh, ">$ofile" or die "Can't write file '$ofile': $!\n";
    binmode $ofh;
    ok(crypt_file($ifile, $ofh, CRYPT_MODE_ENCRYPTED()));
    close $ofh;

    open $fh, $ifile or die "Can't read file '$ifile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents eq $prog);
    open $fh, $ofile or die "Can't read file '$ofile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents =~ /^\Q$head\E/);

    if ($have_decrypt) {
        chomp($line = qx{$perl $ofile});
        ok($line eq $str);
    }
    else {
        skip('Skip Decrypt component not built', 1);
    }

    unlink $ifile;

                                        # Tests 82-85: Check 3-arg (11)
    ok(crypt_file($ofile, $ifile, CRYPT_MODE_DECRYPT()));
    close $ofh;

    open $fh, $ifile or die "Can't read file '$ifile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents eq $prog);
    open $fh, $ofile or die "Can't read file '$ofile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents =~ /^\Q$head\E/);

    if ($have_decrypt) {
        chomp($line = qx{$perl $ifile});
        ok($line eq $str);
    }
    else {
        skip('Skip Decrypt component not built', 1);
    }

    unlink $ifile;

                                        # Tests 86-89: Check 3-arg (12)
    ok(crypt_file($ofile, $ifile, CRYPT_MODE_DECRYPTED()));
    close $ofh;

    open $fh, $ifile or die "Can't read file '$ifile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents eq $prog);
    open $fh, $ofile or die "Can't read file '$ofile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents =~ /^\Q$head\E/);

    if ($have_decrypt) {
        chomp($line = qx{$perl $ifile});
        ok($line eq $str);
    }
    else {
        skip('Skip Decrypt component not built', 1);
    }

                                        # Tests 90-92: Check no newline at EOF
    $prog =~ s/\n$//;
    open $fh, ">$iofile" or die "Can't create file '$iofile': $!\n";
    print $fh $prog;
    close $fh;

    ok(crypt_file($iofile));

    open $fh, $iofile or die "Can't read file '$iofile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents =~ /^\Q$head\E/);

    if ($have_decrypt) {
        chomp($line = qx{$perl $iofile});
        ok($line eq $str);
    }
    else {
        skip('Skip Decrypt component not built', 1);
    }

                                        # Tests 93-140: Check all sizes under
                                        #               16 (largest block size)
                                        #               with newline at EOF
    for ($i = 1; $i <= 16; $i++) {
        open $fh, ">$iofile" or die "Can't create file '$iofile': $!\n";
        binmode $fh;
        print $fh +(';' x ($i - 1)) . "\n";
        close $fh;

        ok(crypt_file($iofile));

        open $fh, $iofile or die "Can't read file '$iofile': $!\n";
        $contents = do { local $/; <$fh> };
        close $fh;
        ok($contents =~ /^\Q$head\E/);

        if ($have_decrypt) {
            chomp($line = qx{$perl $iofile});
            ok($line eq '');
        }
        else {
            skip('Skip Decrypt component not built', 1);
        }
    }

                                        # Tests 141-188: Check all sizes under
                                        #                16 (largest block size)
                                        #                with no newline at EOF
    for ($i = 1; $i <= 16; $i++) {
        open $fh, ">$iofile" or die "Can't create file '$iofile': $!\n";
        print $fh ';' x $i;
        close $fh;

        ok(crypt_file($iofile));

        open $fh, $iofile or die "Can't read file '$iofile': $!\n";
        $contents = do { local $/; <$fh> };
        close $fh;
        ok($contents =~ /^\Q$head\E/);

        if ($have_decrypt) {
            chomp($line = qx{$perl $iofile});
            ok($line eq '');
        }
        else {
            skip('Skip Decrypt component not built', 1);
        }
    }

                                        # Tests 189-236: Check all sizes modulo
                                        #                16 (largest block size)
                                        #                with newline at EOF
    for ($i = 1; $i <= 16; $i++) {
        $str = ';' x $i;
        open $fh, ">$iofile" or die "Can't create file '$iofile': $!\n";
        print $fh qq[print "$str";\n];
        close $fh;

        ok(crypt_file($iofile));

        open $fh, $iofile or die "Can't read file '$iofile': $!\n";
        $contents = do { local $/; <$fh> };
        close $fh;
        ok($contents =~ /^\Q$head\E/);

        if ($have_decrypt) {
            chomp($line = qx{$perl $iofile});
            ok($line eq $str);
        }
        else {
            skip('Skip Decrypt component not built', 1);
        }
    }

                                        # Tests 237-284: Check all sizes modulo
                                        #                16 (largest block size)
                                        #                with no newline at EOF
    for ($i = 1; $i <= 16; $i++) {
        $str = ';' x $i;
        open $fh, ">$iofile" or die "Can't create file '$iofile': $!\n";
        print $fh qq[print "$str";];
        close $fh;

        ok(crypt_file($iofile));

        open $fh, $iofile or die "Can't read file '$iofile': $!\n";
        $contents = do { local $/; <$fh> };
        close $fh;
        ok($contents =~ /^\Q$head\E/);

        if ($have_decrypt) {
            chomp($line = qx{$perl $iofile});
            ok($line eq $str);
        }
        else {
            skip('Skip Decrypt component not built', 1);
        }
    }

                                        # Tests 285-287: Check files larger than
                                        #                BUFSIZ (>4kB should do)
                                        #                with newline at EOF
    $str = ';' x 4096;
    open $fh, ">$iofile" or die "Can't create file '$iofile': $!\n";
    print $fh qq[print "$str";\n];
    close $fh;

    ok(crypt_file($iofile));

    open $fh, $iofile or die "Can't read file '$iofile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents =~ /^\Q$head\E/);

    if ($have_decrypt) {
        chomp($line = qx{$perl $iofile});
        ok($line eq $str);
    }
    else {
        skip('Skip Decrypt component not built', 1);
    }

                                        # Tests 288-290: Check files larger than
                                        #                BUFSIZ (>4kB should do)
                                        #                with no newline at EOF
    $str = ';' x 4096;
    open $fh, ">$iofile" or die "Can't create file '$iofile': $!\n";
    print $fh qq[print "$str";];
    close $fh;

    ok(crypt_file($iofile));

    open $fh, $iofile or die "Can't read file '$iofile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents =~ /^\Q$head\E/);

    if ($have_decrypt) {
        chomp($line = qx{$perl $iofile});
        ok($line eq $str);
    }
    else {
        skip('Skip Decrypt component not built', 1);
    }

    unlink $ifile;
    unlink $ofile;
}

#===============================================================================
