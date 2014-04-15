#!perl
#===============================================================================
#
# t/03_script.t
#
# DESCRIPTION
#   Test script to check crypt_file script (and decryption filter).
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

use Cwd qw(abs_path cwd);
use File::Copy;
use File::Spec::Functions qw(canonpath catdir catfile devnull rel2abs updir);
use FindBin;
use Test;

#===============================================================================
# INITIALISATION
#===============================================================================

my $num_tests;

BEGIN {
    $num_tests = 95;
    plan tests => $num_tests;           # Number of tests to be executed
}

#===============================================================================
# MAIN PROGRAM
#===============================================================================

MAIN: {
                                        # Test 1: Did we make it this far OK?
    ok(1);

    my $top_dir;
    if ($] < 5.006001) {
        # Prior to 5.6.0, Cwd::abs_path() didn't correctly clean-up Win32 paths
        # like C:\Temp\.. which breaks the -d/-r/-t tests, so do it the hard way
        # instead.  Do it for all OS's just in case.
        my $cwd = cwd();
        chdir $FindBin::Bin or die "Can't cd to test script directory: $!\n";
        chdir updir() or die "Can't cd to parent directory: $!\n";
        $top_dir = canonpath(cwd());
        chdir $cwd or die "Can't cd to original directory: $!\n";
    }
    else {
        $top_dir = canonpath(abs_path(catdir($FindBin::Bin, updir())));
    }
    my $lib_dir = catfile($top_dir, 'blib', 'lib', 'Filter', 'Crypto');

    unless (-f catfile($lib_dir, 'CryptFile.pm')) {
        for (2 .. $num_tests) {
            skip('Skip CryptFile component not built', 1);
        }
        exit;
    }

    my $ifile  = 'test.pl';
    my $ofile  = 'test.enc.pl';
    my $iofile = $ifile;
    my $script = 'foo.pl';
    my $module = 'Foo.pm';
    my $bfile  = "$ifile.bak";
    my $lfile  = 'test.lst';
    my $dir1   = 'testdir1';
    my $dir2   = 'testdir2';
    my $str    = 'Hello, world.';
    my $prog   = qq[print "$str\\n";\n];
    my $scrsrc = qq[use Foo;\nFoo::foo();\n];
    my $modsrc = qq[package Foo;\nsub foo() { print "$str\\n" }\n1;\n];
    my $head   = 'use Filter::Crypto::Decrypt;';
    my $q      = $^O =~ /MSWin32/io ? '' : "'";
    my $null   = devnull();

    my $perl;
    if ($] < 5.007003) {
        # Prior to 5.7.3, -Mblib emitted a "Using ..." message on STDERR which
        # looks ugly when we spawn a child perl process and breaks the --silent
        # test.
        $perl = qq["$^X" -Iblib/arch -Iblib/lib];
    }
    else {
        $perl = qq["$^X" -Mblib];
    }

    my $have_decrypt   = -f catfile($lib_dir, 'Decrypt.pm');
    my $have_file_temp = eval { require File::Temp; 1 };

    my $crypt_file = catfile($top_dir, 'blib', 'script', 'crypt_file');

    my($fh, $contents, $line, $dfile, $rdir, $abs_ifile, $cdir, $ddir);
    my($dir3, $dir4, $dir5, $expected, $file, $data);

    unlink $ifile or die "Can't delete file '$ifile': $!\n" if -e $ifile;
    unlink $ofile or die "Can't delete file '$ofile': $!\n" if -e $ofile;

    open $fh, ">$ifile" or die "Can't create file '$ifile': $!\n";
    print $fh $prog;
    close $fh;

    open $fh, ">$lfile" or die "Can't create file '$lfile': $!\n";
    print $fh "$ifile\n";
    close $fh;

    open $fh, ">$script" or die "Can't create file '$script': $!\n";
    print $fh $scrsrc;
    close $fh;

    open $fh, ">$module" or die "Can't create file '$module': $!\n";
    print $fh $modsrc;
    close $fh;

                                        # Tests 2-5: Check STDIN input
    qx{$perl $crypt_file <$ifile >$ofile 2>$null};
    ok($? == 0);

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

                                        # Tests 6-9: Check file spec input
    qx{$perl $crypt_file $ifile >$ofile 2>$null};
    ok($? == 0);

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

                                        # Tests 10-13: Check -l option
    qx{$perl $crypt_file -l $lfile >$ofile 2>$null};
    ok($? == 0);

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

                                        # Tests 14-17: Check -d option
    mkdir $dir1 or die "Can't create directory '$dir1': $!\n";
    copy($ifile, $dir1) or
        die "Can't copy file '$ifile' into directory '$dir1': $!\n";

    qx{$perl $crypt_file -d $dir1 $ifile >$ofile 2>$null};
    ok($? == 0);

    $dfile = catfile($dir1, $ifile);
    open $fh, $dfile or die "Can't read file '$dfile': $!\n";
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

    unlink $dfile;
    unlink $ofile;

                                        # Tests 18-21: Check -r option
    $rdir = catdir($dir1, $dir2);
    mkdir $rdir or die "Can't create directory '$rdir': $!\n";
    copy($ifile, $rdir) or
        die "Can't copy file '$ifile' into directory '$rdir': $!\n";

    qx[$perl $crypt_file -d $dir1 -r ${q}test.p?$q >$ofile 2>$null];
    ok($? == 0);

    $dfile = catfile($rdir, $ifile);
    open $fh, $dfile or die "Can't read file '$dfile': $!\n";
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

    unlink $dfile;
    rmdir $rdir;
    rmdir $dir1;
    unlink $ofile;

                                        # Tests 22-24: Check -t option
    $abs_ifile = rel2abs($ifile);
    chomp($data = qx{$perl $crypt_file -t $ifile});
    ok($? == 0);
    ok($data eq $abs_ifile);

    open $fh, $ifile or die "Can't read file '$ifile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents eq $prog);

                                        # Tests 25-37: Check -d/-r/-t options
    $dir3 = catdir($top_dir, 'lib');
    $dir4 = catdir($dir3, 'Filter');
    $dir5 = catdir($dir3, 'PAR', 'Filter');

    $expected = catdir($dir4, 'Crypto.pm');
    $file = catfile('lib', 'Filter', 'Crypto.pm');
    chomp($data = qx{$perl $crypt_file -d $top_dir -t $file});
    ok($data eq $expected);
    $file = catfile('Filter', 'Crypto.pm');
    chomp($data = qx{$perl $crypt_file -d $dir3 -t $file});
    ok($data eq $expected);
    $file = 'Crypto.pm';
    chomp($data = qx{$perl $crypt_file -d $dir4 -t $file});
    ok($data eq $expected);

    $expected = catdir($dir4, $file);
    chomp($data = qx{$perl $crypt_file -d $dir4 -d $dir5 -t $file});
    ok($data eq $expected);

    $expected = catdir($dir5, $file);
    chomp($data = qx{$perl $crypt_file -d $dir5 -d $dir4 -t $file});
    ok($data eq $expected);

    $expected = catfile($top_dir, 'Makefile.PL') . "\n";
    $data = qx[$perl $crypt_file -d $top_dir -t ${q}Makefil?.PL$q];
    ok($data eq $expected);
    $data = qx[$perl $crypt_file -d $top_dir -t ${q}Make*.PL$q];
    ok($data eq $expected);
    $data = qx[$perl $crypt_file -d $top_dir -t ${q}Makefile.[PQR]L$q];
    ok($data eq $expected);

    $expected = join("\n", sort +(
        catfile($top_dir,              'Makefile.PL'),
        catfile($top_dir, 'CryptFile', 'Makefile.PL'),
        catfile($top_dir, 'Decrypt',   'Makefile.PL')
    )) . "\n";
    chomp($data = qx[$perl $crypt_file -d $top_dir -r -t ${q}Makefil?.PL$q]);
    $data = join("\n", sort split /\n/, $data) . "\n";
    ok($data eq $expected);
    chomp($data = qx[$perl $crypt_file -d $top_dir -r -t ${q}Make*.PL$q]);
    $data = join("\n", sort split /\n/, $data) . "\n";
    ok($data eq $expected);
    chomp($data = qx[$perl $crypt_file -d $top_dir -r -t ${q}Makefile.[PQR]L$q]);
    $data = join("\n", sort split /\n/, $data) . "\n";
    ok($data eq $expected);

    $dir3 = catdir($top_dir, 'CryptFile');
    $dir4 = catdir($top_dir, 'Decrypt');
    $file = "${q}Make*.PL$q";

    chomp($data = qx[$perl $crypt_file -d $top_dir -d $dir3 -d $dir4 -t $file]);
    $data = join("\n", sort split /\n/, $data) . "\n";
    ok($data eq $expected);
    chomp($data = qx[$perl $crypt_file -d $top_dir -d $dir3 -d $dir4 -r -t $file]);
    $data = join("\n", sort split /\n/, $data) . "\n";
    ok($data eq $expected);

                                        # Tests 38-47: Check --silent option
    chomp($line = qx{$perl $crypt_file $ifile 2>&1 1>$ofile});
    ok($? == 0);
    ok($line eq "$abs_ifile: OK");

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

    chomp($line = qx{$perl $crypt_file --silent $ifile 2>&1 1>$ofile});
    ok($? == 0);
    ok($line eq '');

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

                                        # Tests 48-52: Check -i option
    qx{$perl $crypt_file -i $iofile 2>$null};
    ok($? == 0);

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

    qx{$perl $crypt_file -i $iofile 2>$null};
    ok($? == 0);

    open $fh, $iofile or die "Can't read file '$iofile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents eq $prog);

                                        # Tests 53-61: Check script and module
    qx{$perl $crypt_file -i $script 2>$null};
    ok($? == 0);

    open $fh, $script or die "Can't read file '$script': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents =~ /^\Q$head\E/);

    if ($have_decrypt) {
        chomp($line = qx{$perl $script});
        ok($line eq $str);
    }
    else {
        skip('Skip Decrypt component not built', 1);
    }

    qx{$perl $crypt_file -i $module 2>$null};
    ok($? == 0);

    open $fh, $module or die "Can't read file '$module': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents =~ /^\Q$head\E/);

    if ($have_decrypt) {
        chomp($line = qx{$perl $script});
        ok($line eq $str);
    }
    else {
        skip('Skip Decrypt component not built', 1);
    }

    qx{$perl $crypt_file -i $script 2>$null};
    ok($? == 0);

    open $fh, $script or die "Can't read file '$script': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents eq $scrsrc);

    if ($have_decrypt) {
        chomp($line = qx{$perl $script});
        ok($line eq $str);
    }
    else {
        skip('Skip Decrypt component not built', 1);
    }

                                        # Tests 62-66: Check -e option
    qx{$perl $crypt_file -i -e memory $iofile 2>$null};
    ok($? == 0);

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

    if ($have_file_temp) {
        qx{$perl $crypt_file -i -e tempfile $iofile 2>$null};
        ok($? == 0);

        open $fh, $iofile or die "Can't read file '$iofile': $!\n";
        $contents = do { local $/; <$fh> };
        close $fh;
        ok($contents eq $prog);
    }
    else {
        for (1 .. 2) {
            skip('Skip File::Temp required to test -e tempfile', 1);
        }

        open $fh, ">$iofile" or die "Can't recreate file '$iofile': $!\n";
        print $fh $prog;
        close $fh;
    }

                                        # Tests 67-70: Check -b option
    qx{$perl $crypt_file -i -b $q*.bak$q $iofile 2>$null};
    ok($? == 0);

    open $fh, $bfile or die "Can't read file '$bfile': $!\n";
    $contents = do { local $/; <$fh> };
    close $fh;
    ok($contents eq $prog);
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

    unlink $iofile;
    rename $bfile, $iofile;

                                        # Tests 71-74: Check -o option
    qx{$perl $crypt_file -o $q?.enc.[$q $ifile 2>$null};
    ok($? == 0);

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

                                        # Tests 75-92: Check -c option
    qx{$perl $crypt_file -i -c auto $iofile 2>$null};
    ok($? == 0);

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

    qx{$perl $crypt_file -i -c auto $iofile 2>$null};
    ok($? == 0);

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

    qx{$perl $crypt_file -i -c encrypt $iofile 2>$null};
    ok($? == 0);

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

    qx{$perl $crypt_file -i -c encrypted $iofile 2>$null};
    ok($? == 0);

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

    qx{$perl $crypt_file -i -c decrypt $iofile 2>$null};
    ok($? == 0);

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

    qx{$perl $crypt_file -i -c decrypted $iofile 2>$null};
    ok($? == 0);

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

                                        # Test 93: Check -v option
    chomp($data = qx{$perl $crypt_file -v});
    ok($data =~ qr/\A This\ is\ crypt_file              .*?
                    ^ Copyright                         .*?
                    ^ This\ script\ is\ free\ software /mosx);

                                        # Test 94: Check -h option
    chomp($data = qx{$perl $crypt_file -h});
    ok($data =~ qr/\A Usage:     .*?
                    ^ Arguments: .*?
                    ^ Options:   /mosx);

                                        # Test 95: Check -m option
    chomp($data = qx{$perl $crypt_file -m});
    ok($data =~ qr/^ (?:\e\[..)? NAME         .*?
                   ^ (?:\e\[..)? SYNOPSIS     .*?
                   ^ (?:\e\[..)? ARGUMENTS    .*?
                   ^ (?:\e\[..)? OPTIONS      .*?
                   ^ (?:\e\[..)? EXIT\ STATUS .*?
                   ^ (?:\e\[..)? DIAGNOSTICS  .*?
                   ^ (?:\e\[..)? EXAMPLES     .*?
                   ^ (?:\e\[..)? ENVIRONMENT  .*?
                   ^ (?:\e\[..)? SEE\ ALSO    .*?
                   ^ (?:\e\[..)? AUTHOR       .*?
                   ^ (?:\e\[..)? COPYRIGHT    .*?
                   ^ (?:\e\[..)? LICENCE      .*?
                   ^ (?:\e\[..)? VERSION      .*?
                   ^ (?:\e\[..)? DATE         .*?
                   ^ (?:\e\[..)? HISTORY      /mosx);

    unlink $ifile;
    unlink $ofile;
    unlink $lfile;
    unlink $script;
    unlink $module;
}

#===============================================================================
