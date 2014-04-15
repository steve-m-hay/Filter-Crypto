#line 1
#===============================================================================
#
# inc/Module/Install/PRIVATE/Filter/Crypto.pm
#
# DESCRIPTION
#   Distribution-specific Module::Install private extension class for
#   Filter-Crypto distribution.
#
# COPYRIGHT
#   Copyright (C) 2004-2006, 2008 Steve Hay.  All rights reserved.
#
# LICENCE
#   You may distribute under the terms of either the GNU General Public License
#   or the Artistic License, as specified in the LICENCE file.
#
#===============================================================================

package Module::Install::PRIVATE::Filter::Crypto;

use 5.006000;

use strict;
use warnings;

use Config qw(%Config);
use Cwd qw(abs_path);
use Fcntl;
use File::Basename qw(dirname);
use File::Copy qw(copy);
use File::Spec::Functions qw(canonpath catdir catfile updir);
use Text::Wrap qw(wrap);

use constant CIPHER_NAME_DES        => 'DES';
use constant CIPHER_NAME_DES_EDE    => 'DES_EDE';
use constant CIPHER_NAME_DES_EDE3   => 'DES_EDE3';
use constant CIPHER_NAME_RC4        => 'RC4';
use constant CIPHER_NAME_IDEA       => 'IDEA';
use constant CIPHER_NAME_RC2        => 'RC2';
use constant CIPHER_NAME_DESX       => 'DESX';
use constant CIPHER_NAME_BLOWFISH   => 'Blowfish';
use constant CIPHER_NAME_NULL       => 'Null';
use constant CIPHER_NAME_RC5        => 'RC5';
use constant CIPHER_NAME_CAST5      => 'CAST5';
use constant CIPHER_NAME_AES        => 'AES';

use constant CIPHER_MODE_ECB        => 'ECB';
use constant CIPHER_MODE_CBC        => 'CBC';
use constant CIPHER_MODE_CFB        => 'CFB';
use constant CIPHER_MODE_OFB        => 'OFB';

use constant CIPHER_KEY_GIVEN_PSWD  => 1;
use constant CIPHER_KEY_RANDOM_PSWD => 2;
use constant CIPHER_KEY_GIVEN       => 3;
use constant CIPHER_KEY_RANDOM      => 4;

use constant RAND_OPTION_STR        => 'rand';
use constant RAND_PSWD_LEN          => 32;

use constant RNG_PERL_RAND          => 'Perl';
use constant RNG_CRYPT_RANDOM       => 'Crypt::Random';
use constant RNG_MATH_RANDOM        => 'Math::Random';
use constant RNG_OPENSSL_RAND       => 'OpenSSL';

use constant CIPHER_CONFIG_FILENAME => 'CipherConfig.h';

use constant BUILD_OPTION_BOTH      => 'both';
use constant BUILD_OPTION_CRYPTFILE => 'CryptFile';
use constant BUILD_OPTION_DECRYPT   => 'Decrypt';

#===============================================================================
# CLASS INITIALIZATION
#===============================================================================

our(@ISA, $VERSION);

BEGIN {
    @ISA = qw(Module::Install::PRIVATE);

    $VERSION = '1.05';

    # Define protected accessor/mutator methods.
    foreach my $prop (qw(
        prefix_dir inc_dir package ver_num ver_str lib_dir lib_name bin_file
        cipher_name cipher_func cipher_needs_iv key_len rc2_key_bits rc5_rounds
        pswd key
    )) {
        no strict 'refs';
        *$prop = sub {
            use strict 'refs';
            my $self = shift;
            $self->{$prop} = shift if @_;
            return $self->{$prop};
        };
    }
}

#===============================================================================
# PUBLIC API
#===============================================================================

# Method to return the instance of this class that it was invoked on, for use in
# invoking further methods in this class within Makefile.PL.  (This method has a
# suitably unique name to just be autoloaded from Makefile.PL; the other methods
# do not, so must be invoked on our object to ensure they are dispatched
# correctly.)

sub get_filter_crypto_private_obj {
    return shift;
}

sub locate_openssl {
    my $self = shift;

    print "\n";

    $self->query_prefix_dir();
    print "\n";

    $self->locate_inc_dir();
    $self->set_inc();

    $self->determine_ver_num();
    $self->set_define();

    $self->locate_lib_dir_and_file();
    $self->set_libs();

    $self->locate_bin_file();
    print "\n";
}

sub configure_cipher {
    my $self = shift;

    my $cipher_config = $self->opts()->{'cipher-config'};
    if (defined $cipher_config) {
        if (-f $cipher_config) {
            $self->show_found_var(
                'Using specified configuration file', $cipher_config
            );
            $self->copy_cipher_config($cipher_config);
        }
        else {
            $self->exit_with_error(100,
                "No such configuration file '%s'", $cipher_config
            );
        }
    }
    else {
        $self->query_cipher_name();

        my $lc_cipher_name = lc $self->cipher_name();
        my $cipher_config_method = "configure_${lc_cipher_name}_cipher";
        $self->$cipher_config_method();

        $self->query_pswd_or_key();

        $self->write_cipher_config();
    }
}

sub query_build {
    my $self = shift;

    my @build_options = (
        [ BUILD_OPTION_BOTH,      'Build both components'          ],
        [ BUILD_OPTION_CRYPTFILE, 'Build CryptFile component only' ],
        [ BUILD_OPTION_DECRYPT,   'Build Decrypt component only'   ]
    );

    my $build = $self->opts()->{'build'};
    if (defined $build) {
        my %build_options = map { $_->[0] => 1 } @build_options;
        if (exists $build_options{$build}) {
            $self->show_found_var('Using specified build option', $build);
        }
        else {
            $self->exit_with_error(101,
                "Invalid 'build' option value '%s'", $build
            );
        }
    }
    else {
        my $message  = 'Build options:';
        my $question = 'Which component(s) do you want to build?';
        my $default  = BUILD_OPTION_BOTH;

        $build = $self->prompt_list(
            $message, \@build_options, $question, $default
        );
    }
    print "\n";

    if ($build eq BUILD_OPTION_BOTH) {
        return [ BUILD_OPTION_CRYPTFILE, BUILD_OPTION_DECRYPT ];
    }
    else {
        return [ $build ];
    }
}

#===============================================================================
# PROTECTED API
#===============================================================================

sub query_prefix_dir {
    my $self = shift;

    my $prefix_dir = $self->opts()->{'prefix-dir'};
    if (defined $prefix_dir) {
        $prefix_dir = canonpath(abs_path($prefix_dir));
        if (-d $prefix_dir) {
            $self->show_found_var(
                'Using specified prefix directory', $prefix_dir
            );
        }
        else {
            $self->exit_with_error(102,
                "No such prefix directory '%s'", $prefix_dir
            );
        }
    }
    else {
        # Look for the main binary executable "openssl" or "ssleay" and use the
        # parent directory of where that is located; otherwise use the default
        # prefix directory as specified in the latest OpenSSL's own INSTALL
        # file if it exists.
        my $bin_file;
        if ($bin_file = $self->can_run('openssl') or
            $bin_file = $self->can_run('ssleay'))
        {
            if ($self->is_win32()) {
                # Find out (if we can) which platform this binary was built for.
                # This information is normally contained in the output of the
                # binary's "version -a" command, labelled "platform: " (or
                # "Platform:" before 0.9.2).
                my $bin_cmd = "$bin_file version -a 2>&1";

                my $bin_output = `$bin_cmd`;
                my $bin_rc = $? >> 8;

                if ($bin_rc) {
                    $self->exit_with_error(133,
                        "Could not get OpenSSL/SSLeay version information " .
                        "(%d):\n%s", $bin_rc, $bin_output
                    );
                }

                if ((my $platform) = $bin_output =~ /platform: ?(.*)$/imo) {
                    # If we have found a Cygwin binary then we had better not
                    # try to use it with our Win32 perl.
                    if ($platform =~ /^Cygwin/io) {
                        warn("Warning: Ignoring Cygwin OpenSSL/SSLeay binary " .
                             "'$bin_file' on Win32\n");
                        $bin_file = undef;
                    }
                }
            }
        }

        my $default;
        if (defined $bin_file) {
            # The binaries are normally located in a sub-directory (bin/,
            # out32/, out32dll/, out32.dbg/, out32dll.dbg or out/) of the prefix
            # directory.  See locate_bin_file().
            my $bin_dir = dirname($bin_file);
            $default = canonpath(abs_path(catdir($bin_dir, updir())));
        }
        else {
            $default = $self->is_win32() ? 'C:\\openssl' : '/usr/local/ssl';
            unless (-d $default) {
                if ($self->use_default_response()) {
                    $self->exit_with_error(132,
                        'OS unsupported: No prefix directory found for ' .
                        'OpenSSL or SSLeay'
                    );
                }
                else {
                    $default = '';
                }
            }
        }

        my $question = 'Where is your OpenSSL or SSLeay?';

        $prefix_dir = $self->prompt_dir($question, $default);
    }

    $self->prefix_dir($prefix_dir)
}

sub locate_inc_dir {
    my $self = shift;

    # The headers are normally located in the include/ sub-directory of the
    # prefix directory.
    # Again, build directories on "native" Windows platforms may have the files
    # in a different sub-directory, in this case inc32/ (0.9.0 onwards) or out/
    # (up to and including 0.8.1b), or even outinc/ for MinGW builds.  (Beware
    # of version 0.6.0 build directories, which contain an include/ sub-
    # directory containing "Shortcuts" to the real header files in the out/ sub-
    # directory.  Check for the presence of the "cyrypto.h" header file to be
    # sure we find the correct sub-directory.  The header files are now located
    # in the openssl/ sub-directory of the include directory (0.9.3 onwards),
    # but were located in the include directory itself (up to and including
    # 0.8.1b).)
    my $prefix_dir = $self->prefix_dir();
    my($dir, $inc_dir);
    if (-d ($dir = catdir($prefix_dir, 'include')) and
        (-f catfile($dir, 'openssl', 'crypto.h') or
         -f catfile($dir, 'crypto.h')))
    {
        $inc_dir = $dir;
    }
    elsif ($self->is_win32()) {
        if (-d ($dir = catdir($prefix_dir, 'inc32')) and
            (-f catfile($dir, 'openssl', 'crypto.h') or
             -f catfile($dir, 'crypto.h')))
        {
            $inc_dir = $dir;
        }
        elsif (-d ($dir = catdir($prefix_dir, 'outinc')) and
               (-f catfile($dir, 'openssl', 'crypto.h') or
                -f catfile($dir, 'crypto.h')))
        {
            $inc_dir = $dir;
        }
        elsif (-d ($dir = catdir($prefix_dir, 'out')) and
               -f catfile($dir, 'crypto.h'))
        {
            $inc_dir = $dir;
        }
    }

    if (defined $inc_dir) {
        $self->show_found_var('Found include directory', $inc_dir);
        $self->inc_dir($inc_dir)
    }
    else {
        $self->exit_with_error(103, 'No include directory found');
    }
}

sub set_inc {
    my $self = shift;

    my $inc_dir = $self->inc_dir();
    $self->inc("-I$inc_dir");
}

sub determine_ver_num {
    my $self = shift;

    # The header files are now located in the openssl/ sub-directory of the
    # include directory (0.9.3 onwards), but were located in the include
    # directory itself (up to and including 0.8.1b).
    my $inc_dir = $self->inc_dir();
    my($dir, $inc_files_dir);
    if (-d ($dir = catdir($inc_dir, 'openssl'))) {
        $inc_files_dir = $dir;
    }
    else {
        $inc_files_dir = $inc_dir;
    }

    # The version number is now specified by an OPENSSL_VERSION_NUMBER #define
    # in the opensslv.h header file (0.9.2 onwards).  That #define was in the
    # crypto.h header file (0.9.1's), and was called SSLEAY_VERSION_NUMBER (from
    # 0.6.0 to 0.9.0b inclusive).  Earlier versions do not seem to have a
    # version number defined in this way, but we do not support anything earlier
    # anyway.  The version number is specified as a hexadecimal integer of the
    # form MNNFFPPS (major, minor, fix, patch, status [0 for dev, 1 to 14 for
    # betas, and f for release) (0.9.5a onwards, but with the highest bit set in
    # the patch byte for the 0.9.5's), or of the form MNNFFRBB (major, minor,
    # fix, release, patch or beta) (0.9.3's, 0.9.4's and 0.9.5), or of the form
    # MNFP (major, minor, fix, patch) (up to and including 0.9.2b).
    my($file, $ver_file);
    if (-f ($file = catfile($inc_files_dir, 'opensslv.h'))) {
        $ver_file = $file;
    }
    elsif (-f ($file = catfile($inc_files_dir, 'crypto.h'))) {
        $ver_file = $file;
    }
    else {
        $self->exit_with_error(104, 'No version number header file found');
    }

    my $ver_define;
    if (open my $ver_fh, '<', $ver_file) {
        while (<$ver_fh>) {
            if (/^\#define\s+(?:OPENSSL|SSLEAY)_VERSION_NUMBER\s+
                 0x([0-9a-f]+)/iox)
            {
                $ver_define = $1;
                last;
            }
        }
        close $ver_fh;
    }
    else {
        $self->exit_with_error(105,
            "Could not open version number header file '%s' for reading: %s",
            $ver_file, $!
        );
    }

    my($major, $minor, $fix, $patch, $status_str);
    if (defined $ver_define) {
        if (length $ver_define == 8 and
            $ver_define =~ /^([0-9a-f])([0-9a-f]{2})([0-9a-f]{2})/io)
        {
            ($major, $minor, $fix) = map { hex } ($1, $2, $3);

            my $mmf_ver_num = $major * 10000 + $minor * 100 + $fix;

            if ( $mmf_ver_num >  905 or
                ($mmf_ver_num == 905 and $ver_define !~ /100$/o))
            {
                my $status_num;
                ($patch, $status_num) = map { hex }
                    $ver_define =~ /([0-9a-f]{2})([0-9a-f])$/io;

                $patch = 0xff & ($patch & ~0x80) if $mmf_ver_num == 905;

                if ($status_num == 0) {
                    $status_str = '-dev';
                }
                elsif ($status_num < 0xf) {
                    $status_str = '-beta' . (1 .. 0xe)[$status_num - 1];
                }
                else {
                    $status_str = '';
                }
            }
            else {
                my($release, $patch_or_beta) = map { hex }
                    $ver_define =~ /([0-9a-f])([0-9a-f]{2})$/io;

                if ($release == 0) {
                    $patch = 0;
                    if ($patch_or_beta == 0) {
                        $status_str = '-dev';
                    }
                    else {
                        $status_str = '-beta' . (1 .. 0xff)[$patch_or_beta - 1];
                    }
                }
                else {
                    $patch = $patch_or_beta;
                    $status_str = '';
                }
            }
        }
        elsif (length $ver_define == 4 and
               $ver_define =~ /^([0-9a-f])([0-9a-f])([0-9a-f])([0-9a-f])$/io)
        {
            ($major, $minor, $fix, $patch) = map { hex } ($1, $2, $3, $4);
            $status_str = '';
        }
        else {
            $self->exit_with_error(106,
                'Unrecognized version number found (%s)', $ver_define
            );
        }
    }
    else {
        $self->exit_with_error(107, 'No version number found');
    }

    my $ver_num = $major * 1000000 + $minor * 10000 + $fix * 100 + $patch;
    my $ver_str = "$major.$minor.$fix";
    $ver_str .= ('', 'a' .. 'z')[$patch];
    $ver_str .= $status_str;

    my $package = $ver_num >= 90100 ? 'OpenSSL' : 'SSLeay';
    $self->show_found_var("Found $package version", $ver_str);
    $self->package($package);
    $self->ver_str($ver_str);
    $self->ver_num($ver_num);
}

sub set_define {
    my $self = shift;

    my $ver_num = $self->ver_num();
    my $unsafe_mode = exists $self->opts()->{'unsafe-mode'};
    my $debug_mode  = exists $self->opts()->{'debug-mode'};

    my $define =  "-DFILTER_CRYPTO_OPENSSL_VERSION=$ver_num";
    $define   .= ' -DFILTER_CRYPTO_UNSAFE_MODE' if $unsafe_mode;
    $define   .= ' -DFILTER_CRYPTO_DEBUG_MODE'  if $debug_mode;

    $self->define($define);
}

sub locate_lib_dir_and_file {
    my $self = shift;

    # The libraries are normally located in the lib/ sub-directory of the prefix
    # directory, but may be in the lib64/ sub-directory on 64-bit systems.  (The
    # latter may have lib/ directories as well, so check in lib64/ first.)
    # Again, build directories on "native" Windows platforms may have the files
    # in a different sub-directory, in this case out32/, out32dll/, out32.dbg/
    # or out32dll.dbg/ (0.9.0 onwards, depending on whether static or dynamic
    # libraries were built and whether they were built in release or debug mode)
    # or out/ (up to and including 0.8.1b).
    my $prefix_dir = $self->prefix_dir();
    my($dir, $lib_dir, $lib_file, $lib_name);
    if (-d ($dir = catdir($prefix_dir, 'lib64')) and
        ($lib_file, $lib_name) = $self->probe_for_lib_file($dir))
    {
        $lib_dir = $dir;
    }
    elsif (-d ($dir = catdir($prefix_dir, 'lib')) and
           ($lib_file, $lib_name) = $self->probe_for_lib_file($dir))
    {
        $lib_dir = $dir;
    }
    elsif ($self->is_win32()) {
        if (-d ($dir = catdir($prefix_dir, 'out32')) and
            ($lib_file, $lib_name) = $self->probe_for_lib_file($dir))
        {
            $lib_dir = $dir;
        }
        elsif (-d ($dir = catdir($prefix_dir, 'out32dll')) and
               ($lib_file, $lib_name) = $self->probe_for_lib_file($dir))
        {
            $lib_dir = $dir;
        }
        elsif (-d ($dir = catdir($prefix_dir, 'out32.dbg')) and
               ($lib_file, $lib_name) = $self->probe_for_lib_file($dir))
        {
            $lib_dir = $dir;
        }
        elsif (-d ($dir = catdir($prefix_dir, 'out32dll.dbg')) and
               ($lib_file, $lib_name) = $self->probe_for_lib_file($dir))
        {
            $lib_dir = $dir;
        }
        elsif (-d ($dir = catdir($prefix_dir, 'out')) and
               ($lib_file, $lib_name) = $self->probe_for_lib_file($dir))
        {
            $lib_dir = $dir;
        }
    }

    if (defined $lib_dir) {
        $self->show_found_var('Found crypto library', $lib_file);
        $self->lib_dir($lib_dir);
        $self->lib_name($lib_name);
    }
    else {
        $self->exit_with_error(109, 'No crypto library found');
    }
}

sub probe_for_lib_file {
    my $self = shift;
    my $candidate_lib_dir = shift;

    # The libraries on UNIX-type platforms (which includes Cygwin) are called
    # libssl.a (which contains the SSL and TLS implmentations) and libcrypto.a
    # (which contains the ciphers, digests, etc) and are specified as -lssl and
    # -lcrypto respectively.
    # On "native" Windows platforms built with the Microsoft Visual C++ (cl) or
    # Borland C++ (bcc32) they are called ssleay32.lib and libeay32.lib and are
    # specified as -lssleay32 and -llibeay32 (0.8.0 onwards), or ssl32.lib and
    # crypt32.lib, specified as -lssl32 and -lcrypt32 (0.6.0 to 0.6.6b
    # inclusive), or ssl.lib and crypto.lib, specified as -lssl and -lcrypto
    # (0.5.2 and 0.5.2a).
    # It is also possible to produce "native" Windows builds using GCC (i.e.
    # binaries and libraries that are linked against the Microsoft C run-time
    # library msvcrt.dll rather than Cygwin's POSIX C run-time library
    # cygwin1.dll) via MinGW (gcc).  In that case, the OpenSSL libraries are
    # called either libssl.a and libcrypto.a (for static builds) or libssl32.a
    # and libeay32.a [sic] (for dynamic builds).  They are specified as on UNIX-
    # type platforms, as described in the ExtUtils::Liblist manpage.
    my($file, $lib_file, $lib_name);
    if ($self->is_win32()) {
        if ($Config{cc} =~ /gcc/io) {
            if (-f ($file = catfile($candidate_lib_dir, 'libcrypto.a'))) {
                $lib_file = $file;
                $lib_name = 'crypto';
            }
            elsif (-f ($file = catfile($candidate_lib_dir, 'libeay32.a'))) {
                $lib_file = $file;
                $lib_name = 'eay32';
            }
        }
        else {
            if (-f ($file = catfile($candidate_lib_dir, 'libeay32.lib'))) {
                $lib_file = $file;
                $lib_name = 'libeay32';
            }
            elsif (-f ($file = catfile($candidate_lib_dir, 'crypt32.lib'))) {
                $lib_file = $file;
                $lib_name = 'crypt32';
            }
            elsif (-f ($file = catfile($candidate_lib_dir, 'crypto.lib'))) {
                $lib_file = $file;
                $lib_name = 'crypto';
            }
        }
    }
    else {
        if (-f ($file = catfile($candidate_lib_dir, 'libcrypto.a'))) {
            $lib_file = $file;
            $lib_name = 'crypto';
        }
    }

    return $lib_file ? ($lib_file, $lib_name) : ();
}

sub set_libs {
    my $self = shift;

    my $lib_dir  = $self->lib_dir();
    my $lib_name = $self->lib_name();
    $self->libs("-L$lib_dir -l$lib_name");
}

sub locate_bin_file {
    my $self = shift;

    # The binaries are normally located in the bin/ sub-directory of the prefix
    # directory.
    # However, we may be working with a build directory rather than an
    # installation directory, in which case the binary files will be in a
    # different sub-directory on "native" Windows platforms, in this case
    # out32/, out32dll/, out32.dbg/ or out32dll.dbg/ (0.9.0 onwards, depending
    # on whether static or dynamic libraries were built and whether they were
    # built in release or debug mode) or out/ (up to and including 0.8.1b).
    my $prefix_dir = $self->prefix_dir();
    my($dir, $bin_file);
    my $found = 0;
    if (-d ($dir = catdir($prefix_dir, 'bin')) and
        defined($bin_file = $self->probe_for_bin_file($dir)))
    {
        $found = 1;
    }
    elsif ($self->is_win32()) {
        if (-d ($dir = catdir($prefix_dir, 'out32')) and
            defined($bin_file = $self->probe_for_bin_file($dir)))
        {
            $found = 1;
        }
        elsif (-d ($dir = catdir($prefix_dir, 'out32dll')) and
               defined($bin_file = $self->probe_for_bin_file($dir)))
        {
            $found = 1;
        }
        elsif (-d ($dir = catdir($prefix_dir, 'out32.dbg')) and
               defined($bin_file = $self->probe_for_bin_file($dir)))
        {
            $found = 1;
        }
        elsif (-d ($dir = catdir($prefix_dir, 'out32dll.dbg')) and
               defined($bin_file = $self->probe_for_bin_file($dir)))
        {
            $found = 1;
        }
        elsif (-d ($dir = catdir($prefix_dir, 'out')) and
               defined($bin_file = $self->probe_for_bin_file($dir)))
        {
            $found = 1;
        }
    }

    if ($found) {
        $self->show_found_var('Found binary executable', $bin_file);
        $self->bin_file($bin_file)
    }
    else {
        $self->exit_with_error(111, 'No binary executable found');
    }
}

sub probe_for_bin_file {
    my $self = shift;
    my $candidate_bin_dir = shift;

    # The main binary executable is called "openssl" from 0.9.3 onwards, but
    # used to be called "ssleay" up to and including 0.9.2b.
    my($file, $bin_file);
    if (-f ($file = catfile($candidate_bin_dir, "openssl$Config{_exe}"))) {
        $bin_file = $file;
    }
    elsif (-f ($file = catfile($candidate_bin_dir, "ssleay$Config{_exe}"))) {
        $bin_file = $file;
    }

    return $bin_file;
}

sub query_cipher_name {
    my $self = shift;

    my $ver_num = $self->ver_num();

    # Find out (as best as we can) which ciphers, if any, have been disabled in
    # the particular crypto library that we are using.  Ciphers can be disabled
    # at build time via "-DOPENSSL_NO_<cipher_name>" (or "-DNO_<cipher_name>"
    # before 0.9.7), where <cipher_name> can be one of: "DES", "RC4", "IDEA",
    # "RC2", "BF" (or "BLOWFISH" before 0.9.3), "RC5", "CAST" or "AES".  This
    # information is normally contained in the output of the main binary
    # executable's "version -a" command, labelled "compiler: " (or "C flags:"
    # before 0.9.2) and not always on a line of its own.
    my $bin_file = $self->bin_file();
    my $bin_cmd = "$bin_file version -a 2>&1";

    my $bin_output = `$bin_cmd`;
    my $bin_rc = $? >> 8;

    if ($bin_rc) {
        $self->exit_with_error(112,
            "Could not get %s version information (%d):\n%s",
            $self->package(), $bin_rc, $bin_output
        );
    }

    my %disabled = ();
    if ((my $compiler) = $bin_output =~ /(?:C flags|compiler): ?(.*)$/imo) {
        %disabled = map { $_ => 1 }
                    $compiler =~ m|[-/]D ?"?(?:OPENSSL_)?NO_(\w+)"?|go;
    }

    my @cipher_names = ();

    # The DES, DES-EDE, DES-EDE3, RC4 and IDEA ciphers have been in the crypto
    # library since the earliest version that had the EVP_*() functions
    # (SSLeay 0.5.1).
    if (not exists $disabled{DES}) {
        push @cipher_names, (
            [ CIPHER_NAME_DES,      'DES block cipher'                  ],
            [ CIPHER_NAME_DES_EDE,  'Two key triple DES block cipher'   ],
            [ CIPHER_NAME_DES_EDE3, 'Three key triple DES block cipher' ]
        );
    }

    if (not exists $disabled{RC4}) {
        push @cipher_names, (
            [ CIPHER_NAME_RC4, 'RC4 stream cipher' ]
        );
    }

    if (not exists $disabled{IDEA}) {
        push @cipher_names, (
            [ CIPHER_NAME_IDEA, 'IDEA block cipher' ]
        );
    }

    # The RC2 cipher was added in SSLeay 0.5.2.
    if (not exists $disabled{RC2} and $ver_num >= 50200) {
        push @cipher_names, (
            [ CIPHER_NAME_RC2, 'RC2 block cipher' ]
        );
    }

    # The DESX cipher was added in SSLeay 0.6.2.
    if (not exists $disabled{DES} and $ver_num >= 60200) {
        push @cipher_names, (
            [ CIPHER_NAME_DESX, 'DESX block cipher' ]
        );
    }

    # The Blowfish cipher was added in SSLeay 0.6.6.
    if (not exists $disabled{BLOWFISH} and not exists $disabled{BF} and
        $ver_num >= 60600)
    {
        push @cipher_names, (
            [ CIPHER_NAME_BLOWFISH, 'Blowfish block cipher' ]
        );
    }

    # The null cipher was added in SSLeay 0.8.0.
    if ($ver_num >= 80000) {
        push @cipher_names, (
            [ CIPHER_NAME_NULL, 'Null cipher' ]
        );
    }

    # The RC5 and CAST5 ciphers were added in SSLeay 0.9.0.
    if (not exists $disabled{RC5} and $ver_num >= 90000) {
        push @cipher_names, (
            [ CIPHER_NAME_RC5, 'RC5 block cipher' ]
        );
    }

    if (not exists $disabled{CAST} and $ver_num >= 90000) {
        push @cipher_names, (
            [ CIPHER_NAME_CAST5, 'CAST5 block cipher' ]
        );
    }

    # The AES cipher was added in OpenSSL 0.9.7.
    if (not exists $disabled{AES} and $ver_num >= 90700) {
        push @cipher_names, (
            [ CIPHER_NAME_AES, 'AES block cipher' ]
        );
    }

    my $cipher_name = $self->opts()->{'cipher-name'};
    if (defined $cipher_name) {
        my %lc_cipher_names = map { lc $_->[0] => 1 } @cipher_names;
        if (exists $lc_cipher_names{lc $cipher_name}) {
            $self->show_found_var('Using specified cipher name', $cipher_name);
        }
        else {
            $self->exit_with_error(113,
                "No such cipher name '%s'", $cipher_name
            );
        }
    }
    else {
        my $message  = 'Cipher algorithms available:';
        my $question = 'Which cipher algorithm do you want to use?';

        my $default;
        if (not exists $disabled{DES} and $ver_num < 90700) {
            $default = CIPHER_NAME_DES_EDE3;
        }
        elsif (not exists $disabled{AES} and $ver_num >= 90700) {
            $default = CIPHER_NAME_AES;
        }
        else {
            $default = $cipher_names[$#cipher_names][0];
        }

        $cipher_name = $self->prompt_list(
            $message, \@cipher_names, $question, $default
        );
    }
    print "\n";

    $self->cipher_name($cipher_name);
}

sub query_cipher_mode {
    my $self = shift;

    my @cipher_modes = (
        [ CIPHER_MODE_ECB, 'ECB (Electronic Codebook Mode)'    ],
        [ CIPHER_MODE_CBC, 'CBC (Cipher Block Chaining Mode)'  ],
        [ CIPHER_MODE_CFB, 'CFB (64-Bit Cipher Feedback Mode)' ],
        [ CIPHER_MODE_OFB, 'OFB (64-Bit Output Feedback Mode)' ]
    );

    my $cipher_mode = $self->opts()->{'cipher-mode'};
    if (defined $cipher_mode) {
        my %lc_cipher_modes = map { lc $_->[0] => $_->[0] } @cipher_modes;
        if (exists $lc_cipher_modes{lc $cipher_mode}) {
            $self->show_found_var('Using specified cipher mode', $cipher_mode);
            $cipher_mode = $lc_cipher_modes{lc $cipher_mode};
        }
        else {
            $self->exit_with_error(114,
                "No such cipher mode '%s'", $cipher_mode
            );
        }
    }
    else {
        my $message  = 'Modes of operation available:';
        my $question = 'Which mode of operation do you want to use?';
        my $default  = CIPHER_MODE_CBC;

        $cipher_mode = $self->prompt_list(
            $message, \@cipher_modes, $question, $default
        );
    }
    print "\n";

    return $cipher_mode;
}

sub query_key_len {
    my $self = shift;
    my %args = @_;

    my $ver_num = $self->ver_num();

    my $validate;
    if (exists $args{-fixed}) {
        $validate = sub { $_[0] eq $args{-fixed} };
    }
    elsif ($ver_num < 90600) {
        # Before 0.9.6 there was no facility in the EVP library API for setting
        # the key length for variable key lengths ciphers so we can only use the
        # default value.  This should have been specified in the %args, but we
        # provide a default default value of 16 just in case.
        $args{-default} = 16 unless exists $args{-default};
        $validate = sub { $_[0] eq $args{-default} };
    }
    elsif (exists $args{-valid}) {
        my %valid = map { $_ => 1 } @{$args{-valid}};
        $validate = sub { exists $valid{$_[0]} };
    }
    else {
        my $int_pat = qr/^(?:0|[1-9](?:\d+)?)$/o;
        # Minimum key size is clearly 0 bytes if it is not otherwise set
        # already.  Restrict the maximum key size to some sensible value if it
        # is not set already: we do not want to allow the user to enter an
        # arbitrarily large integer.
        $args{-min} = 0    unless exists $args{-min};
        $args{-max} = 1024 unless exists $args{-max};
        $validate = sub {
            $_[0] =~ $int_pat and $_[0] >= $args{-min} and $_[0] <= $args{-max}
        };
    }

    my $key_len = $self->opts()->{'key-len'};
    my $key = $self->opts()->{key};
    if (defined $key_len) {
        if ($validate->($key_len)) {
            $self->show_found_var('Using specified key length', $key_len);
        }
        else {
            $self->exit_with_error(115, "Invalid key length '%d'", $key_len);
        }
    }
    elsif (defined $key and $key ne RAND_OPTION_STR) {
        $key_len = length($key) / 2;
        if ($validate->($key_len)) {
            $self->show_found_var('Using inferred key length', $key_len);
        }
        else {
            $self->exit_with_error(116, "Invalid length key (%d)", $key_len);
        }
    }
    elsif (exists $args{-fixed}) {
        $key_len = $args{-fixed};
        $self->show_found_var('Using fixed key length', $key_len);
    }
    elsif ($ver_num < 90600) {
        $key_len = $args{-default};
        $self->show_found_var('Using default key length', $key_len);
    }
    else {
        my $message = "This is a variable key length algorithm.\n";

        if (exists $args{-valid}) {
            my @key_lens = @{$args{-valid}};
            my $max_key_len = pop @key_lens;
            $message .= sprintf 'Valid key lengths are: %s or %d bytes.',
                                join(', ', @key_lens), $max_key_len;
        }
        else {
            $message .= sprintf 'Valid key lengths are from %d byte%s up to ' .
                                '%d byte%s.',
                                $args{-min}, $args{-min} == 1 ? '' : 's',
                                $args{-max}, $args{-max} == 1 ? '' : 's';
        }

        my $question = 'What key length (in bytes) do you want to use?';

        $key_len = $self->prompt_validate(
            -message  => $message,
            -question => $question,
            -default  => $args{-default},
            -validate => $validate
        );
    }
    print "\n";

    $self->key_len($key_len);
}

sub query_rc2_key_bits {
    my $self = shift;

    # The "effective key bits" parameter can be from 1 to 1024 bits: see RFC
    # 2268.
    my %args = (-min => 1, -max => 1024, -default => 128);

    my $ver_num = $self->ver_num();

    my $validate;
    if ($ver_num < 90600) {
        # Before 0.9.6 there was no facility in the EVP library API for setting
        # the effective key bits for the RC2 cipher so we can only use the
        # default value.
        $validate = sub { $_[0] eq $args{-default} };
    }
    else {
        my $int_pat = qr/^(?:0|[1-9](?:\d+)?)$/o;
        $validate = sub {
            $_[0] =~ $int_pat and $_[0] >= $args{-min} and $_[0] <= $args{-max}
        };
    }

    my $rc2_key_bits = $self->opts()->{'rc2-key-bits'};
    if (defined $rc2_key_bits) {
        if ($validate->($rc2_key_bits)) {
            $self->show_found_var(
                'Using specified RC2 key bits', $rc2_key_bits
            );
        }
        else {
            $self->exit_with_error(117,
                "Invalid RC2 key bits '%d'", $rc2_key_bits
            );
        }
    }
    elsif ($ver_num < 90600) {
        $rc2_key_bits = $args{-default};
        $self->show_found_var('Using default RC2 key bits', $rc2_key_bits);
    }
    else {
        my $message = "This algorithm also has an 'effective key bits' (EKB) " .
                      "parameter.\n";

        $message .= sprintf 'Valid EKB values are from %d bit%s up to %d ' .
                            'bit%s.',
                            $args{-min}, $args{-min} == 1 ? '' : 's',
                            $args{-max}, $args{-max} == 1 ? '' : 's';

        my $question = 'What EKB value (in bits) do you want to use?';

        $rc2_key_bits = $self->prompt_validate(
            -message  => $message,
            -question => $question,
            -default  => $args{-default},
            -validate => $validate
        );
    }
    print "\n";

    $self->rc2_key_bits($rc2_key_bits);
}

sub query_rc5_rounds {
    my $self = shift;

    # The "number of rounds" parameter can be from 0 to 255: see RFC 2040.
    # However, it can currently only be set to 8, 12 or 16 by the RC5 code in
    # OpenSSL: see EVP_EncryptInit.pod in recent OpenSSL distributions.
    my %args = (-valid => [8, 12, 16], -default => 12);

    my $ver_num = $self->ver_num();

    my $validate;
    if ($ver_num < 90600) {
        # Before 0.9.6 there was no facility in the EVP library API for setting
        # the number of rounds for the RC5 cipher so we can only use the default
        # value.
        $validate = sub { $_[0] eq $args{-default} };
    }
    else {
        my %valid = map { $_ => 1 } @{$args{-valid}};
        $validate = sub { exists $valid{$_[0]} };
    }

    my $rc5_rounds = $self->opts()->{'rc5-rounds'};
    if (defined $rc5_rounds) {
        if ($validate->($rc5_rounds)) {
            $self->show_found_var('Using specified RC5 rounds', $rc5_rounds);
        }
        else {
            $self->exit_with_error(118,
                "Invalid RC5 rounds '%d'", $rc5_rounds
            );
        }
    }
    elsif ($ver_num < 90600) {
        $rc5_rounds = $args{-default};
        $self->show_found_var('Using default RC5 rounds', $rc5_rounds);
    }
    else {
        my $message = "This algorithm also has a 'number of rounds' " .
                      "parameter.\n";

        my @rc5_rounds = @{$args{-valid}};
        my $max_rc5_rounds = pop @rc5_rounds;
        $message .= sprintf 'Valid numbers of rounds are: %s or %d.',
                            join(', ', @rc5_rounds), $max_rc5_rounds;

        my $question = 'What number of rounds do you want to use?';

        $rc5_rounds = $self->prompt_validate(
            -message  => $message,
            -question => $question,
            -default  => $args{-default},
            -validate => $validate
        );
    }
    print "\n";

    $self->rc5_rounds($rc5_rounds);
}

sub query_pswd_or_key {
    my $self = shift;

    my $key_len = $self->key_len();

    if ($key_len == 0) {
        $self->key('');
        return;
    }

    my $validate_pswd = sub {
        $_[0] ne ''
    };

    my $validate_key = sub {
        $_[0] =~ /^[0-9a-f]*$/io and length $_[0] == 2 * $key_len
    };

    my $pswd = $self->opts()->{pswd};
    my $key  = $self->opts()->{key};
    if (defined $pswd) {
        if (lc $pswd eq lc RAND_OPTION_STR) {
            $pswd = $self->generate_rand_pswd();
            print "\n";

            $self->show_found_var('Using randomly generated password', $pswd);
            $self->pswd($pswd);
        }
        elsif ($validate_pswd->($pswd)) {
            $self->show_found_var('Using specified password', $pswd);
            $self->pswd(unpack 'H*', $pswd);
        }
        else {
            $self->exit_with_error(119, "Invalid password '%s'", $pswd);
        }
    }
    elsif (defined $key) {
        if (lc $key eq lc RAND_OPTION_STR) {
            $key = $self->generate_rand_key();
            print "\n";

            $self->show_found_var('Using randomly generated key', $key);
            $self->key($key);
        }
        elsif ($validate_key->($key)) {
            $self->show_found_var('Using specified key', $key);
            $self->key($key);
        }
        else {
            $self->exit_with_error(120, "Invalid key '%s'", $key);
        }
    }
    else {
        my @cipher_key_sources = (
            [ CIPHER_KEY_GIVEN_PSWD,  'Enter a password when prompted'     ],
            [ CIPHER_KEY_RANDOM_PSWD, 'Have a password randomly generated' ],
            [ CIPHER_KEY_GIVEN,       'Enter a key when prompted'          ],
            [ CIPHER_KEY_RANDOM,      'Have a key randomly generated'      ]
        );
    
        my $message  = 'You can either specify a password from which the ' .
                       'key to be used for encryption/decryption will be ' .
                       'derived using a PKCS#5 key derivation algorithm, or ' .
                       "you can directly specify the key to use.\n" .
                       'You can also have a password or key randomly ' .
                       "generated for you.\n\n" .
                       'Options for specifying or deriving the key:';
        my $question = 'How do you want to specify or derive the key?';
        my $default  = CIPHER_KEY_RANDOM_PSWD;

        my $cipher_key_source = $self->prompt_list(
            $message, \@cipher_key_sources, $question, $default
        );
    
        print "\n";
    
        if ($cipher_key_source == CIPHER_KEY_GIVEN_PSWD) {
            $message  = 'Enter your password:';
            $question = 'Password?';
            $default  = '';

            $pswd = $self->prompt_validate(
                -message  => $message,
                -question => $question,
                -default  => $default,
                -validate => $validate_pswd
            );

            $self->pswd(unpack 'H*', $pswd);
        }
        elsif ($cipher_key_source == CIPHER_KEY_RANDOM_PSWD) {
            $pswd = $self->generate_rand_pswd();
            $self->pswd($pswd);
        }
        elsif ($cipher_key_source == CIPHER_KEY_GIVEN) {
            $message  = "Enter your ${key_len}-byte key with each byte " .
                        "written as a pair of hexadecimal digits with the " .
                        "high nybble first:";
            $question = 'Key?';
            $default  = '';

            $key = $self->prompt_validate(
                -message  => $message,
                -question => $question,
                -default  => $default,
                -validate => $validate_key
            );

            $self->key($key);
        }
        elsif ($cipher_key_source == CIPHER_KEY_RANDOM) {
            $key = $self->generate_rand_key();
            $self->key($key);
        }
        else {
            $self->exit_with_error(121,
                "Unknown key source '%s'", $cipher_key_source
            );
        }
    }

    print "\n";
}

sub generate_rand_key {
    my $self = shift;
    return $self->generate_rand_octets_hex($self->key_len());
}

sub generate_rand_pswd {
    my $self = shift;
    return $self->generate_rand_octets_hex(RAND_PSWD_LEN);
}

sub generate_rand_octets_hex {
    my $self = shift;
    my $num_octets = shift;

    my $rng = $self->query_rng();

    my $octets;
    if (lc $rng eq lc RNG_PERL_RAND) {
        $octets = '';
        for (1 .. $num_octets) {
            $octets .= chr int rand 256;
        }
    }
    elsif (lc $rng eq lc RNG_CRYPT_RANDOM) {
        # Delay the loading of Crypt::Random until it is actually required since
        # it is not a standard module.
        my $ok = eval {
            require Crypt::Random;
            Crypt::Random->import(qw(makerandom_octet));
            1;
        };

        if (not $ok) {
            $self->exit_with_error(122,
                "Can't load Crypt::Random module for random number generation"
            );
        }

        # Specify "Strength => 0" to use /dev/urandom rather than /dev/random
        # to avoid potentially blocking for a long time.
        $octets = makerandom_octet(
            Length => $num_octets, Strength => 0
        );
    }
    elsif (lc $rng eq lc RNG_MATH_RANDOM) {
        # Delay the loading of Math::Random until it is actually required since
        # it is not a standard module.
        my $ok = eval {
            require Math::Random;
            Math::Random->import(qw(random_uniform_integer));
            1;
        };

        if (not $ok) {
            $self->exit_with_error(123,
                "Can't load Math::Random module for random number generation"
            );
        }

        $octets = join '',
                       map { chr } random_uniform_integer($num_octets, 0, 255);
    }
    elsif (lc $rng eq lc RNG_OPENSSL_RAND) {
        my $bin_file = $self->bin_file();
        my $out_filename = 'rand.out';

        my $bin_cmd = "$bin_file rand -out $out_filename $num_octets 2>&1";

        my $bin_output = `$bin_cmd`;
        my $bin_rc = $? >> 8;

        if ($bin_rc) {
            $self->exit_with_error(124,
                "Could not generate %d random bytes (%d):\n%s",
                $num_octets, $bin_rc, $bin_output
            );
        }

        sysopen my $out_fh, $out_filename, O_RDONLY | O_BINARY or
            $self->exit_with_error(125,
                "Could not open random bytes output file '%s' for reading: %s",
                $out_filename, $!
            );

        my $num_octets_read = sysread $out_fh, $octets, $num_octets;
        if (not defined $num_octets_read) {
            $self->exit_with_error(126,
                "Could not read random bytes from output file '%s': %s",
                $out_filename, $!
            );
        }
        elsif ($num_octets_read != $num_octets) {
            $self->exit_with_error(127,
                "Could not read random bytes from output file '%s': %d bytes " .
                "read, %d bytes expected",
                $out_filename, $num_octets_read, $num_octets
            );
        }

        close $out_fh;
        unlink $out_filename;
    }
    else {
        $self->exit_with_error(128,
            "Unknown random number generator '%s'", $rng
        );
    }

    return unpack 'H*', $octets;
}

sub query_rng {
    my $self = shift;

    my $ver_num = $self->ver_num();
    my $package = $self->package();

    my @rngs = (
        [ RNG_PERL_RAND, "Perl's built-in rand() function" ]
    );

    if (eval { require Crypt::Random; 1 }) {
        push @rngs, (
            [ RNG_CRYPT_RANDOM, 'Crypt::Random' ]
        );
    }

    if (eval { require Math::Random; 1 }) {
        push @rngs, (
            [ RNG_MATH_RANDOM, 'Math::Random' ]
        );
    }

    # The "rand" command was added in OpenSSL 0.9.5a.
    if ($ver_num >= 90501) {
        push @rngs, (
            [ RNG_OPENSSL_RAND, "${package}'s rand command" ]
        );
    }

    my $rng = $self->opts()->{rng};
    if (defined $rng) {
        my %lc_rngs = map { lc $_->[0] => $_->[0] } @rngs;
        if (exists $lc_rngs{lc $rng}) {
            $self->show_found_var('Using specified RNG', $rng);
            $rng = $lc_rngs{lc $rng};
        }
        else {
            $self->exit_with_error(129,
                "Invalid random number generator '%s'", $rng
            );
        }
    }
    else {
        my $message  = 'Random number generators:';
        my $question = 'Which RNG do you want to use?';
        my $default  = $rngs[$#rngs][0];

        $rng = $self->prompt_list(
            $message, \@rngs, $question, $default
        );
    }

    return $rng;
}

sub configure_des_cipher {
    my $self = shift;

    my %cipher_funcs = (
        CIPHER_MODE_ECB, 'EVP_des_ecb()',
        CIPHER_MODE_CBC, 'EVP_des_cbc()',
        CIPHER_MODE_CFB, 'EVP_des_cfb()',
        CIPHER_MODE_OFB, 'EVP_des_ofb()'
    );
    my $cipher_mode = $self->query_cipher_mode();
    $self->cipher_func($cipher_funcs{$cipher_mode});
    $self->cipher_needs_iv(1);

    # The DES cipher can only use an 8 byte key (of which only 7 bytes are
    # actually used by the algorithm): see FIPS PUB 46-3.
    $self->query_key_len(-fixed => 8);
}

sub configure_des_ede_cipher {
    my $self = shift;

    my $ver_num = $self->ver_num();
    my %cipher_funcs = (
        CIPHER_MODE_ECB, ($ver_num < 90700
                          ? 'EVP_des_ede()' : 'EVP_des_ede_ecb()'),
        CIPHER_MODE_CBC, 'EVP_des_ede_cbc()',
        CIPHER_MODE_CFB, 'EVP_des_ede_cfb()',
        CIPHER_MODE_OFB, 'EVP_des_ede_ofb()'
    );
    my $cipher_mode = $self->query_cipher_mode();
    $self->cipher_func($cipher_funcs{$cipher_mode});
    $self->cipher_needs_iv(1);

    # The DES-EDE cipher is two-key triple-DES (i.e. in which an encrypt
    # operation is encrypt with key 1, decrypt with key 2, encrypt with key 1),
    # and therefore requires a key length equivalent to two DES keys, i.e. 16
    # bytes (of which only 14 are used).
    $self->query_key_len(-fixed => 16);
}

sub configure_des_ede3_cipher {
    my $self = shift;

    my $ver_num = $self->ver_num();
    my %cipher_funcs = (
        CIPHER_MODE_ECB, ($ver_num < 90700
                          ? 'EVP_des_ede3()' : 'EVP_des_ede3_ecb()'),
        CIPHER_MODE_CBC, 'EVP_des_ede3_cbc()',
        CIPHER_MODE_CFB, 'EVP_des_ede3_cfb()',
        CIPHER_MODE_OFB, 'EVP_des_ede3_ofb()'
    );
    my $cipher_mode = $self->query_cipher_mode();
    $self->cipher_func($cipher_funcs{$cipher_mode});
    $self->cipher_needs_iv(1);

    # The DES-EDE3 cipher is three-key triple-DES (i.e. in which an encrypt
    # operation is encrypt with key 1, decrypt with key 2, encrypt with key 3),
    # and therefore requires a key length equivalent to two DES keys, i.e. 24
    # bytes (of which only 21 are used).
    $self->query_key_len(-fixed => 24);
}

sub configure_rc4_cipher {
    my $self = shift;

    $self->cipher_func('EVP_rc4()');
    $self->cipher_needs_iv(0);

    # The RC4 cipher can use any key length: see rc4.doc in old SSLeay
    # distributions.
    $self->query_key_len(-min => 1, -default => 16);
}

sub configure_idea_cipher {
    my $self = shift;

    my %cipher_funcs = (
        CIPHER_MODE_ECB, 'EVP_idea_ecb()',
        CIPHER_MODE_CBC, 'EVP_idea_cbc()',
        CIPHER_MODE_CFB, 'EVP_idea_cfb()',
        CIPHER_MODE_OFB, 'EVP_idea_ofb()'
    );
    my $cipher_mode = $self->query_cipher_mode();
    $self->cipher_func($cipher_funcs{$cipher_mode});
    $self->cipher_needs_iv(1);

    # The IDEA cipher can only use a 16 byte key: see idea.doc in old SSLeay
    # distributions.
    $self->query_key_len(-fixed => 16);
}

sub configure_rc2_cipher {
    my $self = shift;

    my %cipher_funcs = (
        CIPHER_MODE_ECB, 'EVP_rc2_ecb()',
        CIPHER_MODE_CBC, 'EVP_rc2_cbc()',
        CIPHER_MODE_CFB, 'EVP_rc2_cfb()',
        CIPHER_MODE_OFB, 'EVP_rc2_ofb()'
    );
    my $cipher_mode = $self->query_cipher_mode();
    $self->cipher_func($cipher_funcs{$cipher_mode});
    $self->cipher_needs_iv(1);

    # The RC2 cipher can use any key length from 1 to 128 bytes: see RFC 2268.
    $self->query_key_len(-min => 1, -max => 128, -default => 16);

    # The RC2 cipher also has a parameter called "effective key bits".
    $self->query_rc2_key_bits();
}

sub configure_desx_cipher {
    my $self = shift;

    $self->cipher_func('EVP_desx_cbc()');
    $self->cipher_needs_iv(1);

    # The DESX cipher can only use a 24 byte key: see des.pod in recent OpenSSL
    # distributions.
    $self->query_key_len(-fixed => 24);
}

sub configure_blowfish_cipher {
    my $self = shift;

    my %cipher_funcs = (
        CIPHER_MODE_ECB, 'EVP_bf_ecb()',
        CIPHER_MODE_CBC, 'EVP_bf_cbc()',
        CIPHER_MODE_CFB, 'EVP_bf_cfb()',
        CIPHER_MODE_OFB, 'EVP_bf_ofb()'
    );
    my $cipher_mode = $self->query_cipher_mode();
    $self->cipher_func($cipher_funcs{$cipher_mode});
    $self->cipher_needs_iv(1);

    # The Blowfish cipher can use any key length up to 72 bytes: see
    # blowfish.doc in old SSLeay distributions.
    $self->query_key_len(-min => 1, -max => 72, -default => 16);
}

sub configure_null_cipher {
    my $self = shift;

    $self->cipher_func('EVP_enc_null()');
    $self->cipher_needs_iv(0);

    # The null cipher does not require a key: it does nothing.
    $self->query_key_len(-fixed => 0);
}

sub configure_rc5_cipher {
    my $self = shift;

    my %cipher_funcs = (
        CIPHER_MODE_ECB, 'EVP_rc5_32_12_16_ecb()',
        CIPHER_MODE_CBC, 'EVP_rc5_32_12_16_cbc()',
        CIPHER_MODE_CFB, 'EVP_rc5_32_12_16_cfb()',
        CIPHER_MODE_OFB, 'EVP_rc5_32_12_16_ofb()'
    );
    my $cipher_mode = $self->query_cipher_mode();
    $self->cipher_func($cipher_funcs{$cipher_mode});
    $self->cipher_needs_iv(1);

    # The RC5 cipher can use any key length from 0 to 255 bytes: see RFC 2040.
    $self->query_key_len(-min => 0, -max => 255, -default => 16);

    # The RC5 cipher also has a parameter called "number of rounds".
    $self->query_rc5_rounds();
}

sub configure_cast5_cipher {
    my $self = shift;

    my %cipher_funcs = (
        CIPHER_MODE_ECB, 'EVP_cast5_ecb()',
        CIPHER_MODE_CBC, 'EVP_cast5_cbc()',
        CIPHER_MODE_CFB, 'EVP_cast5_cfb()',
        CIPHER_MODE_OFB, 'EVP_cast5_ofb()'
    );
    my $cipher_mode = $self->query_cipher_mode();
    $self->cipher_func($cipher_funcs{$cipher_mode});
    $self->cipher_needs_iv(1);

    # The CAST5 cipher can use any key length from 5 to 16 bytes: see RFC 2144.
    $self->query_key_len(-min => 5, -max => 16, -default => 16);
}

sub configure_aes_cipher {
    my $self = shift;

    my %cipher_funcs = (
        CIPHER_MODE_ECB, 'EVP_aes_ecb()',
        CIPHER_MODE_CBC, 'EVP_aes_cbc()',
        CIPHER_MODE_CFB, 'EVP_aes_cfb()',
        CIPHER_MODE_OFB, 'EVP_aes_ofb()'
    );
    my $cipher_mode = $self->query_cipher_mode();
    my $cipher_func = $cipher_funcs{$cipher_mode};

    # The AES cipher can only use a 16, 24 or 32 byte key: see FIPS PUB 197.  Do
    # not offer the choice of 24 or 32 byte keys for 0.9.7 because they do not
    # seem to work.  I do not know why, and the problem does not seem to occur
    # with debug OpenSSL builds, which does not make it very easy to find out
    # why.
    my $ver_num = $self->ver_num();
    if ($ver_num == 90700) {
        $self->query_key_len(-fixed => 16);
    }
    else {
        $self->query_key_len(-valid => [16, 24, 32], -default => 32);
    }

    my $key_len_bits = $self->key_len() * 8;
    $cipher_func =~ s/_aes_/_aes_${key_len_bits}_/;
    $self->cipher_func($cipher_func);
    $self->cipher_needs_iv(1);
}

sub write_cipher_config {
    my $self = shift;

    open my $cfg_fh, '>', CIPHER_CONFIG_FILENAME or
        $self->exit_with_error(130,
            "Could not open configuration file '%s' for writing: %s",
            CIPHER_CONFIG_FILENAME, $!
        );

    my $package    = $self->package();
    my $prefix_dir = $self->prefix_dir();
    my $ver_str    = $self->ver_str();

    print $cfg_fh <<"EOT";
/*============================================================================
 *
 * @{[CIPHER_CONFIG_FILENAME]}
 *
 * DESCRIPTION
 *   Cipher configuration file for Filter::Crypto modules.
 *
 *   DO NOT EDIT THIS FILE!
 *
 *   This file is written by Makefile.PL from its command-line option values
 *   and/or default values.  Any changes made here will be lost the next time
 *   Makefile.PL is run.
 *
 *   Created at @{[scalar localtime]} by Perl version $], installed as
 *   $^X
 *
 *   Configured against $package version $ver_str, installed under
 *   $prefix_dir
 *
 *============================================================================*/

EOT

    my $cipher_func = $self->cipher_func();
    print $cfg_fh "#define FILTER_CRYPTO_CIPHER_FUNC  $cipher_func\n";

    if ($self->cipher_needs_iv()) {
        print $cfg_fh "#define FILTER_CRYPTO_NEED_IV      1\n";
    }
    else {
        print $cfg_fh "#define FILTER_CRYPTO_NEED_IV      0\n";
    }

    my $key_len = $self->key_len();
    print $cfg_fh "#define FILTER_CRYPTO_KEY_LEN      $key_len\n";

    my $rc2_key_bits = $self->rc2_key_bits();
    my $rc5_rounds   = $self->rc5_rounds();
    if (defined $rc2_key_bits) {
        print $cfg_fh "#define FILTER_CRYPTO_RC2_KEY_BITS $rc2_key_bits\n";
    }
    elsif (defined $rc5_rounds) {
        print $cfg_fh "#define FILTER_CRYPTO_RC5_ROUNDS   $rc5_rounds\n";
    }

    my($def, $var);
    if ($key_len == 0) {
        $def = '#define FILTER_CRYPTO_USING_PBE    0';
        $var = 'static const unsigned char *filter_crypto_key = NULL;';
    }
    else {
        my $pswd = $self->pswd();
        if (defined $pswd) {
            $def = '#define FILTER_CRYPTO_USING_PBE    1';
            $pswd = $self->format_chars($pswd);
            my $ver_num = $self->ver_num();
            if ($ver_num < 90400) {
                $var = "static unsigned char filter_crypto_pswd[] = {\n" .
                       "$pswd\n" .
                       "};";
            }
            else {
                $var = "static const unsigned char filter_crypto_pswd[] = {\n" .
                       "$pswd\n" .
                       "};";
            }
        }
        else {
            $def = '#define FILTER_CRYPTO_USING_PBE    0';
            my $key = $self->key();
            $key = $self->format_chars($key);
            $var = "static const unsigned char filter_crypto_key[] = {\n" .
                   "$key\n" .
                   "};";
        }
    }
    print $cfg_fh "$def\n\n";
    print $cfg_fh "$var\n";

    print $cfg_fh <<'EOT';

/*============================================================================*/
EOT

    close $cfg_fh;

    print wrap('', '',
        "Your cipher configuration has been written to the file '" .
        CIPHER_CONFIG_FILENAME . "'.  You may want to keep this file in a " .
        "safe place if you ever need to rebuild these modules using the same " .
        "configuration, especially if your key was randomly generated."
    ), "\n\n";
}

sub format_chars {
    my $self = shift;
    my $chars = shift;

    $chars =~ s/(..)/0x$1, /g;
    $chars =~ s/^/    /;
    $chars =~ s/, $//;
    $chars =~ s/((?:0x.., ){8})/$1\n    /g;
    $chars =~ s/ \n/\n/g;
    $chars =~ s/\n    $//;

    return $chars;
}

sub copy_cipher_config {
    my $self = shift;
    my $cipher_config_file = shift;

    if ($cipher_config_file ne CIPHER_CONFIG_FILENAME) {
        copy($cipher_config_file, CIPHER_CONFIG_FILENAME) or
            $self->exit_with_error(131,
                "Could not copy configuration file '%s' to '%s': %s",
                $cipher_config_file, CIPHER_CONFIG_FILENAME, $!
            );
    }

    print "\n";
}

1;

__END__

#===============================================================================
