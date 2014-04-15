#!perl
#===============================================================================
#
# Makefile.PL
#
# DESCRIPTION
#   Top-level makefile creation script.
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

use inc::Module::Install;

#===============================================================================
# INITIALIZATION
#===============================================================================

our $VERSION = '1.03';
{
    no warnings 'once';
    our $YEAR = '2004-2005';
}

#===============================================================================
# MAIN PROGRAM
#===============================================================================

MAIN: {
    name           ('Filter-Crypto');
    abstract_from  ('lib/Filter/Crypto.pm');
    version_from   ('lib/Filter/Crypto.pm');
    author         ('Steve Hay <shay@cpan.org>');
    license        ('perl');
    perl_version   (5.006000);
    build_requires ('Test::More');
    features       ('crypt_file -e tempfile support' => [
        -default   => 0,
        recommends ('File::Temp')
    ]);
    features       ('PAR::Filter support' => [
        -default   => 0,
        recommends ('PAR::Filter'),
        recommends ('File::Temp')
    ]);
    features       ('POD testing' => [
        -default   => 0,
        recommends ('Test::Pod' => '1.00')
    ]);
    include        ('ExtUtils::AutoInstall');
    clean_files    ('CipherConfig.h');

    my $obj = get_filter_crypto_private_obj();

    my @opt_specs = (
        'prefix-dir|d=s',
        'cipher-config|c=s',
        'cipher-name|n=s',
        'cipher-mode|m=s',
        'pswd|p=s',
        'key|k=s',
        'rng|r=s',
        'key-len|l=i',
        'rc2-key-bits=i',
        'rc5-rounds=i',
        'install-script|i=s',
        'build|b=s',
        'unsafe-mode|u',
        'debug-mode'
    );

    $obj->process_opts(\@opt_specs, 1);
    $obj->check_compiler(1);

    $obj->locate_openssl();
    $obj->configure_cipher();

    my $build = $obj->query_build();

    my @script_specs;
    if ("@$build" =~ /CryptFile/o) {
        @script_specs = qw(
            crypt_file=y
        );
    }
    else {
        @script_specs = qw(
            crypt_file=n
        );
    }

    $obj->query_scripts(\@script_specs);
    $obj->setup_env();

    WriteMakefile(
        DIR => $build,

        dist => {
            DIST_CP  => 'cp',
            PREOP    => 'chmod -R a-x+rwX,go-w $(DISTVNAME) && ' .
                        'chmod a+x $(DISTVNAME)/script/*',
            COMPRESS => 'gzip -9fv',
            SUFFIX   => '.gz',
            ZIPFLAGS => '-9r'
        }
    );
}

#===============================================================================
# MAKEMAKER OVERRIDES
#===============================================================================

# Method to temporarily remove the list of sub-directories when creating the
# (top-level) "test" target since our sub-directories have no tests of their
# own.  This saves the bother of cd'ing into them and avoids the alarming "No
# tests defined..." message when running the top-level "test" target.  (The
# sub-directories' Makefiles still have their own "test" targets, though, so
# anyone manually cd'ing into them and running those "test" targets will get the
# message about there being no tests.)
#
# This method is based on code taken from the MY::test() method in the top-level
# Makefile.PL script in the Tk distribution (version 804.027).

sub MY::test {
    my($self, %args) = @_;
    my $dir = delete $self->{DIR};
    my $str = $self->MM::test(%args);
    $self->{DIR} = $dir;
    return $str;
}

__END__

#===============================================================================
# DOCUMENTATION
#===============================================================================

=head1 NAME

Makefile.PL - Generate makefiles for Filter-Crypto distribution

=head1 SYNOPSIS

    Makefile.PL [--defaults]
                [--prefix-dir=<dir>]
                [--cipher-config=<file>]
                [--cipher-name=<name>] [--cipher-mode=<mode>]
                [--pswd={<pswd>|rand} | --key={<key>|rand}] [--rng=<rng>]
                [--key-len=<len>]
                [--rc2-key-bits=<num>] [--rc5-rounds=<num>]
                [--install-script={y|n}>
                [--build=<component>] [--unsafe-mode] [--debug-mode]
                [--version] [--help] [--manpage]
                [<arg>...]

=head1 ARGUMENTS

Any standard ExtUtils::MakeMaker command-line arguments may be specified, but
note that the guts of this distribution is contained in two modules located in
their own sub-directories with their own B<Makefile.PL>'s and not all
ExtUtils::MakeMaker arguments are necessarily passed through to such
sub-directory builds.

In particular, you should not rely on the INC and LIBS arguments for specifying
the location of the OpenSSL or SSLeay include and library directory paths.
Instead, use the B<--prefix-dir> option described below if the default value
does not match your system.

ExtUtils::MakeMaker arguments can also be given in the PERL_MM_OPTS environment
variable as usual.

=head1 OPTIONS

Any standard ExtUtils::AutoInstall command-line options may be specified.  These
can also be given in the PERL_EXTUTILS_AUTOINSTALL environment variable as
usual.

In addition, the build process for this distribution requires the answers to
various questions regarding (amongst other things) the location of OpenSSL or
SSLeay, which cipher algorithm to use, what password or key to use and whether
or not to install a script.

The command-line options detailed below can be used to provide the answers to
these questions.

If a particular question is not answered via the relevant command-line option
then B<Makefile.PL> will normally prompt the user for the answer.  However, if
it detects that it is not being run interactively and there is nothing on
C<STDIN>, or if your ExtUtils::MakeMaker is version 5.48_01 or later and either
the PERL_MM_USE_DEFAULT environment variable is set to a true value or the
B<--defaults> option is specified, then the default value indicated below in the
description of the option concerned will be used instead and no questions will
be asked.

=over 4

=item B<--defaults>

Specify that the default value indicated below of each option that is not
specified by the relevant command-line option will be used instead of prompting
the user for a response.

You must be using ExtUtils::MakeMaker version 5.48_01 or later for this option
to have any effect.

=item B<-d E<lt>dirE<gt>>, B<--prefix-dir=E<lt>dirE<gt>>

Specify the OpenSSL or SSLeay prefix directory.  This is used to determine the
include and library directories.

By default, B<Makefile.PL> will look for an B<openssl> or B<ssleay> binary
executable and determine the prefix directory from that.  Failing that, the
default prefix directory as specified in the latest OpenSSL's own F<INSTALL>
file will be assumed, namely F</usr/local/ssl>, or F<C:\openssl> on "native"
(i.e. non-Cygwin) Windows platforms.

=item B<-c E<lt>fileE<gt>>, B<--cipher-config=E<lt>fileE<gt>>

Specify the cipher configuration file to build with.  This should be a file
written by a previous run of B<Makefile.PL> containing the answers to all the
cipher configuration questions, which therefore will not be asked this time.
Any cipher configuration options specified along with this option will be
ignored.

This is useful if you ever need to rebuild this distribution using the same
configuration as was used on a previous occasion, for example, if you are
setting up two separate Perl installations, one containing the
Filter::Crypto::CryptFile module and another containing only the
Filter::Crypto::Decrypt module, as described under the B<--build> option above.

=item B<-n E<lt>nameE<gt>>, B<--cipher-name=E<lt>nameE<gt>>

Specify the name of the cipher algorithm to use.  The ciphers available will be
a subset of the following (depending on which version of OpenSSL or SSLeay you
are using and whether or not any of them were disabled when it was built):

    DES      (A block cipher with fixed key length)
    DES_EDE  (A block cipher with fixed key length)
    DES_EDE3 (A block cipher with fixed key length)
    RC4      (A stream cipher with variable key length)
    IDEA     (A block cipher with fixed key length)
    RC2      (A block cipher with variable key length)
    DESX     (A block cipher with fixed key length)
    Blowfish (A block cipher with variable key length)
    Null     (The null cipher with zero key length)
    RC5      (A block cipher with variable key length)
    CAST5    (A block cipher with variable key length)
    AES      (A block cipher with variable key length)

The default cipher is AES if it is available, or else DES_EDE3 if that is
available, or else whichever one nearest the end of the list above is available.

=item B<-m E<lt>modeE<gt>>, B<--cipher-mode=E<lt>modeE<gt>>

Specify the mode of operation if a block cipher was chosen above.  The following
modes are available:

    ECB (Electronic Codebook Mode)
    CBC (Cipher Block Chaining Mode)
    CFB (64-Bit Cipher Feedback Mode)
    OFB (64-Bit Output Feedback Mode)

The CBC mode is used by default.

This option is ignored for the DESX block cipher (which is only available in CBC
mode) and for the stream cipher(s) and the null cipher.

=item B<-p {E<lt>pswdE<gt>|rand}>, B<--pswd={E<lt>pswdE<gt>|rand}>

Specify the password from which to derive the key used for the encryption or
decryption.  (This is known as "password-based encryption" (PBE).)  The special
value "rand" means that a 32-byte password will be randomly generated using the
random number generator specified by the B<--rng> option.

The key will be derived using the PBKDF2 algorithm defined in PKCS#5 v2.0 (which
is also available as RFC2898) if you have OpenSSL 0.9.4 or later.  This is not
available in earlier versions of OpenSSL or SSLeay so in those cases a different
algorithm, largely compatible with PKCS#5 v1.5, is used instead.  In either case
an 8-byte random salt and 2048 iterations are used.  A random initialization
vector (IV) is also generated if required.  When encrypting, both the salt and
IV are prepended to the ciphertext so that they may be recovered for use when
decrypting.

Alternatively, the key may be specified directly (or randomly generated) using
the B<--key> option below.  If both options are given then B<--pswd> is used and
B<--key> is silently ignored.

Note that password-based encryption is preferable to using a fixed key if you
are going to be encrypting many files because the key used in the PBE scheme
will be different for each file that you encrypt because it is derived afresh
for each file using a new random salt.  (This, of course, is exactly the point
of the salt.)  Using the same key repeatedly is vulnerable to "dictionary
attacks", particularly if part of the files being encrypted is known or
predictable, for example, a header section like that used at the top of the
source files in this distribution.

A randomly generated password is used by default.

=item B<-k {E<lt>keyE<gt>|rand}>, B<--key={E<lt>keyE<gt>|rand}>

Specify the key if anything other than the null cipher was chosen above.  The
special value "rand" means that a key of the appropriate length will be randomly
generated using the random number generator specified by the B<--rng> option.

If a key length is also specified using the B<--key-len> option below, or if you
have chosen a fixed key length cipher or are using something earlier than
OpenSSL 0.9.6 (with which the variable key length ciphers can only be used with
their default key lengths), then the length of any key specified here must match
the relevant key length.

An N-byte key must be specified as a string of 2*N hexadecimal digits where each
pair of such digits represents one byte of the key (with the high nybble first).
This is the format produced by Perl's built-in C<unpack()> function with the 'H'
template character, i.e.

    $hexdigits = unpack 'H*', $bytes;

The key specified (or randomly generated) by this option is used directly
without being processed by any key derivation algorithm.  For password-based
encryption, use the B<--pswd> option above.  If both options are given then
B<--pswd> is used and B<--key> is silently ignored.

Note that password-based encryption is preferable to using a fixed key if you
are going to be encrypting many files.  See the description of the B<--pswd>
option above for an explanation.

A randomly generated password [sic] is used by default.

=item B<-r E<lt>rngE<gt>>, B<--rng=E<lt>rngE<gt>>

Specify the random number generator (RNG) with which to generate the password or
key if the option to have one of them randomly generated was chosen above.
Valid RNG's are:

    Perl          - Use perl's built-in rand() function
    Crypt::Random - Use the Crypt::Random Perl module
    Math::Random  - Use the Math::Random Perl module
    OpenSSL       - Use openssl's "rand" command

Note that not all of these options may be available:  Crypt::Random and
Math::Random are not standard Perl modules, and only OpenSSL 0.9.5a or later
have a C<rand> command.

The default RNG is whichever one nearest the end of the list above is available.

This option is silently ignored if a randomly generated password or key was not
chosen.

=item B<-l E<lt>lenE<gt>>, B<--key-len=E<lt>lenE<gt>>

Specify the key length (in bytes) if a variable key length cipher was chosen
above.  Valid key lengths are as follows:

    RC4      - From 1 byte upwards
    RC2      - From 1 byte up to 128 bytes
    Blowfish - From 1 byte up to 72 bytes
    RC5      - From 0 bytes up to 255 bytes
    CAST5    - From 5 bytes up to 16 bytes
    AES      - Either 16, 24 or 32 bytes

The default key length is 16 bytes for each cipher except AES which defaults to
32 bytes, unless a key is specified using the B<--key> option above in which
case the key length is inferred from that.

Note that this option can only be used to change the default key length if you
have OpenSSL version 0.9.6 or later because the facility for setting key lengths
was only added to the EVP library API used by this software in version 0.9.6.
The default key length will always be used with earlier versions of OpenSSL or
SSLeay.

The key length of the fixed key length ciphers, of course, cannot be changed
using this or any other option, whatever version of OpenSSL or SSLeay you have,
but here are the key lengths used by those ciphers for reference purposes when
manually creating the key itself if you choose to do so:

    DES      - 8 bytes
    DES_EDE  - 16 bytes
    DES_EDE3 - 24 bytes
    IDEA     - 16 bytes
    DESX     - 24 bytes
    Null     - 0 bytes

=item B<--rc2-key-bits=E<lt>numE<gt>>

Specify the effective key bits value (in bits) if the RC2 cipher was chosen
above.  Valid values are from 1 bit up to 1024 bits.

The default value is 128 bits.

Note that, as for the B<--key-len> option above, this option can only be used to
change the default value if you have OpenSSL 0.9.6 or later.

This option is silently ignored if the RC2 cipher ws not chosen.

=item B<--rc5-rounds=E<lt>numE<gt>>

Specify the number of rounds if the RC5 cipher was chosen above.  Valid values
are either 8, 12 or 16.

The default value is 12 rounds.

Note that, as for the B<--key-len> option above, this option can only be used to
change the default value if you have OpenSSL 0.9.6 or later.

This option is silently ignored if the RC5 cipher was not chosen.

=item B<-i {y|n}>, B<--install-script={y|n}>

Specify whether or not to install the B<crypt_file> script.

The script is installed by default unless the B<--build> option is set to
"Decrypt" (in which case the Filter::Crypto::CryptFile module, which the
B<crypt_file> script uses, does not get built so there would be no point in
installing the script).

=item B<-b E<lt>componentE<gt>>, B<--build=E<lt>componentE<gt>>

Specify which component ("CryptFile", "Decrypt" or "both") to build.  This
determines which of the two C extension modules (Filter::Crypto::CryptFile,
Filter::Crypto::Decrypt or both) gets built.

By default, both components are built.

However, building only one component may be useful if you want to maintain two
separate Perl installations: one containing the Filter::Crypto::CryptFile module
to be used for encrypting your Perl files, and another containing only the
Filter::Crypto::Decrypt module for distributing with your encrypted Perl files
so that they can be run but not easily decrypted.  (Well, not I<very> easily,
anyway.  Please see the L<Filter::Crypto/"WARNING"> regarding the level of
security provided for your source code by this software.)

If you are going to setup two such Perl installations then clearly you will need
to ensure that the components of this distribution installed into each one were
built with the same cipher configuration options, otherwise the files encrypted
by one cannot be decrypted by the other.  The B<--cipher-config> option below
may assist in this.

=item B<-u>, B<--unsafe-mode>

Specify that the "Decrypt" component should be built in an "unsafe" mode in
which the Perl compiler backend modules are allowed to be loaded.

By default, the "Decrypt" component contains a check to try to disallow running
under the Perl compiler backend which works by simply checking whether or not
any of the relevant modules have been loaded.

Unfortunately, that logic can be unhelpful in certain cases where those modules
are quite legitimately loaded.  One example is when code is running in a
mod_perl environment with the Apache::Status module loaded.  Another example is
when a script that uses an encrypted module is being packaged with PAR: the PAR
packager will not pick up any dependencies that the encrypted module has unless
it compiles or executes the module (via B<pp>'s B<-c> or B<-x> options), and the
Perl compiler backend modules are also loaded during that process.

Note that the existence of this B<--unsafe-mode> option should not be taken to
imply that omitting it produces a decryption environment that is entirely
"safe".  Even without the B<--unsafe-mode> option it will still be possible for
some hackers to make use of the Perl compiler backend modules, and there are
also other security issues anyway.  Please see the L<Filter::Crypto/"WARNING">
for more details.

=item B<--debug-mode>

Specify that the modules should be built in "debug" mode.  In this mode, all of
the checks described in the L<Filter::Crypto/"WARNING"> are disabled and lots of
output is written to C<STDERR> describing what is going on during the encryption
or decryption.

By default, the modules are not built in "debug" mode.

=item B<-v>, B<--version>

Display the script name and version, and then exit.

=item B<-h>, B<--help> | B<--?>

Display a help page listing the arguments and options, and then exit.

=item B<--manpage> | B<--doc>

Display the entire manual page, and then exit.

=back

Options may be introduced with a double dash, a single dash, a plus sign or
(on Win32) a forward slash; case does not matter; an equals sign may be used or
omitted between option names and values; long option names may be abbreviated to
uniqueness.

Options may also be placed between non-option arguments, and option processing
may be stopped at any point in the command-line by inserting a double dash.

=head1 EXIT STATUS

    0   The script exited normally.

    1   The script exited after printing the version, help or manpage.

    2   Invalid command-line arguments.

    >2  An error occurred.

=head1 DIAGNOSTICS

=head2 Warnings and Error Messages

The following diagnostic messages may be produced by this script.  They are
classified as follows (a la L<perldiag>):

    (W) A warning (optional).
    (F) A fatal error (trappable).
    (I) An internal error that you should never see (trappable).

=over 4

=item Can't load %s module for random number generation

(F) The specified module could not be loaded and therefore could not be used
as the random number generator (RNG).  Make sure that the module concerned is
properly installed or use one of the other RNG's instead.

=item Compiler not found: please see INSTALL file for details

(F) The compiler that was used to build Perl, which can be seen by running the
command:

    perl -V:cc

could not be found and therefore could not be used to build this module.

=item Compiler not specified: please see INSTALL file for details

(F) The compiler that was used to build Perl, which can normally be seen by
running the command:

    perl -V:cc

was not specified in the standard library module Config and therefore could not
be used to build this module.

=item Could not copy configuration file '%s' to '%s': %s

(F) The specified configuration file (i.e. the file given by the
B<--cipher-config> option) could not be copied to the specified location (from
which it is included in this distribution's build process).  The system error
message corresponding to the standard C library C<errno> variable is also given.

=item Could not generate %d random bytes (%d): %s

(F) The specified number of random bytes (to be used as the password or key)
could not be generated using the OpenSSL binary executable.  The exit code and
the output from the program are also given.

=item Could not get %s version information (%d): %s

(F) The OpenSSL or SSLeay version information could not be got from the binary
executable.  The exit code and the output from the program are also given.

=item Could not open configuration file '%s' for writing: %s

(F) The specified configuration file could not be opened to write the chosen
cipher configuration options to.  The system error message corresponding to the
standard C library C<errno> variable is also given.

=item Could not open random bytes output file '%s' for reading: %s

(F) The specified file containing the random bytes generated by the OpenSSL
binary executable for use as the password or key could not be opened to read the
bytes from.  The system error message corresponding to the standard C library
C<errno> variable is also given.

=item Could not open version number header file '%s' for reading: %s

(F) The specified OpenSSL or SSLeay header file could not be opened to read the
package's version number from.  The system error message corresponding to the
standard C library C<errno> variable is also given.

=item Could not read random bytes from output file '%s': %s

(F) The random bytes generated by the OpenSSL binary executable for use as the
password or key could not be read from the specified file.  The system error
message corresponding to the standard C library C<errno> variable is also given.

=item Could not read random bytes from output file '%s': %d bytes read, %d bytes
expected

(F) The string of random bytes generated by the OpenSSL binary executable for
use as the password or key and read from the specified file was not of the
expected length.

=item Invalid 'build' option value '%s'

(F) The specified build option value (i.e. the value given by the B<--build>
option) is not valid.

=item Invalid default response '%s'

(I) The method called internally to prompt the user for some input was passed a
default response that was not valid itself.

=item Invalid 'install_script' option value '%s'

(I) The method called internally to determine whether or not to install the
B<crypt_file> script was passed an option value that it did not recognize.

=item Invalid key '%s'

(F) The specified key (i.e. the key given by the B<--key> option) is not valid.

=item Invalid key length '%d'

(F) The specified key length (i.e. the length given by the B<--key-length>
option) is not valid.

=item Invalid length key (%d)

(F) The inferred key length (i.e. the length inferred from the key given by the
B<--key> option) is not valid.

=item Invalid password '%s'

(F) The specified password (i.e. the password given by the B<--pswd> option) is
not valid.

=item Invalid random number generator '%s'

(F) The specified random number generator (i.e. the value given by the B<--rng>
option) is not valid.

=item Invalid RC2 key bits '%d'

(F) The specified RC2 key bits value (i.e. the value given by the
B<--rc2-key-bits> option) is not valid.

=item Invalid RC5 rounds '%d'

(F) The specified RC5 rounds value (i.e. the value given by the B<--rc5-rounds>
option) is not valid.

=item Invalid response

(W) The response supplied by the user to an interactive prompt was not valid.
The user will be prompted again until a valid response is supplied.

=item No binary executable found

(F) The main OpenSSL or SSLeay binary executable could not be located.  Ensure
that there is a full installation of OpenSSL or SSLeay in the location specified
by the prefix directory.

=item No crypto library found

(F) The OpenSSL or SSLeay "crypto" library could not be located.  Ensure that
there is a full installation of OpenSSL or SSLeay in the location specified by
the prefix directory.

=item No include directory found

(F) The OpenSSL or SSLeay include directory could not be located.  Ensure that
there is a full installation of OpenSSL or SSLeay in the location specified by
the prefix directory.

=item No such cipher mode '%s'

(F) The specified cipher mode (i.e. the mode given by the B<--cipher-mode>
option) is not recognized.

=item No such cipher name '%s'

(F) The specified cipher name (i.e. the name given by the B<--cipher-name>
option) is not recognized.

=item No such configuration file '%s'

(F) The specified configuration file (i.e. the file given by the
B<--cipher-config> option) does not exist.

=item No such directory

(W) The response supplied by the user to an interactive prompt for a directory
was not a valid directory.  The user will be prompted again until a valid
directory is supplied.

=item No such prefix directory '%s'

(F) The specified prefix directory (i.e. the directory given by the
B<--prefix-dir> option) does not exist.

=item No version number found

(F) The OpenSSL or SSLeay package's version number could not be found in the
relevant header file.

=item No version number header file found

(F) The OpenSSL or SSLeay header file containing the package's version number
could not be located.  Ensure that there is a full installation of OpenSSL or
SSLeay in the location specified by the prefix directory.

=item Options in list are not unique

(I) The method called internally to prompt the user for a choice from a list of
supposedly unique options was passed a list of options that were not all unique.

=item Unknown key source '%s'

(I) The method called internally to prompt the user for a choice of how to
specify the cipher key returned an unknown value.

=item Unknown random number generator '%s'

(I) The method called internally to prompt the user for a choice random number
generator returned an unknown value.

=item Unrecognized version number found (%s)

(F) The OpenSSL or SSLeay package's version number, read from the relevant
header file, is not in a format that is recognized.

=item Warning: %s ignored: requires ExtUtils::MakeMaker version 5.48_01 or later

(W) You either specified the B<--defaults> command-line option or you have the
PERL_MM_USE_DEFAULT environment variable set to a true value, but you do not
have ExtUtils::MakeMaker version 5.48_01 or later, without which these options
have no effect.  The user will therefore be prompted for responses as usual
instead.

=item Wrong compiler version ('%s'; Perl was built with version '%s'): please
      see INSTALL file for details

(F) A different version of the compiler that was used to build Perl is being
used to build this module.  This is not allowed since it is known to cause
breakages with some combinations of compilers.  Please use the same compiler to
build this module as was used to build Perl itself.

=back

=head1 EXAMPLES

=over 4

=item [UNIX] You have installed OpenSSL in F</usr/local>

Type

    perl Makefile.PL -d /usr/local

The OpenSSL include and library directories F</usr/local/include> and
F</usr/local/lib> respectively will be used.  The user will be prompted for the
answers to other configuration questions.

=item [Win32] You have built OpenSSL in F<C:\Temp\openssl-0.9.7e>

Type

    perl Makefile.PL -d C:\Temp\openssl-0.9.7e

The OpenSSL include and library directories F<C:\Temp\openssl-0.9.7e\inc32> and
F<C:\Temp\openssl-0.9.7e\out32dll> respectively will be used: these are detected
automatically in the absence of F<include\> and F<lib\> sub-directories on
"native" Windows platforms.  The user will be prompted for the answers to other
configuration questions.

=item You want to run B<Makefile.PL> non-interactively

If you are happy with the default values of each option then just type

    perl Makefile.PL --defaults

If you want to override the default value of one or more options but accept the
default values for the rest then you can do so, e.g.

    perl Makefile.PL --defaults -n DES

This will use the DES cipher instead of the default AES (or DES_EDE3) cipher,
but is otherwise a default configuration with no questions asked.

Note that this style of accepting all default values except for specifically
overriden ones applies equally well to the prefix directory option, so creating
a default configuration with a non-standard OpenSSL installation location can be
easily handled, e.g.

    perl Makefile.PL --defaults -d /usr/local

Alternatively, you can explicitly provide values for every option that would
otherwise cause an interactive prompt to be given, e.g.

    perl Makefile.PL -b both -n AES -m CBC -l 32 -p rand -r openssl -i y

This will use the AES cipher in CBC mode with a 32-byte key derived from a
password randomly generated by B<openssl>; the B<crypt_file> script will be
installed.  If the OpenSSL or SSLeay prefix directory is not in one of the
locations in which it can be found automatically by B<Makefile.PL> then use the
B<-d> option as shown in the previous examples too.

=back

=head1 ENVIRONMENT

Any standard ExtUtils::AutoInstall and ExtUtils::MakeMaker environment variables
may be used, namely:

=over 4

=item PERL_EXTUTILS_AUTOINSTALL

Specify ExtUtils::AutoInstall command-line options to be postpended to the list
of command-line options before its option processing takes place.

=item PERL_MM_OPT

Specify ExtUtils::MakeMaker command-line arguments to be prepended to the list
of command-line arguments before its argument processing takes place. 

Note that as far as quoting and escaping is concerned, the environment variable
value is not interpreted in the same way as the Bourne shell would interpret the
corresponding command-line.  Instead, it is simply split on whitespace before
being processed.

Also bear in mind the caveat regarding the use of ExtUtils::MakeMaker command-
line arguments under L<"ARGUMENTS"> above.

=item PERL_MM_USE_DEFAULT

If set to a true value, then the default value (indicated under L<"OPTIONS">
above) of each option that is not specified on the command-line will be used
instead of prompting the user for a response.

You must be using ExtUtils::MakeMaker version 5.48_01 or later for this option
to have any effect.

=back

=head1 SEE ALSO

The F<INSTALL> file;

L<ExtUtils::AutoInstall>;

L<ExtUtils::MakeMaker>.

=head1 ACKNOWLEDGEMENTS

The C<MY::test()> override method is based on code taken from that in the
top-level B<Makefile.PL> script in the Tk distribution (version 804.027),
written by Nick Ing-Simmons.

The C<check_compiler()> method in the Module::Install::PRIVATE module used by
this script is based on code taken from the C<get_avail_w32compilers()> function
in the B<configsmoke.pl> script in the Test-Smoke distribution (version 1.19),
written by Abe Timmerman.

The C<_use_default_response()> and C<_isa_tty()> methods in the
Module::Install::PRIVATE module used by this script are based on code taken from
the C<prompt()> function in the standard library module ExtUtils::MakeMaker
(version 6.17), written by Andy Dougherty, Andreas Koenig and Tim Bunce, and
currently maintained by Michael G Schwern.

=head1 AUTHOR

Steve Hay E<lt>shay@cpan.orgE<gt>

=head1 COPYRIGHT

Copyright (C) 2004-2005 Steve Hay.  All rights reserved.

=head1 LICENCE

This script is free software; you can redistribute it and/or modify it under the
same terms as Perl itself, i.e. under the terms of either the GNU General Public
License or the Artistic License, as specified in the F<LICENCE> file.

=head1 VERSION

Version 1.03

=head1 DATE

02 Sep 2005

=head1 HISTORY

See the F<Changes> file.

=cut

#===============================================================================
