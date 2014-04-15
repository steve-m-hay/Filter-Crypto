#===============================================================================
#
# CryptoCommon-xs.inc
#
# DESCRIPTION
#   Common XS code for Filter::Crypto modules.
#
# COPYRIGHT
#   Copyright (c) 2004, Steve Hay.  All rights reserved.
#
# LICENCE
#   You may distribute under the terms of either the GNU General Public License
#   or the Artistic License, as specified in the LICENCE file.
#
#===============================================================================

#define FILTER_CRYPTO_ERRSTR_VARIABLE "::ErrStr"

BOOT:
{
    STRLEN package_len;
    char *package = SvPV(ST(0), package_len);
    SV *sv;
    SV *rv;
    HV *stash;

    /* We need to have an indented line here otherwise xsubpp gets confused. */
#ifdef FILTER_CRYPTO_DEBUG
    if (items > 1)
        warn("Initialising %s (Version %.2"NVff")\n", package, SvNV(ST(1)));
    else
        warn("Initialising %s (Unknown version)\n", package);
#endif

    /* Allocate and initialise the relevant Perl module's $ErrStr variable name.
     * Note that the value returned by the sizeof() operator includes the NUL
     * terminator, which we must also include when calling Newz(). */
    Newz(0, filter_crypto_errstr_var,
         package_len + sizeof(FILTER_CRYPTO_ERRSTR_VARIABLE), char);
    strcpy(filter_crypto_errstr_var, package);
    strcat(filter_crypto_errstr_var, FILTER_CRYPTO_ERRSTR_VARIABLE);

    /* Load the error strings for all libcrypto functions. */
    ERR_load_crypto_strings();

    /* Create an object blessed into our invocant class so that we can run some
     * cleanup code when the process exits, namely via the object's destructor.
     * Normally we would use an END subroutine instead of a DESTROY method, but
     * in a mod_perl Apache::Registry setup END subroutines are run at the end
     * of each request (unless the script being filtered was preloaded by
     * the parent server process) which would cause multiple free()'s of memory
     * that was only allocated once (at boot time, by the Newz() above).
     * Thanks to Joost on PerlMonks for this idea. */
    sv = NEWSV(0, 0);
    rv = newRV_noinc(sv);
    if ((stash = gv_stashpvn(package, package_len, 0)) == NULL)
        croak("No such package '%s'", package);
    sv_bless(rv, stash);
}

void
DESTROY(self)
    PROTOTYPE: $

    INPUT:
        SV *self;

    PPCODE:
    {
#ifdef FILTER_CRYPTO_DEBUG
        warn("Destroying %s\n", sv_reftype(SvRV(self), TRUE));
#endif

        /* Free the current thread's error queue and all previously loaded error
         * strings.  ERR_remove_state() was introduced in SSLeay 0.6.1, but
         * seems to crash prior to 0.6.4. */
#if FILTER_CRYPTO_OPENSSL_VERSION >= 60400
        ERR_remove_state(0);
#endif
        ERR_free_strings();

        /* Remove all ciphers and/or digests from the internal lookup table. */
#if FILTER_CRYPTO_OPENSSL_VERSION >= 80000
        EVP_cleanup();
#endif

        /* Free the PRNG state. */
        RAND_cleanup();

        /* Free the relevant Perl module's $ErrStr variable name. */
        Safefree(filter_crypto_errstr_var);
    }

#===============================================================================
