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

BOOT:
{
    /* Allocate and initialise the relevant Perl module's $ErrStr variable
     * name. */
    Newz(0, filter_crypto_errstr_var,
         sizeof(FILTER_CRYPTO_PACKAGE_NAME) + sizeof("::ErrStr"), char);
    strcpy(filter_crypto_errstr_var, FILTER_CRYPTO_PACKAGE_NAME);
    strcat(filter_crypto_errstr_var, "::ErrStr");

    /* Load the error strings for all libcrypto functions. */
    ERR_load_crypto_strings();
}

void
END()
    PPCODE:
    {
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
