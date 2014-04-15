/*============================================================================
 *
 * CryptoCommon-c.inc
 *
 * DESCRIPTION
 *   Common C code for Filter::Crypto modules.
 *
 * COPYRIGHT
 *   Copyright (C) 2004-2006 Steve Hay.  All rights reserved.
 *
 * LICENCE
 *   You may distribute under the terms of either the GNU General Public License
 *   or the Artistic License, as specified in the LICENCE file.
 *
 *============================================================================*/

/* Uncomment (or build with --debug-mode option) for debugging. */
/* #define FILTER_CRYPTO_DEBUG_MODE /**/

/* Uncomment for fixed (dummy) salt and/or IV for debugging purposes. */
/* #define FILTER_CRYPTO_NO_RAND_BYTES /**/

#include <memory.h>                     /* For memset().                      */
#include <stdarg.h>                     /* For va_list/va_start()/va_end().   */
#include <stdio.h>                      /* For snprintf().                    */
#include <stdlib.h>                     /* For atoi() and RAND_MAX.           */
#include <time.h>                       /* For time().                        */

                                        /* For getpid() and pid_t.            */
#ifdef WIN32
#  include <process.h>
#  ifndef __MINGW32__
     typedef int pid_t;
#  endif
#else
#  include <unistd.h>
#endif

/* The definition of RAND_screen() is only seen if WINDOWS is #define'd, which
 * it is not by default (even on Win32).  The C file containing the definition
 * #include's "e_os.h" first which #define's WINDOWS if it is not aleady
 * #define'd and WIN32 is (which is indeed the case on Win32).  However, the
 * header file declaring RAND_screen() does not include "e_os.h" so the
 * declaration (which, before 0.9.5a, is also only seen if WINDOWS #define'd)
 * does not get seen.  From 0.9.5a onwards the header file declaring
 * RAND_screen() tests if WIN32 is #define'd too so it works OK.  Therefore,
 * ensure WINDOWS is #define'd if WIN32 is so that earlier versions work too. */
#ifdef WIN32
#  ifndef WINDOWS
#    define WINDOWS
#  endif
#endif

/* For the ERR_*(), EVP_*() and RAND_*() functions.
 * The header files were located directly in the OpenSSL include directory prior
 * to 0.9.3, but are now located in an openssl/ sub-directory of that.  The EVP
 * header was called "envelope.h" before 0.8.0, but is now called "evp.h." */
#if FILTER_CRYPTO_OPENSSL_VERSION < 80000
#  include <envelope.h>
#  include <err.h>
#  include <rand.h>
#elif FILTER_CRYPTO_OPENSSL_VERSION < 90300
#  include <err.h>
#  include <evp.h>
#  include <rand.h>
#else
#  include <openssl/err.h>
#  include <openssl/evp.h>
#  include <openssl/rand.h>
#endif

/* Some early versions of OpenSSL and SSLeay define a "_" symbol in the "des.h"
 * header file.  It is apparently not required, so undefine it since it clashes
 * with the "_" symbol defined in Perl's "config.h" header file.              */
#ifdef _
#  undef _
#endif

#define PERL_NO_GET_CONTEXT             /* See the "perlguts" manpage.        */

#include "patchlevel.h"                 /* Get the version numbers first.     */

#if(PERL_REVISION == 5 && PERL_VERSION > 6)
#  define PERLIO_NOT_STDIO 0            /* See the "perlapio" manpage.        */
#endif

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "ppport.h"

#include "CipherConfig.h"               /* For the cipher details.            */

                                        /* RAND_MAX does not exist on SunOS.  */
#ifndef RAND_MAX
#  include <limits.h>
#  if INT_MAX == 32767
#    define RAND_MAX 32767
#  else
#    define RAND_MAX 0x7fffffff
#  endif
#endif

                                        /* snprintf() is an IEEE Std          */
                                        /* 1003.1-2001 extension to the ISO C */
                                        /* standard (ISO/IEC 9899:1999), and  */
                                        /* is called _snprintf() on Win32.    */
#ifdef WIN32
#  define snprintf _snprintf
#endif

                                        /* PKCS5_SALT_LEN and                 */
                                        /* PKCS5_DEFAULT_ITER were added in   */
                                        /* 0.9.4.                             */
#ifndef PKCS5_SALT_LEN
#  define PKCS5_SALT_LEN     8
#endif
#ifndef PKCS5_DEFAULT_ITER
#  define PKCS5_DEFAULT_ITER 2048
#endif

                                        /* EVP_CIPHER_block_size(),           */
                                        /* EVP_CIPHER_CTX_block_size() and    */
                                        /* EVP_CIPHER_iv_length() were all    */
                                        /* added in 0.6.5.                    */
#ifndef EVP_CIPHER_block_size
#  define EVP_CIPHER_block_size(e)     ((e)->block_size)
#endif
#ifndef EVP_CIPHER_CTX_block_size
#  define EVP_CIPHER_CTX_block_size(e) ((e)->cipher->block_size)
#endif
#ifndef EVP_CIPHER_iv_length
#  define EVP_CIPHER_iv_length(e)      ((e)->iv_len)
#endif

                                        /* Poison() was added in Perl 5.8.0.  */
#ifndef Poison
#  define Poison(d, n, t) (void)memset((char*)(d), 0xAB, (n) * sizeof(t))
#endif

#define FILTER_CRYPTO_OPENSSL_ERR_STR \
    (ERR_reason_error_string(FilterCrypto_GetLastSSLError()))

                                        /* Macro to set the CUR length in an  */
                                        /* SV whose string space has been     */
                                        /* manipulated directly.  Also adds a */
                                        /* NUL terminator in case the string  */
                                        /* gets used as a C "string" later.   */
#define FilterCrypto_SvSetCUR(sv, len) STMT_START { \
    SvCUR_set(sv, len); SvPVX(sv)[len] = '\0'; \
} STMT_END

#define FILTER_CRYPTO_NEED_RANDOM_SALT FILTER_CRYPTO_USING_PBE
#define FILTER_CRYPTO_NEED_RANDOM_IV   FILTER_CRYPTO_NEED_IV   &&            \
                                     !(FILTER_CRYPTO_USING_PBE &&            \
                                       FILTER_CRYPTO_OPENSSL_VERSION < 90400)

typedef enum {
    FILTER_CRYPTO_MODE_DECRYPT = 0,
    FILTER_CRYPTO_MODE_ENCRYPT
} FILTER_CRYPTO_MODE;

typedef struct {
    EVP_CIPHER_CTX *cipher_ctx;
    SV *salt_sv;
    int required_salt_len;
    SV *iv_sv;
    int required_iv_len;
    FILTER_CRYPTO_MODE crypt_mode;
    bool cipher_initialized;
} FILTER_CRYPTO_CCTX;

static FILTER_CRYPTO_CCTX *FilterCrypto_CryptoAlloc(pTHX);
static bool FilterCrypto_CryptoInit(pTHX_ FILTER_CRYPTO_CCTX *ctx,
    FILTER_CRYPTO_MODE crypt_mode);
static bool FilterCrypto_CryptoInitCipher(pTHX_ FILTER_CRYPTO_CCTX *ctx,
    SV *in_sv, SV *out_sv);
static bool FilterCrypto_CryptoUpdate(pTHX_ FILTER_CRYPTO_CCTX *ctx, SV *in_sv,
    SV *out_sv);
static bool FilterCrypto_CryptoFinal(pTHX_ FILTER_CRYPTO_CCTX *ctx, SV *out_sv);
static void FilterCrypto_CryptoFree(pTHX_ FILTER_CRYPTO_CCTX *ctx);
static bool FilterCrypto_CipherInit(pTHX_ EVP_CIPHER_CTX *ctx, SV *salt_sv,
    SV *iv_sv, FILTER_CRYPTO_MODE crypt_mode);
static bool FilterCrypto_CipherUpdate(pTHX_ EVP_CIPHER_CTX *ctx, SV *in_sv,
    SV *out_sv);
static bool FilterCrypto_CipherFinal(pTHX_ EVP_CIPHER_CTX *ctx, SV *out_sv);
static bool FilterCrypto_PRNGInit(pTHX);
static int FilterCrypto_GetRandNum(pTHX_ int min, int max);
static unsigned long FilterCrypto_GetLastSSLError(void);
static void FilterCrypto_SetErrStr(pTHX_ const char *value, ...);
#ifdef FILTER_CRYPTO_DEBUG_MODE
static void FilterCrypto_vHexDump(pTHX_ const unsigned char *data,
    unsigned int len, const char *title, va_list args);
static void FilterCrypto_HexDump(pTHX_ const unsigned char *data,
    unsigned int len, const char *title, ...);
static void FilterCrypto_HexDumpSV(pTHX_ const SV *sv, const char *title, ...);
#endif

/* Fully-qualified name of the relevant Perl module's $ErrStr variable.  This is
 * set at boot time from the (hard-coded) unqualified name and the package name
 * #define'd in the individual XS files and is not subsequently changed, so is
 * virtually a "const" and is therefore thread-safe. */
static char *filter_crypto_errstr_var = NULL;

/*
 * Function to allocate a new crypto context.
 * Returns a pointer to the allocated structure.
 */

static FILTER_CRYPTO_CCTX *FilterCrypto_CryptoAlloc(pTHX) {
    FILTER_CRYPTO_CCTX *ctx;

    /* Allocate the new crypto context. */
    Newxz(ctx, 1, FILTER_CRYPTO_CCTX);

    /* Allocate the cipher context. */
    Newxz(ctx->cipher_ctx, 1, EVP_CIPHER_CTX);

    /* Allocate a pair of SV's with enough string space to hold a salt and an
     * initialization vector (IV) respectively, and store their required
     * lengths.  Mark each one as being a string only. */
#if FILTER_CRYPTO_NEED_RANDOM_SALT
    ctx->salt_sv = newSV(PKCS5_SALT_LEN);
    SvPOK_only(ctx->salt_sv);
    ctx->required_salt_len = PKCS5_SALT_LEN;
#endif

#if FILTER_CRYPTO_NEED_RANDOM_IV
    ctx->iv_sv = newSV(EVP_CIPHER_iv_length(FILTER_CRYPTO_CIPHER_FUNC));
    SvPOK_only(ctx->iv_sv);
    ctx->required_iv_len = EVP_CIPHER_iv_length(FILTER_CRYPTO_CIPHER_FUNC);
#endif

    return ctx;
}

/*
 * Function to initialize the given crypto context in the given mode.
 * Returns a bool to indicate success or failure.
 */

static bool FilterCrypto_CryptoInit(pTHX_ FILTER_CRYPTO_CCTX *ctx,
    FILTER_CRYPTO_MODE crypt_mode)
{
    /* The cipher context gets initialized later (by
     * FilterCrypto_CryptoInitCipher(), called from FilterCrypto_CryptoUpdate())
     * rather than now because we do not necessarily have all the required
     * information to do it now. */

    /* Initialize the salt and IV. */
#if FILTER_CRYPTO_NEED_RANDOM_SALT
    FilterCrypto_SvSetCUR(ctx->salt_sv, 0);
#else
    ctx->salt_sv = Nullsv;
#endif
#if FILTER_CRYPTO_NEED_RANDOM_IV
    FilterCrypto_SvSetCUR(ctx->iv_sv,   0);
#else
    ctx->iv_sv = Nullsv;
#endif

    /* Initialize the crypt mode and cipher context initialization status. */
    ctx->crypt_mode         = crypt_mode;
    ctx->cipher_initialized = FALSE;

    /* Clear the current thread's OpenSSL/SSLeay error queue. */
    ERR_clear_error();

    /* Clear our own last error message. */
    FilterCrypto_SetErrStr(aTHX_ "");
    return TRUE;
}

/*
 * Function to initialize the cipher context within the given crypto context.
 * This is called automatically from FilterCrypto_CryptoUpdate() since when
 * decrypting, a salt and/or an IV may need to be recovered from the given input
 * SV that is passed to FilterCrypto_CryptoUpdate().  In that case, the salt
 * and/or IV will be removed from the start of the input SV, leaving any further
 * data in place for FilterCrypto_CryptoUpdate() to process afterwards.  When
 * encrypting, it may be necessary to have a salt and/or IV randomly generated.
 * In that case, they will be written to the start of the given output SV, which
 * will be grown accordingly to accomodate them as well as the output data that
 * it should already be large enough for.
 * Returns a bool to indicate success or failure.
 */

static bool FilterCrypto_CryptoInitCipher(pTHX_ FILTER_CRYPTO_CCTX *ctx,
    SV *in_sv, SV *out_sv)
{
    /* If we're using password-based encryption (PBE) then a salt is required
     * for the key derivation.  It must be randomly generated when encrypting,
     * and output with the encrypted data so that it can be read back in and
     * used again for decrypting.  We also need an IV, which must be handled in
     * the same way, except that the old key derivation algorithm used by
     * FilterCrypto_CipherInit() before 0.9.4 generates an IV for us. */
#if(FILTER_CRYPTO_NEED_RANDOM_SALT || FILTER_CRYPTO_NEED_RANDOM_IV)
    switch (ctx->crypt_mode) {
        case FILTER_CRYPTO_MODE_ENCRYPT: {
#  if FILTER_CRYPTO_NEED_RANDOM_SALT
            unsigned char *salt_text = (unsigned char *)SvPVX(ctx->salt_sv);
#  endif
#  if FILTER_CRYPTO_NEED_RANDOM_IV
            unsigned char *iv_text   = (unsigned char *)SvPVX(ctx->iv_sv);
#  endif

            /* Ensure the pseudo-random number generator (PRNG) is seeded. */
            if (!FilterCrypto_PRNGInit(aTHX))
                return FALSE;

#  if FILTER_CRYPTO_NEED_RANDOM_SALT
#    if defined(FILTER_CRYPTO_NO_RAND_BYTES)
            memset(salt_text, '*', ctx->required_salt_len);
#    elif FILTER_CRYPTO_OPENSSL_VERSION < 90500
            RAND_bytes(salt_text, ctx->required_salt_len);
#    else
            if (!RAND_bytes(salt_text, ctx->required_salt_len)) {
                if (!RAND_pseudo_bytes(salt_text, ctx->required_salt_len)) {
                    FilterCrypto_SetErrStr(aTHX_
                        "Can't generate %d-byte random salt: %s",
                        ctx->required_salt_len, FILTER_CRYPTO_OPENSSL_ERR_STR
                    );
                    return FALSE;
                }
                warn("Random salt may not be cryptographically strong");
            }
#    endif
            FilterCrypto_SvSetCUR(ctx->salt_sv, ctx->required_salt_len);

            /* Grow the output SV's buffer enough to hold the salt as well as
             * the output data that it should already be large enough for. */
            SvGROW(out_sv, SvLEN(out_sv) + ctx->required_salt_len);

            sv_catpvn(out_sv, salt_text, ctx->required_salt_len);

#    ifdef FILTER_CRYPTO_DEBUG_MODE
            FilterCrypto_HexDump(aTHX_ salt_text, ctx->required_salt_len,
                "Generated %d-byte salt", ctx->required_salt_len
            );
#    endif
#  endif

#  if FILTER_CRYPTO_NEED_RANDOM_IV
#    if defined(FILTER_CRYPTO_NO_RAND_BYTES)
            memset(iv_text, '*', ctx->required_iv_len);
#    elif FILTER_CRYPTO_OPENSSL_VERSION < 90500
            RAND_bytes(iv_text, ctx->required_iv_len);
#    else
            if (!RAND_bytes(iv_text, ctx->required_iv_len)) {
                if (!RAND_pseudo_bytes(iv_text, ctx->required_iv_len)) {
                    FilterCrypto_SetErrStr(aTHX_
                        "Can't generate %d-byte random IV: %s",
                        ctx->required_iv_len, FILTER_CRYPTO_OPENSSL_ERR_STR
                    );
                    return FALSE;
                }
                warn("Random IV may not be cryptographically strong");
            }
#    endif
            FilterCrypto_SvSetCUR(ctx->iv_sv, ctx->required_iv_len);

            /* Grow the output SV's buffer enough to hold the IV as well as the
             * output data that it should already be large enough for. */
            SvGROW(out_sv, SvLEN(out_sv) + ctx->required_iv_len);

            sv_catpvn(out_sv, iv_text, ctx->required_iv_len);

#    ifdef FILTER_CRYPTO_DEBUG_MODE
            FilterCrypto_HexDump(aTHX_ iv_text, ctx->required_iv_len,
                "Generated %d-byte IV", ctx->required_iv_len
            );
#    endif
#  endif

            break;
        }

        case FILTER_CRYPTO_MODE_DECRYPT: {
#  if FILTER_CRYPTO_NEED_RANDOM_SALT
            int missing_salt_len;
#  endif
#  if FILTER_CRYPTO_NEED_RANDOM_IV
            int missing_iv_len;
#  endif
            int in_len;
            unsigned char *in_text;

#  if FILTER_CRYPTO_NEED_RANDOM_SALT
            missing_salt_len = ctx->required_salt_len - SvCUR(ctx->salt_sv);
            if (missing_salt_len > 0) {
                in_len = SvCUR(in_sv);
                in_text = (unsigned char *)SvPVX(in_sv);
                if (missing_salt_len <= in_len) {
                    sv_catpvn(ctx->salt_sv, in_text, missing_salt_len);
                    sv_chop(in_sv, in_text + missing_salt_len);
                }
                else {
                    sv_catpvn(ctx->salt_sv, in_text, in_len);
                    FilterCrypto_SvSetCUR(in_sv, 0);

                    /* We have not fully populated the salt yet so just return
                     * success for now.  We'll be called again later. */
                    return TRUE;
                }

#    ifdef FILTER_CRYPTO_DEBUG_MODE
                FilterCrypto_HexDumpSV(aTHX_ ctx->salt_sv,
                    "Recovered %d-byte salt", SvCUR(ctx->salt_sv)
                );
#    endif
            }
#  endif

#  if FILTER_CRYPTO_NEED_RANDOM_IV
            missing_iv_len = ctx->required_iv_len - SvCUR(ctx->iv_sv);
            if (missing_iv_len > 0) {
                in_len = SvCUR(in_sv);
                in_text = (unsigned char *)SvPVX(in_sv);
                if (missing_iv_len <= in_len) {
                    sv_catpvn(ctx->iv_sv, in_text, missing_iv_len);
                    sv_chop(in_sv, in_text + missing_iv_len);
                }
                else {
                    sv_catpvn(ctx->iv_sv, in_text, in_len);
                    FilterCrypto_SvSetCUR(in_sv, 0);

                    /* We have not fully populated the IV yet so just return
                     * success for now.  We'll be called again later. */
                    return TRUE;
                }

#    ifdef FILTER_CRYPTO_DEBUG_MODE
                FilterCrypto_HexDumpSV(aTHX_ ctx->iv_sv,
                    "Recovered %d-byte IV", SvCUR(ctx->iv_sv)
                );
#    endif
            }
#  endif

            /* Make sure the in_sv's OOK flag is turned off in case it was set
             * by the use of sv_chop() above.  This copies any bytes remaining
             * in in_sv's PV slot to the start of that slot so that they are
             * still available for FilterCrypto_CryptoUpdate(). */
            SvOOK_off(in_sv);

            break;
        }

        default:
            croak("Unknown crypto context mode '%d'", ctx->crypt_mode);
    }
#endif

    if (!FilterCrypto_CipherInit(aTHX_ ctx->cipher_ctx, ctx->salt_sv,
            ctx->iv_sv, ctx->crypt_mode))
        return FALSE;

    ctx->cipher_initialized = TRUE;

    return TRUE;
}

/*
 * Function to update the given crypto context with data in the given input SV.
 * This data is not assumed to be null-terminated, so the correct length must be
 * set in SvCUR(in_sv).  Likewise for the data written into the output SV:
 * SvCUR(out_sv) will be set correctly by this function.
 * Returns a bool to indicate success or failure.
 */

static bool FilterCrypto_CryptoUpdate(pTHX_ FILTER_CRYPTO_CCTX *ctx, SV *in_sv,
    SV *out_sv)
{
    /* If the cipher context is not yet initialized then use the data in the
     * input SV to initialize it now. */
    if (!ctx->cipher_initialized) {
        if (!FilterCrypto_CryptoInitCipher(aTHX_ ctx, in_sv, out_sv))
            return FALSE;
    }

    /* If there is any data left in the input SV after the above initialization
     * has potentially been run then use it to update the cipher context.
     * Otherwise just return success. */
    if (SvCUR(in_sv))
        return FilterCrypto_CipherUpdate(aTHX_ ctx->cipher_ctx, in_sv, out_sv);
    else
        return TRUE;
}

/*
 * Function to finalize the given crypto context.  The data written into the
 * output SV is not assumed to be null-terminated, so SvCUR(out_sv) will be set
 * correctly by this function.
 * Returns a bool to indicate success or failure.
 */

static bool FilterCrypto_CryptoFinal(pTHX_ FILTER_CRYPTO_CCTX *ctx, SV *out_sv)
{
    return FilterCrypto_CipherFinal(aTHX_ ctx->cipher_ctx, out_sv);
}

/*
 * Function to free the given crypto context.
 */

static void FilterCrypto_CryptoFree(pTHX_ FILTER_CRYPTO_CCTX *ctx) {
    /* Free the IV and salt by decrementing their reference counts (to zero). */
#if FILTER_CRYPTO_NEED_RANDOM_IV
    SvREFCNT_dec(ctx->iv_sv);
#endif
#if FILTER_CRYPTO_NEED_RANDOM_SALT
    SvREFCNT_dec(ctx->salt_sv);
#endif

    /* Free the cipher context. */
    Safefree(ctx->cipher_ctx);

    /* Free the crypto context. */
    Safefree(ctx);
}

/*
 * Function to initialize the given cipher context in the given mode using the
 * given salt and/or IV if necessary.
 * Returns a bool to indicate success or failure.
 */

static bool FilterCrypto_CipherInit(pTHX_ EVP_CIPHER_CTX *ctx, SV *salt_sv,
    SV *iv_sv, FILTER_CRYPTO_MODE crypt_mode)
{
#if FILTER_CRYPTO_OPENSSL_VERSION < 90300
    EVP_CIPHER *cipher_func = FILTER_CRYPTO_CIPHER_FUNC;
#else
    const EVP_CIPHER *cipher_func = FILTER_CRYPTO_CIPHER_FUNC;
#endif
#if FILTER_CRYPTO_KEY_LEN == 0
    unsigned char *key = NULL;
#else
    unsigned char key[FILTER_CRYPTO_KEY_LEN];
#endif
#if FILTER_CRYPTO_NEED_RANDOM_SALT
    unsigned char *salt = (unsigned char *)SvPVX(salt_sv);
#  if FILTER_CRYPTO_OPENSSL_VERSION >= 90400
    int salt_len = SvCUR(salt_sv);
#  endif
#endif
#if FILTER_CRYPTO_NEED_RANDOM_IV
    unsigned char *iv = (unsigned char *)SvPVX(iv_sv);
#else
    unsigned char *iv = NULL;
#endif
#if(FILTER_CRYPTO_USING_PBE                && \
    FILTER_CRYPTO_OPENSSL_VERSION  < 90400 && \
    FILTER_CRYPTO_OPENSSL_VERSION >= 90000)
    int derived_key_len;
#endif

    /* Derive the key from the given password.  PBE should really be initialized
     * with PKCS5_pbe2_set() and EVP_PBE_CipherInit().  The former generates a
     * random IV, while the latter derives a key from the given password by a
     * PKCS#5 v2.0 key derivation algorithm (via PKCS5_v2_PBE_keyivgen() and
     * ultimately PKCS5_PBKDF2_HMAC_SHA1()).  There is currently (as of 0.9.7e)
     * a problem with PKCS5_pbe2_set() in that the IV cannot be user-specified,
     * but this could be overcome by DER-encoding the X509_ALGOR structure
     * returned by it and writing/reading this when encrypting/decrypting as we
     * currently do with the salt and/or IV.  However, there is another problem,
     * with PKCS5_v2_PBE_keyivgen(), which cannot be overcome so easily: it only
     * works with the default key length of the given cipher, so we would lose
     * the ability to set the key length differently for those algorithms with
     * variable key lengths.  There are also problems using EVP_PBE_CipherInit()
     * at all with some ciphers because it relies on the ASN1 code, which, as
     * the "BUGS" section of the EVP_EncryptInit.pod in recent OpenSSL
     * distributions says, is incomplete and sometimes inaccurate.  Therefore,
     * we use the standard EVP_CipherInit[_ex]() functions, and call
     * PKCS5_PBKDF2_HMAC_SHA1() directly ourselves to do the PKCS#5 v2.0 key
     * derivation.
     * See the exchanges between myself and Steve Henson on the "openssl-users"
     * mailing list, 08-13 Sep 2004, for more details on all of this.
     * One final fly in the ointment is that PKCS5_PBKDF2_HMAC_SHA1() is only
     * available as of 0.9.4, so before that we use EVP_BytesToKey() instead.
     * This is at best PKCS#5 v1.5 compatible and also does not support non-
     * default key lengths for variable key length ciphers.  In this case,
     * however, the latter is not an issue because the EVP library only has
     * facilities for changing the key lengths from 0.9.6 onwards anyway. */

#if FILTER_CRYPTO_OPENSSL_VERSION < 90400

#  if FILTER_CRYPTO_USING_PBE
    Newxz(iv, EVP_CIPHER_iv_length(cipher_func), unsigned char);

    /* Do not check the return value of EVP_BytesToKey() before 0.9.0: it was
     * faulty. */
#    if FILTER_CRYPTO_OPENSSL_VERSION < 90000
    EVP_BytesToKey(cipher_func, EVP_md5(), salt, filter_crypto_pswd,
        sizeof(filter_crypto_pswd), PKCS5_DEFAULT_ITER, key, iv);
#    else
    if ((derived_key_len = EVP_BytesToKey(cipher_func, EVP_md5(), salt,
            filter_crypto_pswd, sizeof(filter_crypto_pswd), PKCS5_DEFAULT_ITER,
            key, iv)) != FILTER_CRYPTO_KEY_LEN)
    {
        Safefree(iv);
        FilterCrypto_SetErrStr(aTHX_
            "Derived key length is wrong (%d, expected %d)",
            derived_key_len, FILTER_CRYPTO_KEY_LEN
        );
        return FALSE;
    }
#    endif
#  else
    Copy(filter_crypto_key, key, FILTER_CRYPTO_KEY_LEN, unsigned char);
#  endif

    EVP_CipherInit(ctx, cipher_func, key, iv, crypt_mode);

#  if FILTER_CRYPTO_USING_PBE
    Safefree(iv);
#  endif

#elif FILTER_CRYPTO_OPENSSL_VERSION < 90600

#  if FILTER_CRYPTO_USING_PBE
    if (PKCS5_PBKDF2_HMAC_SHA1(filter_crypto_pswd, sizeof(filter_crypto_pswd),
            salt, salt_len, PKCS5_DEFAULT_ITER, FILTER_CRYPTO_KEY_LEN, key) !=
            1)
    {
        FilterCrypto_SetErrStr(aTHX_
            "Can't derive %d-byte key: %s",
            FILTER_CRYPTO_KEY_LEN, FILTER_CRYPTO_OPENSSL_ERR_STR
        );
        return FALSE;
    }
#  else
    Copy(filter_crypto_key, key, FILTER_CRYPTO_KEY_LEN, unsigned char);
#  endif

    EVP_CipherInit(ctx, cipher_func, key, iv, crypt_mode);

#else

    /* From 0.9.6 onwards the EVP library API does have facilities for modifying
     * the key length for variable key length ciphers and for modifying other
     * cipher parameters, so to start with we just specify which cipher we are
     * using.  Then we can set the key length and other parameters in the cipher
     * context structure thus created, and then finally derive the key and set
     * both it and the IV in the cipher context structure. */
#  if FILTER_CRYPTO_OPENSSL_VERSION < 90700
    if (!EVP_CipherInit(ctx, cipher_func, NULL, NULL, crypt_mode)) {
        FilterCrypto_SetErrStr(aTHX_
            "Can't initialize cipher context in crypt mode '%d': %s",
            crypt_mode, FILTER_CRYPTO_OPENSSL_ERR_STR
        );
        return FALSE;
    }
#  else
    EVP_CIPHER_CTX_init(ctx);

    if (!EVP_CipherInit_ex(ctx, cipher_func, NULL, NULL, NULL, crypt_mode)) {
        FilterCrypto_SetErrStr(aTHX_
            "Can't initialize cipher context in crypt mode '%d': %s",
            crypt_mode, FILTER_CRYPTO_OPENSSL_ERR_STR
        );
        return FALSE;
    }
#  endif

    /* Now we can modify the parameters for the chosen cipher.  First, set the
     * key length. */
    if (!EVP_CIPHER_CTX_set_key_length(ctx, FILTER_CRYPTO_KEY_LEN)) {
        FilterCrypto_SetErrStr(aTHX_
            "Can't set key length to %d: %s",
            FILTER_CRYPTO_KEY_LEN, FILTER_CRYPTO_OPENSSL_ERR_STR
        );
        return FALSE;
    }

    /* Now modify any other cipher-specific parameters that we have. */
#  if defined(FILTER_CRYPTO_RC2_KEY_BITS)
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_SET_RC2_KEY_BITS,
            FILTER_CRYPTO_RC2_KEY_BITS, NULL))
    {
        FilterCrypto_SetErrStr(aTHX_
            "Can't set RC2 effective key bits to %d: %s",
            FILTER_CRYPTO_RC2_KEY_BITS, FILTER_CRYPTO_OPENSSL_ERR_STR
        );
        return FALSE;
    }
#  elif defined(FILTER_CRYPTO_RC5_ROUNDS)
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_SET_RC5_ROUNDS,
            FILTER_CRYPTO_RC5_ROUNDS, NULL))
    {
        FilterCrypto_SetErrStr(aTHX_
            "Can't set RC5 number of rounds to %d: %s",
            FILTER_CRYPTO_RC5_ROUNDS, FILTER_CRYPTO_OPENSSL_ERR_STR
        );
        return FALSE;
    }
#  endif

    /* We have finished modifying the cipher parameters, so we can now
     * finish the initialization of the cipher context by deriving the key
     * and setting both it and the IV. */
#  if FILTER_CRYPTO_USING_PBE
    if (PKCS5_PBKDF2_HMAC_SHA1(filter_crypto_pswd, sizeof(filter_crypto_pswd),
            salt, salt_len, PKCS5_DEFAULT_ITER, FILTER_CRYPTO_KEY_LEN, key) !=
            1)
    {
        FilterCrypto_SetErrStr(aTHX_
            "Can't derive %d-byte key: %s",
            FILTER_CRYPTO_KEY_LEN, FILTER_CRYPTO_OPENSSL_ERR_STR
        );
        return FALSE;
    }
#  else
    Copy(filter_crypto_key, key, FILTER_CRYPTO_KEY_LEN, unsigned char);
#  endif

#  if FILTER_CRYPTO_OPENSSL_VERSION < 90700
    if (!EVP_CipherInit(ctx, NULL, key, iv, crypt_mode)) {
        FilterCrypto_SetErrStr(aTHX_
            "Can't initialize cipher context in crypt mode '%d' using %d-byte "
            "key: %s",
            crypt_mode, FILTER_CRYPTO_KEY_LEN, FILTER_CRYPTO_OPENSSL_ERR_STR
        );
        return FALSE;
    }
#  else
    if (!EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, crypt_mode)) {
        FilterCrypto_SetErrStr(aTHX_
            "Can't initialize cipher context in crypt mode '%d' using %d-byte "
            "key: %s",
            crypt_mode, FILTER_CRYPTO_KEY_LEN, FILTER_CRYPTO_OPENSSL_ERR_STR
        );
        return FALSE;
    }
#  endif

#endif

    /* Wipe the key from memory now that it has been set in the cipher context.
     * It's still around somewhere, of course, but at least this is one place
     * less that it might be found. */
    Poison(key, FILTER_CRYPTO_KEY_LEN, unsigned char);

    return TRUE;
}

/*
 * Function to update the given cipher context with the data in the given input
 * SV.  This data is not assumed to be null-terminated, so the correct length
 * must be set in SvCUR(in_sv).  Likewise for the data written into the output
 * SV: SvCUR(out_sv) will be set correctly by this function.
 * Returns a bool to indicate success or failure.
 */

static bool FilterCrypto_CipherUpdate(pTHX_ EVP_CIPHER_CTX *ctx, SV *in_sv,
    SV *out_sv)
{
#if FILTER_CRYPTO_OPENSSL_VERSION < 90700
    unsigned char *in_text = (unsigned char *)SvPVX(in_sv);
#else
    const unsigned char *in_text = (const unsigned char *)SvPVX(in_sv);
#endif
    unsigned char *out_text;
    int in_len = SvCUR(in_sv);
    int orig_out_len;
    int out_len;

    /* Up to in_len + EVP_CIPHER_CTX_block_size(ctx) - 1 bytes may be written
     * when encrypting, and up to in_len + EVP_CIPHER_CTX_block_size(ctx) bytes
     * may be written when decrypting, so ensure that the output buffer is big
     * enough (plus space for a NUL terminator). */
    out_text = (unsigned char *)SvGROW(
        out_sv, (STRLEN)(in_len + EVP_CIPHER_CTX_block_size(ctx) + 1)
    );

    /* Advance the out_text pointer to the end of any existing output since the
     * output buffer may already have a salt and/or an IV in it if we have just
     * initialized an encryption process. */
    orig_out_len = SvCUR(out_sv);
    out_text += orig_out_len;

#if FILTER_CRYPTO_OPENSSL_VERSION < 90600
    EVP_CipherUpdate(ctx, out_text, &out_len, in_text, in_len);
#else
    if (!EVP_CipherUpdate(ctx, out_text, &out_len, in_text, in_len)) {
        FilterCrypto_SetErrStr(aTHX_
            "Can't update cipher context with %d bytes of in-text: %s",
            in_len, FILTER_CRYPTO_OPENSSL_ERR_STR
        );
        return FALSE;
    }
#endif

#ifdef FILTER_CRYPTO_DEBUG_MODE
    FilterCrypto_HexDump(aTHX_ out_text, out_len,
        "Converted %d bytes to %d bytes", in_len, out_len
    );
#endif

    /* Set the output length in the output SV, again accounting for any output
     * that already existed. */
    FilterCrypto_SvSetCUR(out_sv, orig_out_len + out_len);

    return TRUE;
}

/*
 * Function to finalize the given cipher context.  The data written into the
 * output SV is not assumed to be null-terminated, so SvCUR(out_sv) will be set
 * correctly by this function.
 * Returns a bool to indicate success or failure.
 */

static bool FilterCrypto_CipherFinal(pTHX_ EVP_CIPHER_CTX *ctx, SV *out_sv) {
    unsigned char *out_text;
    int out_len;

    /* Up to EVP_CIPHER_CTX_block_size(ctx) bytes may be written when encrypting
     * or decrypting, so ensure that the output buffer is big enough (plus space
     * for a NUL terminator). */
    out_text = (unsigned char *)SvGROW(
        out_sv, (STRLEN)(EVP_CIPHER_CTX_block_size(ctx) + 1)
    );

#if FILTER_CRYPTO_OPENSSL_VERSION < 90700
    if (!EVP_CipherFinal(ctx, out_text, &out_len)) {
        FilterCrypto_SetErrStr(aTHX_
            "Can't finalize cipher context: %s", FILTER_CRYPTO_OPENSSL_ERR_STR
        );
        return FALSE;
    }
#else
    if (!EVP_CipherFinal_ex(ctx, out_text, &out_len)) {
        FilterCrypto_SetErrStr(aTHX_
            "Can't finalize cipher context: %s", FILTER_CRYPTO_OPENSSL_ERR_STR
        );
        return FALSE;
    }

    if (!EVP_CIPHER_CTX_cleanup(ctx)) {
        FilterCrypto_SetErrStr(aTHX_
            "Can't cleanup cipher context: %s", FILTER_CRYPTO_OPENSSL_ERR_STR
        );
        return FALSE;
    }
#endif

#ifdef FILTER_CRYPTO_DEBUG_MODE
    FilterCrypto_HexDump(aTHX_ out_text, out_len,
        "Converted final block to %d bytes", out_len
    );
#endif

    /* Set the output length in the output SV. */
    FilterCrypto_SvSetCUR(out_sv, out_len);

    return TRUE;
}

/*
 * Function to initialize the OpenSSL/SSLeay PRNG.
 * Returns a bool to indicate success or failure.
 *
 * This function is based on code taken from the ssl_rand_seed() function in
 * mod_ssl (version 2.8.19-1.3.31).
 */

static bool FilterCrypto_PRNGInit(pTHX) {
    /* The PRNG is seeded transparently for us on some OS's (e.g. using UNIX's
     * /dev/urandom or /dev/random devices or Win32's Crypto API) in some
     * versions of OpenSSL and SSLeay, but in other cases we must do it
     * manually.  From 0.9.5 onwards RAND_status() is available to report
     * whether the PRNG is seeded.  Before 0.9.5 we always seed the PRNG
     * ourselves just to be sure. */
#if FILTER_CRYPTO_OPENSSL_VERSION >= 90500
    if (RAND_status())
        return TRUE;
#endif

    /* Win32 has a RAND_screen() function for seeding the PRNG from 0.6.5
     * onwards.  In other cases we just have to manage ourselves. */
#if(defined(WIN32) && FILTER_CRYPTO_OPENSSL_VERSION >= 60500)
    RAND_screen();
#else
    {
        time_t t;
        pid_t pid;
        int n;
        unsigned char stackdata[256];

        t = time(NULL);
        RAND_seed((unsigned char *)&t, sizeof t);

        pid = getpid();
        RAND_seed((unsigned char *)&pid, sizeof pid);

        n = FilterCrypto_GetRandNum(aTHX_ 0, sizeof stackdata - 128 - 1);
        RAND_seed(stackdata + n, 128);
    }
#endif

    /* We cannot check whether we have seeded the PRNG with enough entropy
     * before 0.9.5, so we just return TRUE in that case and hope for the
     * best. */
#if FILTER_CRYPTO_OPENSSL_VERSION >= 90500
    if (RAND_status()) {
        return TRUE;
    }
    else {
        FilterCrypto_SetErrStr(aTHX_ "Can't initialize PRNG");
        return FALSE;
    }
#else
    return TRUE;
#endif
}

/*
 * Function to return a random number between min and max.
 *
 * This function is based on the ssl_rand_choosenum() function in mod_ssl
 * (version 2.8.19-1.3.31).
 */

static int FilterCrypto_GetRandNum(pTHX_ int min, int max) {
    char buf[50];
    int n;

    seedDrand01((Rand_seed_t)time(NULL));
    PL_srand_called = TRUE;

    snprintf(buf, sizeof buf, "%.0f", Drand01() * (max - min));

    n = atoi(buf) + 1;

    if (n < min)
        n = min;

    if (n > max)
        n = max;

    return n;
}

/*
 * Function to get the last (most recent) OpenSSL/SSLeay error from the current
 * thread's error queue.
 */

static unsigned long FilterCrypto_GetLastSSLError(void) {
#if FILTER_CRYPTO_OPENSSL_VERSION >= 90700
    return ERR_peek_last_error();
#else
    unsigned long err;
    unsigned long last_err = 0;
    /* There are no ERR_peek_last_*() functions before 0.9.7, so we have to get
     * the errors (removing them from the queue) from the earliest to the last
     * instead.  We probably ought to put them back again afterwards, but it
     * does not really matter. */
    while ((err = ERR_get_error()))
        last_err = err;
    return last_err;
#endif
}

/*
 * Function to set the relevant Perl module's $ErrStr variable to the given
 * value.
 */

static void FilterCrypto_SetErrStr(pTHX_ const char *value, ...) {
    va_list args;

    /* Get the relevant Perl module's $ErrStr variable and set an appropriate
     * value in it. */
    va_start(args, value);
    sv_vsetpvf(get_sv(filter_crypto_errstr_var, TRUE), value, &args);
    va_end(args);
}

#ifdef FILTER_CRYPTO_DEBUG_MODE
/*
 * Function to print a dump of the given data.  Each character (octet) is shown
 * as itself if it is "printable"; otherwise it is shown as its hexadecimal
 * code.  An optional title can be printed first.  Pass NULL as the third
 * argument to omit the title.
 * Use this via either FilterCrypto_HexDump() or FilterCrypto_HexDumpSV().
 */

static void FilterCrypto_vHexDump(pTHX_ const unsigned char *data,
    unsigned int len, const char *title, va_list args)
{
    unsigned int i;

    if (title) {
        PerlIO_vprintf(PerlIO_stderr(), title, args);
        PerlIO_printf(PerlIO_stderr(), ":\n");
    }

    for (i = 0; i < len; ++i) {
        if (i % 16 == 0)
            PerlIO_printf(PerlIO_stderr(), "%s%08x", i == 0 ? "" : "\n", i);

        if (data[i] >= 32 && data[i] <= 127)
            PerlIO_printf(PerlIO_stderr(), " %2c", data[i]);
        else
            PerlIO_printf(PerlIO_stderr(), " %02x", data[i]);
    }

    PerlIO_printf(PerlIO_stderr(), "%s%08x\n", i == 0 ? "" : "\n", i);
}

/*
 * Function to print a dump of the given data.
 */

static void FilterCrypto_HexDump(pTHX_ const unsigned char *data,
    unsigned int len, const char *title, ...)
{
    va_list args;

    va_start(args, title);
    FilterCrypto_vHexDump(aTHX_ data, len, title, args);
    va_end(args);
}

/*
 * Function to print a dump of the data in the given SV.
 */

static void FilterCrypto_HexDumpSV(pTHX_ const SV *sv, const char *title, ...) {
    STRLEN len;
    unsigned char *data;
    va_list args;

    data = (unsigned char *)SvPV((SV *)sv, len);
    va_start(args, title);
    FilterCrypto_vHexDump(aTHX_ data, len, title, args);
    va_end(args);
}
#endif

/*============================================================================*/
