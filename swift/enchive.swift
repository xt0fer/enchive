
import Foundation


// #ifndef ENCHIVE_VERSION
// #  define ENCHIVE_VERSION 3.5
let ENCHIVE_VERSION = 3.5
// #endif

// #ifndef ENCHIVE_FORMAT_VERSION
// #  define ENCHIVE_FORMAT_VERSION 3
let ENCHIVE_FORMAT_VERSION = 3
// #endif

// #ifndef ENCHIVE_FILE_EXTENSION
// #  define ENCHIVE_FILE_EXTENSION .enchive
// #endif
let ENCHIVE_FILE_EXTENSION = ".enchive"


// #ifndef ENCHIVE_KEY_DERIVE_ITERATIONS
// #  define ENCHIVE_KEY_DERIVE_ITERATIONS 25  /* 32MB */
// #endif
let ENCHIVE_KEY_DERIVE_ITERATIONS = 25 // 32MB

// #ifndef ENCHIVE_SECKEY_DERIVE_ITERATIONS
// #  define ENCHIVE_SECKEY_DERIVE_ITERATIONS 29 /* 512MB */
// #endif
let ENCHIVE_SECKEY_DERIVE_ITERATIONS = 29 // 512MB

let define ENCHIVE_OPTION_AGENT = 1
// #ifndef ENCHIVE_OPTION_AGENT
// #  if defined(__unix__) || defined(__APPLE__) || defined(__HAIKU__)
// #    define ENCHIVE_OPTION_AGENT 1
// #  else
// #    define ENCHIVE_OPTION_AGENT 0
// #  endif
// #endif

// #ifndef ENCHIVE_AGENT_TIMEOUT
// #  define ENCHIVE_AGENT_TIMEOUT 900 /* 15 minutes */
// #endif
let ENCHIVE_AGENT_TIMEOUT = 900

// #ifndef ENCHIVE_AGENT_DEFAULT_ENABLED
// #  define ENCHIVE_AGENT_DEFAULT_ENABLED 0
// #endif
let ENCHIVE_AGENT_DEFAULT_ENABLED = 0
// #ifndef ENCHIVE_PINENTRY_DEFAULT
// #  define ENCHIVE_PINENTRY_DEFAULT pinentry
// #endif
let ENCHIVE_PINENTRY_DEFAULT = "pinentry"
// #ifndef ENCHIVE_PINENTRY_DEFAULT_ENABLED
// #  define ENCHIVE_PINENTRY_DEFAULT_ENABLED 0
// #endif

// #ifndef ENCHIVE_PASSPHRASE_MAX
// #  define ENCHIVE_PASSPHRASE_MAX 1024
// #endif
let define ENCHIVE_PASSPHRASE_MAX = 1024

// /* Required for correct builds */

// #ifndef _POSIX_C_SOURCE
// #  define _POSIX_C_SOURCE 1
// #endif

// #define OPTPARSE_IMPLEMENTATION

// #define STR(a) XSTR(a)
// #define XSTR(a) #a

// /* Integer definitions needed by crypto */

// #include <stdint.h>
/* If your compiler lacks a stdint.h, such as when compiling with a
 * plain ANSI C compiler, you'll need to replace this include with the
 * appropriate typedefs for the following types:
 *
 *   uint8_t
 *   uint32_t
 *   uint64_t
 *   int32_t
 *   int64_t
 *
 * You will also need to define these macros:
 *
 *   UINT8_C
 *   UINT32_C
 */

let SHA256_BLOCK_SIZE = 32

// ## Encryption/decryption algorithm

// The process for encrypting a file:

// 1. Generate an ephemeral 256-bit Curve25519 key pair.
// 2. Perform a Curve25519 Diffie-Hellman key exchange with the master
//    key to produce a shared secret.
// 3. SHA-256 hash the shared secret to generate a 64-bit IV.
// 4. Add the format number to the first byte of the IV.
// 5. Initialize ChaCha20 with the shared secret as the key.
// 6. Write the 8-byte IV.
// 7. Write the 32-byte ephemeral public key.
// 8. Encrypt the file with ChaCha20 and write the ciphertext.
// 9. Write `HMAC(key, plaintext)`.


/**
 * Encrypt from file to file using key/iv, aborting on any error.
 */
// static void
// symmetric_encrypt(FILE *in, FILE *out, const uint8_t *key, const uint8_t *iv)
// {
func symmetric_encrypt(in: file, out: file, key: bytes, iv: bytes) {

//     static uint8_t buffer[2][CHACHA_BLOCKLENGTH * 1024];
//     uint8_t mac[SHA256_BLOCK_SIZE];
//     SHA256_CTX hmac[1];
//     chacha_ctx ctx[1];

//     chacha_keysetup(ctx, key, 256);
//     chacha_ivsetup(ctx, iv);
//     hmac_init(hmac, key);

//     for (;;) {
//         size_t z = fread(buffer[0], 1, sizeof(buffer[0]), in);
//         if (!z) {
//             if (ferror(in))
//                 fatal("error reading plaintext file");
//             break;
//         }
//         sha256_update(hmac, buffer[0], z);
//         chacha_encrypt(ctx, buffer[0], buffer[1], z);
//         if (!fwrite(buffer[1], z, 1, out))
//             fatal("error writing ciphertext file");
//         if (z < sizeof(buffer[0]))
//             break;
//     }

//     hmac_final(hmac, key, mac);

//     if (!fwrite(mac, sizeof(mac), 1, out))
//         fatal("error writing checksum to ciphertext file");
//     if (fflush(out))
//         fatal("error flushing to ciphertext file -- %s", strerror(errno));
}


// The process for decrypting a file:

// 1. Read the 8-byte ChaCha20 IV.
// 2. Read the 32-byte ephemeral public key.
// 3. Perform a Curve25519 Diffie-Hellman key exchange with the ephemeral
//    public key.
// 4. Validate the IV against the shared secret hash and format version.
// 5. Initialize ChaCha20 with the shared secret as the key.
// 6. Decrypt the ciphertext using ChaCha20.
// 7. Verify `HMAC(key, plaintext)`.

/**
 * Decrypt from file to file using key/iv, aborting on any error.
 */
// static void
// symmetric_decrypt(FILE *in, FILE *out, const uint8_t *key, const uint8_t *iv)
// {
//     static uint8_t buffer[2][CHACHA_BLOCKLENGTH * 1024 + SHA256_BLOCK_SIZE];
//     uint8_t mac[SHA256_BLOCK_SIZE];
//     SHA256_CTX hmac[1];
//     chacha_ctx ctx[1];

//     chacha_keysetup(ctx, key, 256);
//     chacha_ivsetup(ctx, iv);
//     hmac_init(hmac, key);

//     /* Always keep SHA256_BLOCK_SIZE bytes in the buffer. */
//     if (!(fread(buffer[0], SHA256_BLOCK_SIZE, 1, in))) {
//         if (ferror(in))
//             fatal("cannot read ciphertext file");
//         else
//             fatal("ciphertext file too short");
//     }

//     for (;;) {
//         uint8_t *p = buffer[0] + SHA256_BLOCK_SIZE;
//         size_t z = fread(p, 1, sizeof(buffer[0]) - SHA256_BLOCK_SIZE, in);
//         if (!z) {
//             if (ferror(in))
//                 fatal("error reading ciphertext file");
//             break;
//         }
//         chacha_encrypt(ctx, buffer[0], buffer[1], z);
//         sha256_update(hmac, buffer[1], z);
//         if (!fwrite(buffer[1], z, 1, out))
//             fatal("error writing plaintext file");

//         /* Move last SHA256_BLOCK_SIZE bytes to the front. */
//         memmove(buffer[0], buffer[0] + z, SHA256_BLOCK_SIZE);

//         if (z < sizeof(buffer[0]) - SHA256_BLOCK_SIZE)
//             break;
//     }

//     hmac_final(hmac, key, mac);
//     if (memcmp(buffer[0], mac, sizeof(mac)) != 0)
//         fatal("checksum mismatch!");
//     if (fflush(out))
//         fatal("error flushing to plaintext file -- %s", strerror(errno));

// }


// ## Key derivation algorithm

// Enchive uses an scrypt-like algorithm for key derivation, requiring a
// large buffer of random access memory. Derivation is controlled by a
// single difficulty exponent *D*. Secret key derivation requires 512MB
// of memory (D=29) by default, and protection key derivation requires
// 32MB by default (D=25). The salt for the secret key is all zeros.

// 1. Allocate a `(1 << D) + 32` byte buffer, *M*.
// 2. Compute `HMAC_SHA256(salt, passphrase)` and write this 32-byte
//    result to the beginning of *M*.
// 3. For each uninitialized 32-byte chunk in *M*, compute the SHA-256
//    hash of the previous 32-byte chunk.
// 4. Initialize a byte pointer *P* to the last 32-byte chunk of *M*.
// 5. Compute the SHA-256 hash, *H*, of the 32 bytes at *P*.
// 6. Overwrite the memory at *P* with *H*.
// 7. Take the first *D* bits of *H* and use this value to set a new *P*
//    pointing into *M*.
// 8. Repeat from step 5 `1 << (D - 5)` times.
// 9. *P* points to the result.


// static void
// command_archive(struct optparse *options)
// {
func command_archive(deleteIn: Bool) {
//     static const struct optparse_long archive[] = {
//         {"delete", 'd', OPTPARSE_NONE},
//         {0, 0, 0}
//     };

//     /* Options */
//     char *infile;
let infile = "";
//     char *outfile;
let outfile = "";
//     FILE *in = stdin;
//     FILE *out = stdout;

//     char *pubfile = dupstr(global_pubkey);
//     int delete = 0;

//     /* Workspace */
//     uint8_t public[32];
var public: [UInt8] = Array(repeating: 0, count: 32)
//     uint8_t esecret[32];
var esecret: [UInt8] = Array(repeating: 0, count: 32)
//     uint8_t epublic[32];
var epublic: [UInt8] = Array(repeating: 0, count: 32)
//     uint8_t shared[32];
var shared: [UInt8] = Array(repeating: 0, count: 32)
//     uint8_t iv[SHA256_BLOCK_SIZE];
var iv: [SHA256_BLOCK_SIZE] = Array(repeating: 0, count: SHA256_BLOCK_SIZE)
//     SHA256_CTX sha[1];

//     int option;
//     while ((option = optparse_long(options, archive, 0)) != -1) {
//         switch (option) {
//             case 'd':
//                 delete = 1;
//                 break;
//             default:
//                 fatal("%s", options->errmsg);
//         }
//     }
    // pass in flag to delete infile after success
    var delete = deleteIn

//     if (!pubfile)
//         pubfile = default_pubfile();
//     load_pubkey(pubfile, public);
//     free(pubfile);

//     infile = optparse_arg(options);
//     if (infile) {
//         in = fopen(infile, "rb");
//         if (!in)
//             fatal("could not open input file '%s' -- %s",
//                   infile, strerror(errno));
//     }

//     outfile = dupstr(optparse_arg(options));
//     if (!outfile && infile) {
//         /* Generate an output filename. */
//         outfile = joinstr(2, infile, enchive_suffix);
//     }
//     if (outfile) {
//         out = fopen(outfile, "wb");
//         if (!out)
//             fatal("could not open output file '%s' -- %s",
//                   outfile, strerror(errno));
//         cleanup_register(out, outfile);
//     }

//     /* Generare ephemeral keypair. */
//     generate_secret(esecret);
//     compute_public(epublic, esecret);

//     /* Create shared secret between ephemeral key and master key. */
//     compute_shared(shared, esecret, public);
//     sha256_init(sha);
//     sha256_update(sha, shared, sizeof(shared));
//     sha256_final(sha, iv);
//     iv[0] += (unsigned)ENCHIVE_FORMAT_VERSION;
//     if (!fwrite(iv, 8, 1, out))
//         fatal("failed to write IV to archive");
//     if (!fwrite(epublic, sizeof(epublic), 1, out))
//         fatal("failed to write ephemeral key to archive");
//     symmetric_encrypt(in, out, shared, iv);

//     if (in != stdin)
//         fclose(in);
//     if (out != stdout) {
//         cleanup_closed(out);
//         fclose(out); /* already flushed */
//     }
    
    // close in and out if they are not stdin and stdout.
 

//     if (delete && infile)
//         remove(infile);
    // delete infile after success
    if (delete) {
        remove_in_file(infile)
    }
// }
}

// static void
// command_extract(struct optparse *options)
// {
//     static const struct optparse_long extract[] = {
//         {"delete", 'd', OPTPARSE_NONE},
//         {0, 0, 0}
//     };

//     /* Options */
//     char *infile;
//     char *outfile;
//     FILE *in = stdin;
//     FILE *out = stdout;
//     char *secfile = dupstr(global_seckey);
//     int delete = 0;

//     /* Workspace */
//     SHA256_CTX sha[1];
//     uint8_t secret[32];
//     uint8_t epublic[32];
//     uint8_t shared[32];
//     uint8_t iv[8];
//     uint8_t check_iv[SHA256_BLOCK_SIZE];

//     int option;
//     while ((option = optparse_long(options, extract, 0)) != -1) {
//         switch (option) {
//             case 'd':
//                 delete = 1;
//                 break;
//             default:
//                 fatal("%s", options->errmsg);
//         }
//     }

//     if (!secfile)
//         secfile = default_secfile();
//     load_seckey(secfile, secret);
//     free(secfile);

//     infile = optparse_arg(options);
//     if (infile) {
//         in = fopen(infile, "rb");
//         if (!in)
//             fatal("could not open input file '%s' -- %s",
//                   infile, strerror(errno));
//     }

//     outfile = dupstr(optparse_arg(options));
//     if (!outfile && infile) {
//         /* Generate an output filename. */
//         size_t slen = sizeof(enchive_suffix) - 1;
//         size_t len = strlen(infile);
//         if (len <= slen || strcmp(enchive_suffix, infile + len - slen) != 0)
//             fatal("could not determine output filename from %s", infile);
//         outfile = dupstr(infile);
//         outfile[len - slen] = 0;
//     }
//     if (outfile) {
//         out = fopen(outfile, "wb");
//         if (!out)
//             fatal("could not open output file '%s' -- %s",
//                   infile, strerror(errno));
//         cleanup_register(out, outfile);
//     }

//     if (!(fread(iv, sizeof(iv), 1, in)))
//         fatal("failed to read IV from archive");
//     if (!(fread(epublic, sizeof(epublic), 1, in)))
//         fatal("failed to read ephemeral key from archive");
//     compute_shared(shared, secret, epublic);

//     /* Validate key before processing the file. */
//     sha256_init(sha);
//     sha256_update(sha, shared, sizeof(shared));
//     sha256_final(sha, check_iv);
//     check_iv[0] += (unsigned)ENCHIVE_FORMAT_VERSION;
//     if (memcmp(iv, check_iv, sizeof(iv)) != 0)
//         fatal("invalid master key or format");

//     symmetric_decrypt(in, out, shared, iv);

//     if (in != stdin)
//         fclose(in);
//     if (out != stdout) {
//         cleanup_closed(out);
//         fclose(out); /* already flushed */
//     }

//     if (delete && infile)
//         remove(infile);
// }