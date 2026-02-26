// Lockr.c – XChaCha20-Poly1305 with default .lockr/.key
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#include "chacha20_poly1305.h"

#define CHUNK 65536

// ─────────────────────────────────────────────────────
// Print cyberpunk Lockr banner
// ─────────────────────────────────────────────────────
static void print_banner(void) {
    printf(
" /$$                           /$$                \n"
"| $$                          | $$                \n"
"| $$        /$$$$$$   /$$$$$$$| $$   /$$  /$$$$$$ \n"
"| $$       /$$__  $$ /$$_____/| $$  /$$/ /$$__  $$\n"
"| $$      | $$  \\ $$| $$      | $$$$$$/ | $$  \\__/\n"
"| $$      | $$  | $$| $$      | $$_  $$ | $$      \n"
"| $$$$$$$$|  $$$$$$/|  $$$$$$$| $$ \\  $$| $$      \n"
"|________/ \\______/  \\_______/|__/  \\__/|__/      \n"
"                                                  \n"
"                                                  \n"
    );
}

// ─────────────────────────────────────────────────────
static FILE *open_or_pipe(const char *path, const char *mode) {
    if (strcmp(path, "-") == 0) {
        if (strchr(mode, 'r')) return stdin;
        if (strchr(mode, 'w') || strchr(mode, 'a')) return stdout;
    }
    FILE *f = fopen(path, mode);
    if (!f) fprintf(stderr, "[Lockr] Cannot open '%s': %s\n", path, strerror(errno));
    return f;
}

static size_t get_input_size(FILE *f) {
    if (f == stdin || f == stdout) return 0;
    long cur = ftell(f);
    if (fseek(f, 0, SEEK_END) != 0) return 0;
    long sz = ftell(f);
    fseek(f, cur, SEEK_SET);
    return (sz >= 0) ? (size_t)sz : 0;
}

static int fill_random(uint8_t *buf, size_t len) {
#ifdef _WIN32
    return BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 ? 0 : -1;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t r = read(fd, buf, len);
    close(fd);
    return r == (ssize_t)len ? 0 : -1;
#endif
}

static void print_hex(const char *label, const uint8_t *buf, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

// ─────────────────────────────────────────────────────
int main(int argc, char **argv) {
    // Print banner on startup
    print_banner();

    if (argc < 4) {
        fprintf(stderr,
            "Usage: %s <encrypt|decrypt> <input|- > <output|- > [aadfile] [keyfile]\n"
            "  '-' means stdin/stdout\n"
            "  Default encrypted file: <input>.lockr\n"
            "  Default key file      : <input>.key\n"
            "  Uses XChaCha20-Poly1305 (192-bit nonce)\n",
            argv[0]);
        return 1;
    }

    const char *mode    = argv[1];
    const char *in_path = argv[2];
    const char *out_path = argv[3];
    const char *aad_path = argc >= 5 ? argv[4] : NULL;
    const char *key_path = argc >= 6 ? argv[5] : NULL;

    // Set default .lockr and .key filenames if not specified
    char *out_default = NULL;
    char *key_default = NULL;

    if (!key_path) {
        key_default = malloc(strlen(in_path) + 5);
        sprintf(key_default, "%s.key", in_path);
        key_path = key_default;
    }

    if (!out_path || strcmp(out_path, "-") == 0) {
        out_default = malloc(strlen(in_path) + 7);
        sprintf(out_default, "%s.lockr", in_path);
        out_path = out_default;
    }

    uint8_t key[32], nonce[24], tag[16] = {0};
    uint8_t *aad = NULL;
    size_t aad_len = 0;

    if (aad_path) {
        FILE *fa = fopen(aad_path, "rb");
        if (fa) {
            fseek(fa, 0, SEEK_END); aad_len = ftell(fa); fseek(fa, 0, SEEK_SET);
            aad = malloc(aad_len);
            if (aad) fread(aad, 1, aad_len, fa);
            fclose(fa);
        }
    }

    FILE *fin  = open_or_pipe(in_path,  "rb");
    FILE *fout = open_or_pipe(out_path, "wb");
    if (!fin || !fout) {
        free(aad); free(out_default); free(key_default);
        return 1;
    }

    int is_stdin  = (fin  == stdin);
    int is_stdout = (fout == stdout);
    size_t filesize = get_input_size(fin);

    if (strcmp(mode, "encrypt") == 0) {
        printf("[Lockr] Encrypting %s → %s\n", is_stdin ? "<stdin>" : in_path, is_stdout ? "<stdout>" : out_path);

        if (fill_random(key, 32) < 0 || fill_random(nonce, 24) < 0) {
            fprintf(stderr, "[Lockr] Random generation failed\n");
            goto cleanup;
        }

        xchacha20poly1305_encrypt_stream_progress(fin, fout, tag, key, nonce, aad, aad_len, filesize);

        if (!is_stdout) {
            print_hex("[Lockr] Key   (32 bytes)", key,   32);
            print_hex("[Lockr] Nonce (24 bytes)", nonce, 24);
            print_hex("[Lockr] Tag   (16 bytes)", tag,   16);
        }

        FILE *kf = fopen(key_path, "wb");
        if (kf) {
            fwrite(key, 1, 32, kf);
            fclose(kf);
            if (!is_stdout) printf("[Lockr] Key saved to %s\n", key_path);
        }
    }
    else if (strcmp(mode, "decrypt") == 0) {
        printf("[Lockr] Decrypting %s → %s\n", is_stdin ? "<stdin>" : in_path, is_stdout ? "<stdout>" : out_path);

        FILE *kf = fopen(key_path, "rb");
        if (!kf || fread(key, 1, 32, kf) != 32) {
            fprintf(stderr, "[Lockr] Failed to load key from %s\n", key_path);
            if (kf) fclose(kf);
            goto cleanup;
        }
        if (kf) fclose(kf);

        int r = xchacha20poly1305_decrypt_stream_progress(fin, fout, key, aad, aad_len);
        if (r != 0) fprintf(stderr, "[Lockr] Decryption or verification failed\n");
    }
    else {
        fprintf(stderr, "[Lockr] Unknown mode: %s\n", mode);
    }

cleanup:
    if (fin  != stdin)  fclose(fin);
    if (fout != stdout) fclose(fout);
    free(aad);
    free(out_default);
    free(key_default);
    return 0;
}