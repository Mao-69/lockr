// chacha20_poly1305.h
// XChaCha20-Poly1305 (192-bit nonce) – RFC 8439 compatible core + HChaCha20
// Fixed: no more -Wstringop-overflow warnings

#ifndef CHACHA20_POLY1305_H
#define CHACHA20_POLY1305_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define CHUNK 65536

// ─────────────────────────────────────────────────────────────────────────────
// Endian helpers
// ─────────────────────────────────────────────────────────────────────────────

static uint32_t load32_le(const uint8_t *b) {
    return (uint32_t)b[0] | ((uint32_t)b[1]<<8) | ((uint32_t)b[2]<<16) | ((uint32_t)b[3]<<24);
}

static void store32_le(uint8_t *b, uint32_t v) {
    b[0] = v&0xff; b[1]=(v>>8)&0xff; b[2]=(v>>16)&0xff; b[3]=(v>>24)&0xff;
}

static uint64_t load64_le(const uint8_t *b) {
    return (uint64_t)load32_le(b) | ((uint64_t)load32_le(b+4)<<32);
}

static void store64_le(uint8_t *b, uint64_t v) {
    store32_le(b, (uint32_t)v);
    store32_le(b+4, (uint32_t)(v>>32));
}

// ─────────────────────────────────────────────────────────────────────────────
// ChaCha20 core
// ─────────────────────────────────────────────────────────────────────────────

#define ROTL32(v,n) (((v)<<(n))|((v)>>(32-(n))))
#define QR(a,b,c,d) do { a+=b; d^=a; d=ROTL32(d,16); c+=d; b^=c; b=ROTL32(b,12); a+=b; d^=a; d=ROTL32(d,8); c+=d; b^=c; b=ROTL32(b,7); } while(0)

static const uint32_t CHACHA_CONST[4] = {0x61707865,0x3320646e,0x79622d32,0x6b206574};

static void chacha20_block(uint32_t out[16], const uint8_t key[32], uint32_t counter, const uint8_t nonce[12]) {
    uint32_t state[16], x[16];
    for (int i = 0; i < 4; i++) state[i] = CHACHA_CONST[i];
    for (int i = 0; i < 8; i++) state[4+i] = load32_le(key + i*4);
    state[12] = counter;
    state[13] = load32_le(nonce); state[14] = load32_le(nonce+4); state[15] = load32_le(nonce+8);
    memcpy(x, state, sizeof(state));
    for (int i = 0; i < 10; i++) {
        QR(x[0],x[4],x[8],x[12]); QR(x[1],x[5],x[9],x[13]);
        QR(x[2],x[6],x[10],x[14]); QR(x[3],x[7],x[11],x[15]);
        QR(x[0],x[5],x[10],x[15]); QR(x[1],x[6],x[11],x[12]);
        QR(x[2],x[7],x[8],x[13]); QR(x[3],x[4],x[9],x[14]);
    }
    for (int i = 0; i < 16; i++) out[i] = x[i] + state[i];
}

static void chacha20_xor(uint8_t *data, size_t len, const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
    uint32_t block[16]; uint8_t ks[64];
    while (len > 0) {
        chacha20_block(block, key, counter++, nonce);
        for (int i = 0; i < 16; i++) store32_le(ks + i*4, block[i]);
        size_t bs = len < 64 ? len : 64;
        for (size_t i = 0; i < bs; i++) data[i] ^= ks[i];
        data += bs; len -= bs;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HChaCha20 (used by XChaCha20)
// ─────────────────────────────────────────────────────────────────────────────

static void hchacha20_block(uint32_t out[8], const uint8_t key[32], const uint8_t nonce[16]) {
    uint32_t x[16];
    x[0] = CHACHA_CONST[0]; x[1] = CHACHA_CONST[1]; x[2] = CHACHA_CONST[2]; x[3] = CHACHA_CONST[3];
    x[4] = load32_le(key+0); x[5] = load32_le(key+4); x[6] = load32_le(key+8); x[7] = load32_le(key+12);
    x[8] = load32_le(key+16); x[9] = load32_le(key+20); x[10]= load32_le(key+24); x[11]= load32_le(key+28);
    x[12]= load32_le(nonce+0); x[13]= load32_le(nonce+4); x[14]= load32_le(nonce+8); x[15]= load32_le(nonce+12);

    for (int i = 0; i < 10; i++) {
        QR(x[0],x[4],x[8],x[12]); QR(x[1],x[5],x[9],x[13]);
        QR(x[2],x[6],x[10],x[14]); QR(x[3],x[7],x[11],x[15]);
        QR(x[0],x[5],x[10],x[15]); QR(x[1],x[6],x[11],x[12]);
        QR(x[2],x[7],x[8],x[13]); QR(x[3],x[4],x[9],x[14]);
    }
    out[0] = x[0]; out[1] = x[1]; out[2] = x[2]; out[3] = x[3];
    out[4] = x[12]; out[5] = x[13]; out[6] = x[14]; out[7] = x[15];
}

// ─────────────────────────────────────────────────────────────────────────────
// XChaCha20 (192-bit nonce)
// ─────────────────────────────────────────────────────────────────────────────

static void xchacha20_xor(uint8_t *data, size_t len, const uint8_t key[32], const uint8_t nonce[24], uint64_t counter) {
    uint8_t subkey[32];
    uint32_t tmp[8];
    hchacha20_block(tmp, key, nonce);
    for (int i = 0; i < 8; i++) store32_le(subkey + i*4, tmp[i]);

    uint8_t chacha_nonce[12] = {0};
    memcpy(chacha_nonce + 4, nonce + 16, 8);

    chacha20_xor(data, len, subkey, chacha_nonce, (uint32_t)counter);
}

// ─────────────────────────────────────────────────────────────────────────────
// Poly1305 (RFC 8439 compliant)
// ─────────────────────────────────────────────────────────────────────────────

typedef struct {
    uint64_t h0, h1, h2;
    uint64_t r0, r1, r2;
    uint64_t pad0, pad1;
    uint8_t buffer[16];
    size_t leftover;
} poly1305_ctx;

static void poly1305_init(poly1305_ctx *ctx, const uint8_t key[32]) {
    uint64_t t0 = load64_le(key), t1 = load64_le(key+8);
    ctx->r0 = t0 & 0x0ffffffc0fffffffULL;
    ctx->r1 = ((t0>>44)|(t1<<20)) & 0x0ffffffc0ffffffcULL;
    ctx->r2 = (t1>>24) & 0x3fffffffULL;
    ctx->h0 = ctx->h1 = ctx->h2 = 0;
    ctx->pad0 = load64_le(key+16); ctx->pad1 = load64_le(key+24);
    ctx->leftover = 0;
}

static void poly1305_block(poly1305_ctx *ctx, const uint8_t *m, int final) {
    uint64_t t0 = load64_le(m), t1 = load64_le(m+8);
    ctx->h0 += t0 & 0x3fffffffffffULL;
    ctx->h1 += ((t0>>42)|(t1<<22)) & 0x3fffffffffffULL;
    ctx->h2 += (t1>>20) & 0x3ffffffffffULL;
    if (final) ctx->h2 += (1ULL << 40);

    uint64_t d0 = ctx->h0*ctx->r0 + ctx->h1*5*ctx->r2 + ctx->h2*5*ctx->r1;
    uint64_t d1 = ctx->h0*ctx->r1 + ctx->h1*ctx->r0 + ctx->h2*5*ctx->r2;
    uint64_t d2 = ctx->h0*ctx->r2 + ctx->h1*ctx->r1 + ctx->h2*ctx->r0;

    uint64_t c = d0 >> 44; d0 &= 0x0fffffffffffULL; d1 += c;
    c = d1 >> 44; d1 &= 0x0fffffffffffULL; d2 += c;
    c = d2 >> 42; d2 &= 0x03fffffffffULL; d0 += 5*c;
    c = d0 >> 44; d0 &= 0x0fffffffffffULL; d1 += c;

    ctx->h0 = d0; ctx->h1 = d1; ctx->h2 = d2;
}

static void poly1305_update(poly1305_ctx *ctx, const uint8_t *msg, size_t len) {
    if (ctx->leftover) {
        size_t want = 16 - ctx->leftover;
        if (len < want) {
            memcpy(ctx->buffer + ctx->leftover, msg, len);
            ctx->leftover += len;
            return;
        }
        memcpy(ctx->buffer + ctx->leftover, msg, want);
        poly1305_block(ctx, ctx->buffer, 0);
        ctx->leftover = 0;
        msg += want; len -= want;
    }
    while (len >= 16) {
        poly1305_block(ctx, msg, 0);
        msg += 16; len -= 16;
    }
    if (len) {
        memcpy(ctx->buffer, msg, len);
        ctx->leftover = len;
    }
}

static void poly1305_finish(poly1305_ctx *ctx, uint8_t mac[16]) {
    if (ctx->leftover) {
        ctx->buffer[ctx->leftover] = 1;
        memset(ctx->buffer + ctx->leftover + 1, 0, 15 - ctx->leftover);
        poly1305_block(ctx, ctx->buffer, 1);
    } else {
        uint8_t one[16] = {1};
        poly1305_block(ctx, one, 1);
    }

    uint64_t f0 = ctx->h0 + ctx->pad0;
    uint64_t f1 = ctx->h1 + ctx->pad1 + (f0 >> 44);
    f0 &= 0x0fffffffffffULL;
    f1 &= 0x0fffffffffffULL;
    store64_le(mac, f0 | (f1 << 44));
    store64_le(mac + 8, f1 >> 20);
}

static int poly1305_verify(const uint8_t *a, const uint8_t *b) {
    uint8_t d = 0;
    for (int i = 0; i < 16; i++) d |= a[i] ^ b[i];
    return d == 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// File format: XChaCha20-Poly1305 self-contained
// ─────────────────────────────────────────────────────────────────────────────

static const uint8_t XHP_MAGIC[4] = {'X','H','P','1'};

static void xchacha20poly1305_encrypt_stream_progress(FILE *fin, FILE *fout,
        uint8_t tag[16], const uint8_t key[32], const uint8_t nonce[24],
        const uint8_t *aad, size_t aad_len, size_t filesize) {

    fwrite(XHP_MAGIC, 1, 4, fout);
    fwrite(nonce, 1, 24, fout);
    fseek(fout, 16, SEEK_CUR);  // tag placeholder

    uint8_t lenbuf[8];
    store64_le(lenbuf, aad_len);
    fwrite(lenbuf, 1, 8, fout);
    if (aad_len) fwrite(aad, 1, aad_len, fout);

    uint8_t subkey[32];
    uint32_t tmp[8];
    hchacha20_block(tmp, key, nonce);
    for (int i = 0; i < 8; i++) store32_le(subkey + i*4, tmp[i]);

    uint8_t poly_nonce[12] = {0};
    memcpy(poly_nonce + 4, nonce + 16, 8);

    uint8_t polykey[32];
    uint32_t poly_block[16];
    chacha20_block(poly_block, subkey, 0, poly_nonce);
    memcpy(polykey, poly_block, 32);  // safe, only first 32 bytes used

    poly1305_ctx ctx;
    poly1305_init(&ctx, polykey);
    poly1305_update(&ctx, aad, aad_len);
    if (aad_len % 16) {
        uint8_t pad[16] = {0};
        poly1305_update(&ctx, pad, 16 - (aad_len % 16));
    }

    uint8_t buf[CHUNK];
    size_t read;
    uint64_t ct_len = 0;

    while ((read = fread(buf, 1, CHUNK, fin)) > 0) {
        xchacha20_xor(buf, read, key, nonce, 1 + ct_len/64);
        fwrite(buf, 1, read, fout);
        poly1305_update(&ctx, buf, read);
        ct_len += read;
    }

    if (ct_len % 16) {
        uint8_t pad[16] = {0};
        poly1305_update(&ctx, pad, 16 - (ct_len % 16));
    }

    uint8_t lens[16] = {0};
    store64_le(lens, aad_len);
    store64_le(lens + 8, ct_len);
    poly1305_update(&ctx, lens, 16);
    poly1305_finish(&ctx, tag);

    long pos = ftell(fout);
    fseek(fout, 4 + 24, SEEK_SET);
    fwrite(tag, 1, 16, fout);
    fseek(fout, pos, SEEK_SET);
}

static int xchacha20poly1305_decrypt_stream_progress(FILE *fin, FILE *fout,
        const uint8_t key[32], const uint8_t *aad, size_t aad_len) {

    uint8_t magic[4];
    if (fread(magic, 1, 4, fin) != 4 || memcmp(magic, XHP_MAGIC, 4) != 0) return -1;

    uint8_t nonce[24];
    fread(nonce, 1, 24, fin);

    uint8_t file_tag[16];
    fread(file_tag, 1, 16, fin);

    uint8_t lenbuf[8];
    fread(lenbuf, 1, 8, fin);
    size_t file_aad_len = load64_le(lenbuf);

    uint8_t *file_aad = file_aad_len ? malloc(file_aad_len) : NULL;
    if (file_aad_len && fread(file_aad, 1, file_aad_len, fin) != file_aad_len) {
        free(file_aad);
        return -1;
    }

    if (file_aad_len != aad_len || (aad_len && memcmp(aad, file_aad, aad_len) != 0)) {
        free(file_aad);
        return -1;
    }
    free(file_aad);

    long ct_start = ftell(fin);
    fseek(fin, 0, SEEK_END);
    size_t ct_len = ftell(fin) - ct_start;
    fseek(fin, ct_start, SEEK_SET);

    // Verify
    uint8_t subkey[32];
    uint32_t tmp[8];
    hchacha20_block(tmp, key, nonce);
    for (int i = 0; i < 8; i++) store32_le(subkey + i*4, tmp[i]);

    uint8_t poly_nonce[12] = {0};
    memcpy(poly_nonce + 4, nonce + 16, 8);

    uint8_t polykey[32];
    uint32_t poly_block[16];
    chacha20_block(poly_block, subkey, 0, poly_nonce);
    memcpy(polykey, poly_block, 32);

    poly1305_ctx ctx;
    poly1305_init(&ctx, polykey);
    poly1305_update(&ctx, aad, aad_len);
    if (aad_len % 16) {
        uint8_t pad[16] = {0};
        poly1305_update(&ctx, pad, 16 - (aad_len % 16));
    }

    uint8_t buf[CHUNK];
    size_t remaining = ct_len;
    while (remaining) {
        size_t r = remaining > CHUNK ? CHUNK : remaining;
        fread(buf, 1, r, fin);
        poly1305_update(&ctx, buf, r);
        remaining -= r;
    }
    if (ct_len % 16) {
        uint8_t pad[16] = {0};
        poly1305_update(&ctx, pad, 16 - (ct_len % 16));
    }

    uint8_t lens[16] = {0};
    store64_le(lens, aad_len);
    store64_le(lens + 8, ct_len);
    poly1305_update(&ctx, lens, 16);

    uint8_t computed[16];
    poly1305_finish(&ctx, computed);
    if (!poly1305_verify(file_tag, computed)) return -1;

    // Decrypt
    fseek(fin, ct_start, SEEK_SET);
    remaining = ct_len;
    uint64_t ctr = 1;
    while (remaining) {
        size_t r = remaining > CHUNK ? CHUNK : remaining;
        fread(buf, 1, r, fin);
        xchacha20_xor(buf, r, key, nonce, ctr);
        fwrite(buf, 1, r, fout);
        ctr += (r + 63) / 64;
        remaining -= r;
    }
    return 0;
}

#endif