//
// Created by Zach on 2021/5/13.
//

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <fcntl.h>
#include <e_os.h>
#include <string>
#include <openssl/ec.h>
#include <crypto/ec/ec_lcl.h>
#include "utils.h"


unsigned char *hex2bin(const char *data, int size, int *outlen) {
    int i = 0;
    int len = 0;
    char char1 = '\0';
    char char2 = '\0';
    unsigned char value = 0;
    unsigned char *out = NULL;

    if (size % 2 != 0) {
        return NULL;
    }

    len = size / 2;
    out = (unsigned char *) malloc(len * sizeof(char) + 1);
    if (out == NULL) {
        return NULL;
    }

    while (i < len) {
        char1 = *data;
        if (char1 >= '0' && char1 <= '9') {
            value = (char1 - '0') << 4;
        } else if (char1 >= 'a' && char1 <= 'f') {
            value = (char1 - 'a' + 10) << 4;
        } else if (char1 >= 'A' && char1 <= 'F') {
            value = (char1 - 'A' + 10) << 4;
        } else {
            free(out);
            return NULL;
        }
        data++;

        char2 = *data;
        if (char2 >= '0' && char2 <= '9') {
            value |= char2 - '0';
        } else if (char2 >= 'a' && char2 <= 'f') {
            value |= char2 - 'a' + 10;
        } else if (char2 >= 'A' && char2 <= 'F') {
            value |= char2 - 'A' + 10;
        } else {
            free(out);
            return NULL;
        }

        data++;
        *(out + i++) = value;
    }
    *(out + i) = '\0';

    if (outlen != NULL) {
        *outlen = i;
    }

    return out;
}

char *bin2hex(unsigned char *data, int size) {
    int i = 0;
    int v = 0;
    char *p = NULL;
    char *buf = NULL;
    char base_char = 'A';

    buf = p = (char *) malloc(size * 2 + 1);
    for (i = 0; i < size; i++) {
        v = data[i] >> 4;
        *p++ = v < 10 ? v + '0' : v - 10 + base_char;

        v = data[i] & 0x0f;
        *p++ = v < 10 ? v + '0' : v - 10 + base_char;
    }

    *p = '\0';
    return buf;
}

int b64_op(const unsigned char *in, int in_len,
           char *out, int out_len, int op) {
    int ret = 0;
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bio = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, bio);
    if (op == 0) {
        ret = BIO_write(b64, in, in_len);
        BIO_flush(b64);
        if (ret > 0) {
            ret = BIO_read(bio, out, out_len);
        }

    } else {
        ret = BIO_write(bio, in, in_len);
        BIO_flush(bio);
        if (ret) {
            ret = BIO_read(b64, out, out_len);
        }
    }
    BIO_free(b64);
    return ret;
}

int writeBufToFile(char *file, char *buf) {
    int fd = open(file, O_CREAT | O_RDWR, 0666);
    if (fd == -1)
        return -1;
    int offset = write(fd, buf, 1024);
    if (offset == 0)
        return -2;
    close(fd);
    return 0;
}

int readBufFromFile(char *file, char *buf) {
    int fd = open(file, O_CREAT | O_RDWR, 0666);
    if (fd == -1)
        return -1;
    int offset = read(fd, buf, 1024);
    if (offset == 0)
        return -2;
    close(fd);
    return 0;
}