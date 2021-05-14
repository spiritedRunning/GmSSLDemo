//
// Created by Zach on 2021/5/13.
//

#ifndef GMSSLDEMO_UTILS_H
#define GMSSLDEMO_UTILS_H

unsigned char *hex2bin(const char *data, int size, int *outlen);

char *bin2hex(unsigned char *data, int size);

int b64_op(const unsigned char *in, int in_len, char *out, int out_len, int op);

/*存储文件*/
int writeBufToFile(char *file, char *buf);
/*读取文件*/
int readBufFromFile(char *file, char *buf);

int initEcKey(EC_KEY *ec_key,char * path);



#endif //GMSSLDEMO_UTILS_H
