#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <openssl/md5.h>
#include <stdlib.h>
#include <unistd.h>
#include "eapol.h"

void md5_hash(unsigned char id, char* pwd, int p_len, unsigned char* val, int v_len, unsigned char* result) {
    char raw[1 + v_len + p_len];
    MD5_CTX ctx;

    raw[0] = id;
    memcpy(raw + 1, pwd, p_len);
    memcpy(raw + p_len + 1, val, v_len);

    MD5_Init(&ctx);
    MD5_Update(&ctx, raw, 1 + v_len + p_len);
    MD5_Final(result, &ctx);
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        exit(EXIT_FAILURE);
    }

    int fd;
    int buf_len = 1024;
    uchar buf[1024], data[1024];
    uchar id;
    struct sockaddr_ll addr, auth;

    if ((fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_PAE))) == -1) {
        exit(EXIT_FAILURE);
    }

    eapol_init_addr(&addr, "enp8s0");
    eapol_start(fd, &addr);
    eapol_request_username(fd, &auth, &id);
    memcpy(addr.sll_addr, auth.sll_addr, ETH_ALEN);
    eapol_response_username(fd, &addr, argv[1], id);
    eapol_request_challenge(fd, &id, buf, &buf_len);
    md5_hash(id, argv[2], strlen(argv[2]), buf, buf_len, data);
    eapol_response_challenge(fd, &addr, id, data, 16);
    eapol_result(fd);
    eapol_keep_alive(fd, &addr, 191, 20);
    eapol_log_off(fd, &addr);

    return 0;
}
