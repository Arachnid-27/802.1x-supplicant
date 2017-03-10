#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

/**
 * Reference: RFC3748
 */

#define EAP_CODE_REQUEST 0x01
#define EAP_CODE_RESPONSE 0x02
#define EAP_CODE_SUCCESS 0x03
#define EAP_CODE_FAILURE 0x04

#define EAP_TYPE_IDENTITY 0x01
#define EAP_TYPE_NOTIFICATION 0x02
#define EAP_TYPE_NAK 0x03
#define EAP_TYPE_MD5 0x04
#define EAP_TYPE_OTP 0x05
#define EAP_TYPE_GTC 0x06
#define EAP_TYPE_EXPANDED 0xFE 
#define EAP_TYPE_EXPERIMENTAL 0xFF

#define EAP_HEADER_SIZE 0x05

/** 
 * 0        8        16               32       40                   
 * +--------+--------+----------------+--------+-----------------+ 
 * |  code  |   id   |     length     |  type  |      data       | 
 * +--------+--------+----------------+--------+-----------------+
 */

#define EAPOL_PROTOCOL_VERSION 0x01

#define EAPOL_TYPE_PACKET 0x00
#define EAPOL_TYPE_START 0x01
#define EAPOL_TYPE_LOGOFF 0x02

#define EAPOL_HEADER_SIZE 4

/**
 * 0        8        16               32
 * +--------+--------+----------------+------------------------+
 * |protocol| packet |  packet body   |          body          |
 * |version |  type  |     length     |                        |
 * +--------+--------+----------------+------------------------+
 */


#define EAPOL_BUF_SIZE 2048

typedef unsigned char uchar;

uchar eapol_buf[EAPOL_BUF_SIZE];
uchar eap_code, eap_id, eap_type;
uchar *eap_packet;
int eap_length;

const char* get_eap_code() {
    switch (eap_code) {
        case EAP_CODE_REQUEST:
            return "Request";
        case EAP_CODE_RESPONSE:
            return "Response";
        case EAP_CODE_SUCCESS:
            return "Success";
        case EAP_CODE_FAILURE:
            return "Failure";
    }
    return "(unknown)";
}

const char* get_eap_type() {
    switch (eap_type) {
        case EAP_TYPE_IDENTITY:
            return "Identity";
        case EAP_TYPE_NOTIFICATION:
            return "Notification";
        case EAP_TYPE_NAK:
            return "Nak";
        case EAP_TYPE_MD5:
            return "MD5-Challenge";
        case EAP_TYPE_OTP:
            return "One Time Password";
        case EAP_TYPE_GTC:
            return "Generic Token Card";
        case EAP_TYPE_EXPANDED:
            return "Expanded Nak";
        case EAP_TYPE_EXPERIMENTAL:
            return "Experimental";
    }
    return "(unknown)";
}

void eapol_show_message() {
    printf("EAP Message\n");
    printf("Code: %s (%d)\n", get_eap_code(), eap_code);
    printf("Indentifier: %d\n", eap_id);
    printf("Length: %d\n", eap_length);
    printf("Type: %s (%d)\n", get_eap_type(), eap_type);
    printf("Raw Data: ");
    for (int i = 0; i < eap_length; ++i) {
        printf("%02x ", eap_packet[i]);
    }
    printf("\n");
}

void eapol_parse_packet() {
    eap_packet = eapol_buf + EAPOL_HEADER_SIZE;
    eap_length = (eapol_buf[2] << 8) | eapol_buf[3];
    eap_code = eapol_buf[4];
    eap_id = eapol_buf[5];
    eap_type = eapol_buf[8];
}

int eapol_send_packet(int fd, int len, struct sockaddr_ll* addr) {
    return sendto(fd, eapol_buf, len, 0, (struct sockaddr*) &addr, sizeof(struct sockaddr_ll)) == len;
}

/*
 * set the addr of authenticator
 * MAC 01:80:c2:00:00:03
 */

void eapol_init_addr(struct sockaddr_ll* addr, const char* ifname) {
    memset(&addr, 0, sizeof(struct sockaddr_ll));
    addr->sll_family = AF_PACKET;
    addr->sll_protocol = htons(ETH_P_PAE);
    addr->sll_ifindex = if_nametoindex(ifname);
    addr->sll_hatype = ARPHRD_ETHER;
    addr->sll_pkttype = PACKET_HOST;
    addr->sll_halen = ETH_ALEN;
    addr->sll_addr[0] = 0x01;
    addr->sll_addr[1] = 0x80;
    addr->sll_addr[2] = 0xc2;
    addr->sll_addr[3] = 0x00;
    addr->sll_addr[4] = 0x00;
    addr->sll_addr[5] = 0x03;
}

int eapol_start(int fd, struct sockaddr_ll* addr) {
    eapol_buf[0] = EAPOL_PROTOCOL_VERSION;
    eapol_buf[1] = EAPOL_TYPE_START;
    eapol_buf[2] = 0x00;
    eapol_buf[3] = 0x00;

    return eapol_send_packet(fd, EAPOL_HEADER_SIZE, addr);
}

int eapol_request_username(int fd, struct sockaddr_ll* addr, uchar* id) {
    if (recvfrom(fd, eapol_buf, EAPOL_BUF_SIZE, 0, (struct sockaddr*) &addr, NULL) == -1) {
        return -1;
    }

    eapol_parse_packet();
    eapol_show_message();

    if (eap_code != EAP_CODE_REQUEST || eap_type != EAP_TYPE_IDENTITY) {
        return -1;
    }

    *id = eap_id;

    return 0;
}

int eapol_response_username(int fd, struct sockaddr_ll* addr, const char* username, const uchar id) {
    const int u_len = strlen(username);
    const int m_len = EAP_HEADER_SIZE + u_len;
    const int s_len = EAPOL_HEADER_SIZE + m_len;
    
    eapol_buf[0] = EAPOL_PROTOCOL_VERSION;
    eapol_buf[1] = EAPOL_TYPE_PACKET;
    eapol_buf[2] = (m_len >> 8) & 0xFF;
    eapol_buf[3] = m_len & 0xFF;

    eapol_buf[4] = EAP_CODE_RESPONSE;
    eapol_buf[5] = id;
    eapol_buf[6] = eapol_buf[2];
    eapol_buf[7] = eapol_buf[3];
    eapol_buf[8] = EAP_TYPE_IDENTITY;
    memcpy(eapol_buf + 9, username, u_len);

    return eapol_send_packet(fd, s_len, addr);
}


/*
 * only support MD5-Challenge
 */

int eapol_request_challenge(int fd, uchar* id, uchar* buf, int* buf_len) {
    if (recvfrom(fd, eapol_buf, EAPOL_BUF_SIZE, 0, NULL, NULL) == -1) {
        return -1;
    }

    eapol_parse_packet();
    eapol_show_message();

    if (eap_code != EAP_CODE_REQUEST || eap_type != EAP_TYPE_MD5) {
        return -1;
    }

    int v_size = eapol_buf[9];

    if (*buf_len < v_size) {
        return -1;
    }

    *id = eap_id;
    *buf_len = v_size;
    memcpy(eapol_buf + 10, buf, v_size);

    return 0;
}

int eapol_response_challenge(int fd, struct sockaddr_ll* addr, uchar id, uchar* buf, int buf_len) {
    const int m_len = EAP_HEADER_SIZE + buf_len;
    const int s_len = EAPOL_HEADER_SIZE + m_len;

    eapol_buf[0] = EAPOL_PROTOCOL_VERSION;
    eapol_buf[1] = EAPOL_TYPE_PACKET;
    eapol_buf[2] = (m_len >> 8) & 0xFF;
    eapol_buf[3] = m_len & 0xFF;

    eapol_buf[4] = EAP_CODE_RESPONSE;
    eapol_buf[5] = id;
    eapol_buf[6] = eapol_buf[2];
    eapol_buf[7] = eapol_buf[3];
    eapol_buf[8] = EAP_TYPE_MD5;
    eapol_buf[9] = buf_len;
    memcpy(eapol_buf + 10, buf, 16);

    return eapol_send_packet(fd, s_len, addr);
}

int eapol_result(int fd) {
    if (recvfrom(fd, eapol_buf, EAPOL_BUF_SIZE, 0, NULL, NULL) == -1) {
        return -1;
    }

    eapol_parse_packet();
    eapol_show_message();

    if (eap_code != EAP_CODE_SUCCESS) {
        return -1;
    }

    return 0;
}

void eapol_keep_alive(int fd, struct sockaddr_ll* addr, uchar type, int sec) {
    eapol_buf[0] = EAPOL_PROTOCOL_VERSION;
    eapol_buf[1] = type;
    eapol_buf[2] = 0x00;
    eapol_buf[3] = 0x00;

    while (1) {
        eapol_send_packet(fd, EAPOL_HEADER_SIZE, addr);
        sleep(sec);
    }
}

int eapol_log_off(int fd, struct sockaddr_ll* addr) {
    eapol_buf[0] = EAPOL_PROTOCOL_VERSION;
    eapol_buf[1] = EAPOL_TYPE_LOGOFF;
    eapol_buf[2] = 0x00;
    eapol_buf[3] = 0x00;

    return eapol_send_packet(fd, EAPOL_HEADER_SIZE, addr);
}
