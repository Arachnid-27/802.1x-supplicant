#include <errno.h>
#include <stdlib.h>
#include <ifaddrs.h>
#include <signal.h>
#include "eapol.h"
#include "md5.h"

static void quit_handler(int sig);
static void md5_hash(uint8_t id, uint8_t* pwd, int p_len, uint8_t* val, int v_len, uint8_t* result);
static void show_interfaces();
static void show_usage();

static uint8_t sig_quit;

int main(int argc, char* argv[]) {
    char ch;
    int fd;
    int buf_len = 1024;
    uint8_t buf[1024], data[1024];
    uint8_t id;
    struct sockaddr_ll addr, auth;
    struct sigaction sa;
    char *username, *password, *interface;

    if (getuid() != 0) {
        printf("permission denied!\n");
        exit(EXIT_SUCCESS);
    }

    if (argc < 2) {
        show_usage();
    }

    while ((ch = getopt(argc, argv, "u:p:i:l")) != -1) {
        switch (ch) {
            case 'u':
                username = optarg;
                break;
            case 'p':
                password = optarg;
                break;
            case 'i':
                interface = optarg;
                break;
            case 'l':
                show_interfaces();
                break;
            default:
                printf("unknown option %c\n", ch);
                show_usage();
        }
    }

    if ((fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_PAE))) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = quit_handler;

    eapol_init_addr(&addr, interface);
    eapol_start(fd, &addr);
    eapol_request_username(fd, &auth, &id);
    memcpy(addr.sll_addr, auth.sll_addr, ETH_ALEN);
    eapol_response_username(fd, &addr, username, id);
    eapol_request_challenge(fd, &id, buf, &buf_len);
    md5_hash(id, (uint8_t*) password, strlen(password), buf, buf_len, data);
    eapol_response_challenge(fd, &addr, id, data, 16);
    eapol_result(fd);

    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }

    while (!sig_quit) {
        eapol_keep_alive(fd, &addr, 191);
        sleep(20);
    }

    eapol_log_off(fd, &addr);

    printf("quit successed!\n");
    exit(EXIT_SUCCESS);
}

static void quit_handler(int sig) {
    sig_quit = 1;
}

static void md5_hash(uint8_t id, uint8_t* pwd, int p_len, uint8_t* val, int v_len, uint8_t* result) {
    uint8_t raw[1 + v_len + p_len];
    struct md5_ctx ctx;

    raw[0] = id;
    memcpy(raw + 1, pwd, p_len);
    memcpy(raw + p_len + 1, val, v_len);

    md5_init(&ctx);
    md5_update(&ctx, raw, 1 + v_len + p_len);
    md5_final(result, &ctx);
}

static void show_interfaces() {
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_flags & IFF_LOOPBACK) {
            continue;
        }

        if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_PACKET) {
            printf("%s\n", ifa->ifa_name);
        }
    }

    exit(EXIT_SUCCESS);
}

static void show_usage() {
    printf("authentication:\n");
    printf("    supplicant -u <username> -p <password> -i <interface>\n");
    printf("list interfaces:\n");
    printf("    supplicant -l\n");

    exit(EXIT_SUCCESS);
}
