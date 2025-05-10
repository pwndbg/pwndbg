#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void break_here() {};

int parse_ip_port(const char* ip_str, int port, struct sockaddr_storage* out_addr, socklen_t* out_len) {
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Error: Invalid port number. Provide a value between 1 and 65535.\n");
        return -1;
    }

    memset(out_addr, 0, sizeof(*out_addr));
    if (strchr(ip_str, ':') != NULL) {
        // IPv6
        struct sockaddr_in6* addr6 = (struct sockaddr_in6*)out_addr;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(port);
        if (inet_pton(AF_INET6, ip_str, &addr6->sin6_addr) <= 0) {
            perror("inet_pton (IPv6)");
            return -1;
        }
        *out_len = sizeof(struct sockaddr_in6);
        return AF_INET6;
    } else {
        // IPv4
        struct sockaddr_in* addr4 = (struct sockaddr_in*)out_addr;
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(port);
        if (inet_pton(AF_INET, ip_str, &addr4->sin_addr) <= 0) {
            perror("inet_pton (IPv4)");
            return -1;
        }
        *out_len = sizeof(struct sockaddr_in);
        return AF_INET;
    }
}

int main(int argc, char const* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <ip> <port>\n", argv[0]);
        return -1;
    }
    const char* ip_str = argv[1];
    int port = atoi(argv[2]);

    puts("Hello World");

    int sock;
    struct sockaddr_storage serv_addr;
    socklen_t addr_len;
    int family = parse_ip_port(ip_str, port, &serv_addr, &addr_len);
    if (family < 0) {
        return -1;
    }

    if ((sock = socket(family, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return -1;
    }

    if (connect(sock, (struct sockaddr*)&serv_addr, addr_len) < 0) {
        perror("connect");
        return -1;
    }

    break_here();

    close(sock);
    return 0;
}
