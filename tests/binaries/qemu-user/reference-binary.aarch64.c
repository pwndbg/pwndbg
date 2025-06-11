#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>

#define PORT 80

void break_here() {};

int main(int argc, char const* argv[]) {
    puts("Hello World");

    int sock = 0, client_fd;
    struct sockaddr_in serv_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "1.1.1.1", &serv_addr.sin_addr) <= 0) {
        perror("inet_pton");
        return -1;
    }

    if ((client_fd = connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr))) < 0) {
        perror("connect");
        return -1;
    }

    break_here();

    close(client_fd);
    return 0;
}
