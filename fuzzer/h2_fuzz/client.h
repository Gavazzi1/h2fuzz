#ifndef NEZHA_CLIENT_H
#define NEZHA_CLIENT_H

#include <netinet/tcp.h>
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include <mutex>
#include <arpa/inet.h>

class Client {
public:
    virtual ~Client() {
        if (this->alive) {
            this->close();
        }
    }

    int connect(const char *ip_addr, int port) {
        struct sockaddr_in serv_addr{};
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);

        if (inet_pton(AF_INET, ip_addr, &serv_addr.sin_addr) <= 0) {
            error("ERROR invalid address/address not supported");
        }

        int on = 1;
        this->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *) &on, sizeof(int));

        if (this->sock < 0) {
            error("ERROR opening socket");
        }

        // timeout in 5 seconds
        struct timeval tv{};
        tv.tv_sec = 60;
        tv.tv_usec = 0;
        setsockopt(this->sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

        int retval = ::connect(this->sock, (struct sockaddr *) &serv_addr, sizeof(struct sockaddr_in));
        if (retval == 0) {
            this->alive = true;
        } else {
            std::cerr << "ERROR connecting to " << ip_addr << std::endl;
        }
        return retval;
    }

    ssize_t send(const void *data, size_t n, int flags) const {
        return ::send(this->sock, data, n, flags);
    }

    ssize_t read(void *buf, size_t n) const {
        return ::read(this->sock, buf, n);
    }

    int close() {
        this->alive = false;
        return ::close(this->sock);
    }

protected:
    int sock = 0;
    bool alive = false;

    static void error(const char *msg) {
        perror(msg);
        exit(0);
    }
};

#endif
