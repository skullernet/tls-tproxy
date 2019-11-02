#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <string.h>

#include <libdill.h>
#undef bsend
#undef brecv

#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>

#include <linux/netfilter_ipv4.h>   // for SO_ORIGINAL_DST

#define TLS_HANDSHAKE       0x16
#define TLS_CLIENT_HELLO    0x01

#define pr_error(...) fprintf(stderr, __VA_ARGS__)
#define pr_info(...)  do { if (verbose > 0) fprintf(stderr, __VA_ARGS__); } while (0)
#define pr_debug(...) do { if (verbose > 1) fprintf(stderr, __VA_ARGS__); } while (0)

enum { TPROXY_IN = 1, TPROXY_OUT = 2 };

static struct ipaddr    listen_ip4;
static struct ipaddr    listen_ip6;

static int  tproxy;
static int  verbose;
static int  workers;

// partial receive
static int precv(int s, void *buf, size_t len, int64_t deadline)
{
    while (1) {
        ssize_t r = recv(s, buf, len, 0);
        if (r >= 0) return r;
        if (r < 0 && errno != EAGAIN) return -1;
        if (fdin(s, deadline)) return -1;
    }
}

static int brecv(int s, void *buf, size_t len, int64_t deadline)
{
    uint8_t *src = buf;
    while (1) {
        ssize_t r = recv(s, src, len, 0);
        if (r == 0) {
            errno = EPIPE;
            return -1;
        }
        if (r > 0) {
            src += r;
            len -= r;
            if (len == 0) return 0;
        }
        if (r < 0 && errno != EAGAIN) return -1;
        if (fdin(s, deadline)) return -1;
    }
}

static int bsend(int s, void *buf, size_t len, int64_t deadline)
{
    uint8_t *src = buf;
    while (1) {
        ssize_t r = send(s, src, len, MSG_NOSIGNAL);
        if (r > 0) {
            src += r;
            len -= r;
            if (len == 0) return 0;
        }
        if (r < 0 && errno != EAGAIN) return -1;
        if (fdout(s, deadline)) return -1;
    }
}

static coroutine void forward(int in_s, int out_s, int ch)
{
    int64_t res = 0;
    while (1) {
        uint8_t buf[0x8000];
        int r = precv(in_s, buf, sizeof(buf), -1);
        if (r <= 0) break;
        if (bsend(out_s, buf, r, -1)) break;
        res += r;
    }
    // signal completion
    chsend(ch, &res, sizeof(res), -1);
    chdone(ch);
}

static int getofs(const uint8_t *rec, int rec_len)
{
    int ofs = 4 + 2 + 32;   // skip header, client_version, random
    if (ofs >= rec_len) return ofs;
    ofs += 1 + rec[ofs];    // skip session_id
    if (ofs + 1 >= rec_len) return ofs + 1;
    ofs += 2 + (rec[ofs] << 8 | rec[ofs + 1]);  // skip cipher_suites
    if (ofs >= rec_len) return ofs;
    ofs += 1 + rec[ofs];    // skip compression_methods
    return ofs;
}

static char *a2s_buf(struct ipaddr *a, char *buf)
{
    const char *fmt = ipaddr_family(a) == AF_INET6 ? "[%s]:%d" : "%s:%d";
    snprintf(buf, 64, fmt, ipaddr_str(a, (char [IPADDR_MAXSTRLEN]){}), ipaddr_port(a));
    return buf;
}
#define a2s(a)  a2s_buf(a, (char [64]){})

static int open_socket(int family, bool transparent);

static void fd_close(int s, bool drop)
{
    fdclean(s); // clear libdill state
    if (drop) {
        struct linger l = { 1, 0 }; // disconnect socket immediately
        setsockopt(s, SOL_SOCKET, SO_LINGER, &l, sizeof(l));
    }
    close(s);
}

static int fd_connect(int s, const struct ipaddr *addr)
{
    if (!connect(s, ipaddr_sockaddr(addr), ipaddr_len(addr)))
        return 0;   // succeeded immediately?
    if (errno != EINPROGRESS)
        return -1;
    if (fdout(s, -1))
        return -1;
    int err;
    socklen_t errlen = sizeof(err);
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &errlen))
        return -1;
    if (err) {
        errno = err;
        return -1;
    }
    return 0;
}

static int tproxy_connect(const struct ipaddr *src, const struct ipaddr *dst)
{
    int s = open_socket(ipaddr_family(dst), tproxy & TPROXY_OUT);
    if (s < 0)
        return -1;
    if (tproxy & TPROXY_OUT) {
        if (bind(s, ipaddr_sockaddr(src), ipaddr_len(src))) {
            perror("bind");
            goto fail;
        }
    }
    if (fd_connect(s, dst)) {
        perror("connect");
        goto fail;
    }
    return s;
fail:
    fd_close(s, true);
    return -1;
}

static int tls_handshake(int s, int s_rem, int64_t deadline)
{
    uint8_t hdr[5];
    if (brecv(s, hdr, 1, deadline)) return -1;
    if (hdr[0] != TLS_HANDSHAKE) {
        pr_info("Expected TLS_HANDSHAKE, got %d\n", hdr[0]);
        return bsend(s_rem, hdr, 1, deadline);
    }
    if (brecv(s, hdr + 1, 1, deadline)) return -1;
    if (hdr[1] != 0x03) {
        pr_info("Expected TLS version 3, got %d\n", hdr[1]);
        return bsend(s_rem, hdr, 2, deadline);
    }
    if (brecv(s, hdr + 2, 3, deadline)) return -1;
    int rec_len = hdr[3] << 8 | hdr[4];
    if (rec_len == 0 || rec_len > 0x4000) {
        pr_info("Bad TLS handshake rec_len = %d\n", rec_len);
        return bsend(s_rem, hdr, 5, deadline);
    }
    pr_debug("TLS handshake rec_len = %d\n", rec_len);

    uint8_t rec[0x4000];
    if (brecv(s, rec, 1, deadline)) return -1;
    if (rec[0] != TLS_CLIENT_HELLO) {
        pr_info("Expected TLS_CLIENT_HELLO, got %d\n", rec[0]);
        if (bsend(s_rem, hdr, 5, deadline)) return -1;
        if (bsend(s_rem, rec, 1, deadline)) return -1;
        return 0;
    }
    if (brecv(s, rec + 1, rec_len - 1, deadline)) return -1;

    int ofs = getofs(rec, rec_len);
    pr_debug("TLS hello offset = %d\n", ofs);
    if (ofs >= rec_len) {
        // already split, or no extensions
        if (bsend(s_rem, hdr, 5, deadline)) return -1;
        if (bsend(s_rem, rec, rec_len, deadline)) return -1;
    } else {
        hdr[3] = ofs >> 8;
        hdr[4] = ofs & 0xff;
        if (bsend(s_rem, hdr, 5, deadline)) return -1;
        if (bsend(s_rem, rec, ofs, deadline)) return -1;

        int len = rec_len - ofs;
        hdr[3] = len >> 8;
        hdr[4] = len & 0xff;
        if (bsend(s_rem, hdr, 5, deadline)) return -1;
        if (bsend(s_rem, rec + ofs, len, deadline)) return -1;
    }
    return 0;
}

static coroutine void do_proxy(int s, struct ipaddr src, struct ipaddr dst)
{
    bool drop = true;
    int s_rem = tproxy_connect(&src, &dst);
    if (s_rem < 0)
        goto fail0;

    pr_info("Connect %s <--> %s\n", a2s(&src), a2s(&dst));
    int64_t sent = 0, rcvd = 0;

    // give them 15 seconds to send handshake
    if (tls_handshake(s, s_rem, now() + 15000)) goto fail1;

    int och[2], ich[2];
    if (chmake(och)) goto fail1;
    if (chmake(ich)) goto fail2;

    // start forwarding
    int ob = go(forward(s, s_rem, och[1]));
    if (ob < 0) goto fail3;
    int ib = go(forward(s_rem, s, ich[1]));
    if (ib < 0) goto fail4;

    struct chclause cc[] = {
        { CHRECV, och[0], &sent, sizeof(sent) },
        { CHRECV, ich[0], &rcvd, sizeof(rcvd) },
    };

    // wait until either side closes connection or error occurs
    switch (choose(cc, 2, -1)) {
    case 0: // incoming connection closed
        if (shutdown(s_rem, SHUT_WR)) break;
        if (chrecv(ich[0], &rcvd, sizeof(rcvd), -1)) break;
        drop = false;
        break;
    case 1: // outgoing connection closed
        if (shutdown(s, SHUT_WR)) break;
        if (chrecv(och[0], &sent, sizeof(sent), -1)) break;
        drop = false;
        break;
    }

    hclose(ib);
fail4:
    hclose(ob);
fail3:
    hclose(ich[0]);
    hclose(ich[0]);
fail2:
    hclose(och[0]);
    hclose(och[1]);
fail1:
    pr_info("Disconnect %s <--> %s ", a2s(&src), a2s(&dst));
    if (drop)
        pr_info("(with error)\n");
    else
        pr_info("(%"PRId64" bytes sent, %"PRId64" bytes rcvd)\n", sent, rcvd);
    fd_close(s_rem, drop);
fail0:
    fd_close(s, drop);
}

static int accept_new_conn(int fd, const struct ipaddr *src)
{
    struct ipaddr dst;
    socklen_t addrlen = sizeof(dst);
    if (tproxy & TPROXY_IN) {
        // for TPROXY, getsockname() returns destination address
        if (getsockname(fd, (struct sockaddr *)&dst, &addrlen)) {
            perror("getsockname");
            goto fail;
        }
    } else {
        // assume REDIRECT target
        if (getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &dst, &addrlen) &&
            getsockopt(fd, SOL_IPV6, SO_ORIGINAL_DST, &dst, &addrlen)) {
            perror("getsockopt(SO_ORIGINAL_DST)");
            goto fail;
        }
    }
    if (ipaddr_equal(&dst, &listen_ip4, 0) ||
        ipaddr_equal(&dst, &listen_ip6, 0)) {
        pr_info("Refusing to talk to self\n");
        goto fail;
    }
    if (bundle_go(workers, do_proxy(fd, *src, dst))) {
        perror("bundle_go");
        fd_close(fd, true);
        return -1;
    }
    return 0;
fail:
    fd_close(fd, true);
    return 0;
}

static coroutine void do_accept(int s)
{
    int spare_fd = dup(s);
    while (1) {
        struct ipaddr src;
        socklen_t addrlen = sizeof(src);
        int fd = accept4(s, (struct sockaddr *)&src, &addrlen, SOCK_NONBLOCK);
        if (fd >= 0) {
            if (accept_new_conn(fd, &src)) break;
            continue;
        }
        int err = errno;
        if (err == EAGAIN) {
            if (fdin(s, -1)) break;
            continue;
        }
        perror("accept4");
        if (err == ENFILE || err == EMFILE) {
            close(spare_fd);
            fd = accept4(s, (struct sockaddr *)&src, &addrlen, SOCK_NONBLOCK);
            if (fd >= 0) {
                fd_close(fd, true);
                spare_fd = dup(s);
            }
        }
    }
    close(spare_fd);
    fd_close(s, false);
}

static int open_socket(int family, bool transparent)
{
    int s = socket(family, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (s < 0) {
        perror("socket");
        return -1;
    }
    const int yes = 1;
    if (family == AF_INET6) {
        if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes))) {
            perror("setsockopt(IPV6_V6ONLY)");
            goto fail;
        }
        if (transparent) {
            if (setsockopt(s, IPPROTO_IPV6, IPV6_TRANSPARENT, &yes, sizeof(yes))) {
                perror("setsockopt(IPV6_TRANSPARENT)");
                goto fail;
            }
        }
    } else {
        if (transparent) {
            if (setsockopt(s, IPPROTO_IP, IP_TRANSPARENT, &yes, sizeof(yes))) {
                perror("setsockopt(IP_TRANSPARENT)");
                goto fail;
            }
        }
    }
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes))) {
        perror("setsockopt(SO_REUSEADDR)");
        goto fail;
    }
    return s;
fail:
    close(s);
    return -1;
}

static int setup_socket(const char *iface, int port, int mode)
{
    struct ipaddr *addr = mode == IPADDR_IPV4 ? &listen_ip4 : &listen_ip6;
    if (ipaddr_local(addr, iface, port, mode)) {
        perror("ipaddr_local");
        return -1;
    }
    int s = open_socket(ipaddr_family(addr), tproxy & TPROXY_IN);
    if (s < 0)
        return -1;
    if (bind(s, ipaddr_sockaddr(addr), ipaddr_len(addr))) {
        perror("bind");
        goto fail;
    }
    if (listen(s, 10)) {
        perror("listen");
        goto fail;
    }
    pr_info("Listening at %s\n", a2s(addr));
    if (bundle_go(workers, do_accept(s))) {
        perror("bundle_go");
        goto fail;
    }
    return 0;
fail:
    close(s);
    return -1;
}

int main(int argc, char **argv)
{
    char *iface = NULL;
    int port = 5555;
    int mode = 0;
    int opt;
    while ((opt = getopt(argc, argv, "i:p:46tTvh")) != -1) {
        switch (opt) {
        case 'i': iface = optarg; break;
        case 'p': port = atoi(optarg); break;
        case '4': mode = IPADDR_IPV4; break;
        case '6': mode = IPADDR_IPV6; break;
        case 't': tproxy |= TPROXY_IN; break;
        case 'T': tproxy |= TPROXY_OUT; break;
        case 'v': verbose++; break;
        case 'h':
        default:
            pr_error("Usage: %s [-i iface] [-p port] [-46tTvh]\n", argv[0]);
            return 1;
        }
    }
    workers = bundle();
    if (workers < 0) {
        perror("bundle");
        return 1;
    }
    if (mode == 0) {
        if (setup_socket(iface, port, IPADDR_IPV4)) return 1;
        setup_socket(iface, port, IPADDR_IPV6);
    } else {
        if (setup_socket(iface, port, mode)) return 1;
    }
    bundle_wait(workers, -1);
    return 1;
}
