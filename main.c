#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/types.h>
#include <unistd.h>

#include <cmp/cmp.h>

#define PLEDGE_WORKER "stdio rpath wpath cpath dpath fattr chown flock"

#define MAX_MESSAGE_LENGTH (1024 * 1024)
#define MAX_USERNAME_LENGTH 16
#define MAX_PASSWORD_LENGTH 128

// Don't use PATH_MAX. It's derpy.
#define MAX_PATH_LENGTH 4096

#ifdef __OpenBSD__
#include <login_cap.h>
#include <bsd_auth.h>
#else
int pledge(const char *promises, const char *paths[]) {
    fprintf(stderr, "WARNING: sandbox not supported on this platform\n");
    errno = ENOTSUP;
    return -1;
}

int auth_userokay(char *name, char *style, char *type, char *password) {
    fprintf(stderr, "WARNING: authentication not supported on this platform\n");
    return 1;
}
#endif

static inline void __fail(const char* file, int line, const char* func, const char* text) {
    fprintf(stderr, "Assertion failed: %s:%d (%s): %s\n", file, line, func, text);
    if (errno != 0) {
        perror("    ");
    }

    exit(1);
}

#define verify(cond) ((cond)? (0) : __fail(__FILE__, __LINE__, __func__, #cond))

// From MurmurHash3
static inline uint64_t integerHash(uint64_t k) {
    k ^= k >> 33;
    k *= 0xff51afd7ed558ccdLLU;
    k ^= k >> 33;
    k *= 0xc4ceb9fe1a85ec53LLU;
    k ^= k >> 33;

    return k;
}

static bool read_bytes(void *data, size_t limit, int fd) {
    return read(fd, data, limit) == limit;
}

static bool fd_reader(cmp_ctx_t* ctx, void* data, size_t limit) {
    return read_bytes(data, limit, (int)ctx->buf);
}

static size_t fd_writer(cmp_ctx_t* ctx, const void* data, size_t count) {
    return write((int)ctx->buf, data, sizeof(uint8_t) * count);
}

typedef struct {
    char root[MAX_PATH_LENGTH];
    uid_t uid;
    gid_t gid;
} auth_t;

void cmp_fd_init(cmp_ctx_t* cmp, int fd) {
    cmp_init(cmp, (void*)fd, fd_reader, fd_writer);
}

int sandbox(const char* promises, const char* paths[]) {
    if (pledge(promises, paths) == 0) {
        return 0;
    }

    verify(errno == ENOTSUP);
    return 0;
}

void handle_worker(va_list args) {
    const int sockfd = va_arg(args, int);
    const auth_t* auth = va_arg(args, auth_t*);

    verify(chroot(auth->root) == 0);
    verify(chdir("/") == 0);

    verify(setgid(auth->gid) == 0);
    verify(setuid(auth->uid) == 0);
    verify(setgroups(0, NULL) == 0);
    sandbox(PLEDGE_WORKER, NULL);

    close(sockfd);
}

void handle_state(va_list args) {
    verify(chroot("/var/empty") == 0);
    verify(chdir("/") == 0);
    sandbox("stdio", NULL);
}

void spawn(void (*worker)(), ...) {
    pid_t pid = fork();
    verify(pid >= 0);

    if (pid == 0) {
        va_list args;
        va_start(args, worker);
        worker(args);
        va_end(args);
        exit(0);
    }

    return;
}

bool authenticate(int sock, auth_t* auth) {
    char username[MAX_USERNAME_LENGTH];
    char password[MAX_PASSWORD_LENGTH];

    cmp_ctx_t cmp;
    cmp_fd_init(&cmp, sock);

    uint32_t array_size = 0;
    uint32_t username_len = sizeof(username) - 1;
    uint32_t password_len = sizeof(password) - 1;
    uint32_t root_len = MAX_PATH_LENGTH - 1;

    if (!cmp_read_array(&cmp, &array_size)) { return false; }
    if (array_size != 2) {
        return false;
    }

    if (!cmp_read_str(&cmp, username, &username_len)) { return false; }
    if (!cmp_read_str(&cmp, password, &password_len)) { return false; }
    if (!cmp_read_str(&cmp, auth->root, &root_len)) { return false; }

    struct passwd* passwd = getpwnam(username);
    if (passwd == NULL) { return false; }
    auth->uid = passwd->pw_uid;
    auth->gid = passwd->pw_gid;

    if (!auth_userokay(username, NULL, NULL, password)) {
        return false;
    }

    return true;
}

int main(int argc, char** argv) {
    auth_t authentication;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;

    int portno = 8001;
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    verify(sockfd >= 0);

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(portno);
    verify(bind(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) >= 0);
    listen(sockfd, 5);

    while (1) {
        socklen_t client_len = sizeof(client_addr);
        int newsockfd = accept(sockfd, (struct sockaddr *) &client_addr, &client_len);
        verify(newsockfd >= 0);
        memset(&authentication, 0, sizeof(authentication));
        if (authenticate(newsockfd, &authentication)) {
            spawn(handle_worker, newsockfd, &authentication);
        }

        close(newsockfd);
    }

    return 0;
}
