#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "encdec.h"

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s <device> <count> [--key <value>] [--raw|--decrypt]\n", prog);
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    const char *device = argv[1];
    int count = atoi(argv[2]);
    int key = 0;
    int read_state = ENCDEC_READ_STATE_DECRYPT;

    for (int i = 3; i < argc; ++i) {
        if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            key = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--raw") == 0) {
            read_state = ENCDEC_READ_STATE_RAW;
        } else if (strcmp(argv[i], "--decrypt") == 0) {
            read_state = ENCDEC_READ_STATE_DECRYPT;
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    int fd = open(device, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    if (ioctl(fd, ENCDEC_CMD_CHANGE_KEY, key) < 0) {
        perror("ioctl change_key");
    }

    if (ioctl(fd, ENCDEC_CMD_SET_READ_STATE, read_state) < 0) {
        perror("ioctl set_read_state");
    }

    char *buf = malloc(count + 1);
    if (!buf) {
        perror("malloc");
        close(fd);
        return 1;
    }

    int ret = read(fd, buf, count);
    if (ret < 0) {
        perror("read");
        free(buf);
        close(fd);
        return 1;
    }

    buf[ret] = '\0';
    printf("%s", buf);

    free(buf);
    close(fd);
    return 0;
}
