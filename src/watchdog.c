#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <linux/watchdog.h>


int wd_open() {
    int fd = open("/dev/watchdog", O_WRONLY, 0);

    int timeout = 300;
    ioctl(fd, WDIOC_SETTIMEOUT, &timeout);
    printf("watchdog set to %d seconds\n", timeout);

    return fd;
}


void wd_feed(int fd) {
    write(fd, "b", 1);
}
