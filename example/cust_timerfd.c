#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <poll.h>

struct local_timerfd {
    int fd;
    timer_t timer;
};

static struct local_timerfd fds[10] = { {0} };
static int idx = 0;

static void timer_pipe_cb(union sigval sigev_value)
{
    char a = (char)1;

    if(1 != write(sigev_value.sival_int, &a, 1)){
        fprintf(stderr, "failed to write pipe fd");
        return;
    }

    return;
}

int local_timerfd_create(int clockid, int flags)
{
    struct sigevent evp;
    timer_t timer = 0;
    int pipe_fd[2] = { 0 };

    if(0 != pipe(pipe_fd)){
        fprintf(stderr, "failed to create pipe fd: %m");
        return -1;
    }

    (void)memset(&evp, 0, sizeof(evp));
    evp.sigev_value.sival_int = pipe_fd[1];
    evp.sigev_notify = SIGEV_THREAD;
    evp.sigev_notify_function = timer_pipe_cb;

    // create the timer, binding it to the event
    if (-1 == timer_create(clockid, &evp, &timer)) {
        fprintf(stderr, "failed to create timer: %m");
        return -1;
    }

    fds[idx].fd = pipe_fd[0];
    memcpy(&fds[idx].timer, &timer, sizeof(timer_t));
    idx++;

    return pipe_fd[0];
}

int local_timerfd_settime(int fd, int flags, const struct itimerspec *new_value, struct itimerspec *old_value)
{
    struct itimerspec ts;
    int i = 0, ret;

    for (; i < 10; i++) {
        if (fds[i].fd == fd) {
            break;
        }
        fprintf(stderr, "not initialized\n");
        return -1;
    }

    ts.it_value.tv_sec = new_value->it_value.tv_sec;
    ts.it_value.tv_nsec = new_value->it_value.tv_nsec;
    ts.it_interval.tv_sec = new_value->it_interval.tv_sec;
    ts.it_interval.tv_nsec = new_value->it_interval.tv_nsec;
    ret = timer_settime(fds[i].timer, 0, &ts, NULL);
    if (0 != ret) {
        fprintf(stderr, "failed to set timer: %m");
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    struct pollfd pfds;
    struct itimerspec ts;
    struct timespec now;
    int cnt;

    pfds.fd = local_timerfd_create(CLOCK_MONOTONIC, 0);
    pfds.events = POLLIN;

    ts.it_value.tv_sec = 0;
    ts.it_value.tv_nsec = atoi(argv[1]);
    ts.it_interval.tv_sec = 0;
    ts.it_interval.tv_nsec = atoi(argv[1]);
    local_timerfd_settime(pfds.fd, 0, &ts, NULL);

    while (1) {
        poll(&pfds, 1, -1);
        if (pfds.revents & POLLIN) {
            clock_gettime(CLOCK_REALTIME, &now);
            int buf;
            cnt = read(pfds.fd, &buf, sizeof(int));
            printf("[%ld.%09ld] timeout, cnt %d\n", now.tv_sec, now.tv_nsec, cnt);
        }
        else
            fprintf(stderr, "There is no data.\n");
    }

    return 0;
}
