/* https://cirosantilli.com/linux-kernel-module-cheat#config-proc-events
 * https://github.com/cirosantilli/linux-kernel-module-cheat/blob/master/userland/linux/proc_events.c
 *
 * https://github.com/tijko/pevent
 */

// To remove "struct sigaction incomplete type" syntax error.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/netlink.h>
#include <sys/socket.h>

//////////////////////////////////////////////////////////////////////////////

#define TAG "proc_events"

static int print_error(bool with_code, char *format, va_list args)
{
    fprintf(stderr, "%s: ", TAG);
    vfprintf(stderr, format, args);

    if (with_code)
        fprintf(stderr, ": %s", strerror(errno));

    fprintf(stderr, "\n");
    fflush(stderr);
    return EXIT_FAILURE;
}

static int print_err(char *format, ...)
{
    va_list args;
    va_start(args, format);
    print_error(false, format, args);
    va_end(args);
    return EXIT_FAILURE;
}

static int print_err_code(char *format, ...)
{
    va_list args;
    va_start(args, format);
    print_error(true, format, args);
    va_end(args);
    return EXIT_FAILURE;
}

static void print_out(char *format, ...)
{
    printf("%s: ", TAG);

    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    printf("\n");
    fflush(stdout);
}

/*
 * SA_RESTART flag makes recv() restart after signal handler returns.
 * https://www.man7.org/linux/man-pages/man7/signal.7.html
 *
 * signal() sets SA_RESTART. But we want recv() be
 * interrupted on signal received. So we use sigaction().
 */
static int set_sig_actions(void (*handler)(int))
{
    int sigs[] = {SIGHUP, SIGINT, SIGQUIT, SIGTERM};
    for (unsigned int i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++)
    {
        struct sigaction act;
        if (sigaction(sigs[i], NULL, &act))
            return print_err_code("Failed to get sigaction");

        act.sa_handler = handler;
        act.sa_flags &= ~SA_RESTART; // Be explicit.

        if (sigaction(sigs[i], &act, NULL))
            return print_err_code("Failed to set sigaction");
    }

    return EXIT_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////////

static bool print = false;

// Why use volatile: https://stackoverflow.com/q/246127/9165920
static volatile bool stopped = false;

//////////////////////////////////////////////////////////////////////////////

static int nl_connect()
{
    int rc;
    int nl_sock;
    struct sockaddr_nl sa_nl;

    nl_sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (nl_sock == -1)
    {
        print_err_code("Failed to create socket");
        return -1;
    }

    sa_nl.nl_family = AF_NETLINK;
    sa_nl.nl_groups = CN_IDX_PROC;
    sa_nl.nl_pid = getpid();
    rc = bind(nl_sock, (struct sockaddr *)&sa_nl, sizeof(sa_nl));
    if (rc == -1)
    {
        print_err_code("Failed to bind to socket");
        close(nl_sock);
        return -1;
    }

    return nl_sock;
}

static int set_proc_ev_listen(int nl_sock, bool enable)
{
    struct __attribute__((aligned(NLMSG_ALIGNTO)))
    {
        struct nlmsghdr nl_hdr;
        struct __attribute__((__packed__))
        {
            struct cn_msg cn_msg;
            enum proc_cn_mcast_op cn_mcast;
        };
    } nlcn_msg;

    memset(&nlcn_msg, 0, sizeof(nlcn_msg));
    nlcn_msg.nl_hdr.nlmsg_len = sizeof(nlcn_msg);
    nlcn_msg.nl_hdr.nlmsg_pid = getpid();
    nlcn_msg.nl_hdr.nlmsg_type = NLMSG_DONE;

    nlcn_msg.cn_msg.id.idx = CN_IDX_PROC;
    nlcn_msg.cn_msg.id.val = CN_VAL_PROC;
    nlcn_msg.cn_msg.len = sizeof(enum proc_cn_mcast_op);

    nlcn_msg.cn_mcast = enable ? PROC_CN_MCAST_LISTEN : PROC_CN_MCAST_IGNORE;

    if (send(nl_sock, &nlcn_msg, sizeof(nlcn_msg), 0) == -1)
        return print_err_code("Failed to send msg");

    return EXIT_SUCCESS;
}

static int handle_proc_events(int nl_sock, void (*cb)(int, int))
{
    int rc;
    struct __attribute__((aligned(NLMSG_ALIGNTO)))
    {
        struct nlmsghdr nl_hdr;
        struct __attribute__((__packed__))
        {
            struct cn_msg cn_msg;
            struct proc_event proc_ev;
        };
    } nlcn_msg;

    // Use poll() to allow terminate from another thread in Python code.
    struct pollfd pfd = {.fd = nl_sock, .events = POLLIN};

    while (!stopped)
    {
        rc = poll(&pfd, 1, 500);
        if (rc == 0)
            // 500ms timed out
            continue;

        if (rc < 0)
        {
            /*
             * poll() is always interrupted despite of SA_RESTART.
             * https://www.man7.org/linux/man-pages/man7/signal.7.html
             */
            if (errno == EINTR)
                // Will check if 'stopped' set in signal handler.
                continue;
            else
                return print_err_code("Netlink poll failed");
        }

        if ((pfd.revents & POLLERR) != 0 || (pfd.revents & POLLNVAL) != 0)
        {
            int err = 0;
            socklen_t len = sizeof(err);
            getsockopt(pfd.fd, SOL_SOCKET, SO_ERROR, (void *)&err, &len);

            if (err)
                print_err("Netlink poll failed: %s", strerror(err));
            else
                print_err("Netlink poll failed");

            if (err == ENOBUFS)
                // No sure if there is data to read with recv() or not.
                // https://stackoverflow.com/q/45846900/9165920
                continue;
            else
                return 1;
        }

        // Should not happen.
        if ((pfd.revents & POLLIN) == 0)
            continue;

        // Do not receive event if stopped.
        if (stopped)
            break;

        rc = recv(nl_sock, &nlcn_msg, sizeof(nlcn_msg), 0);

        if (rc == 0)
            // EOF
            break;

        if (rc == -1)
        {
            // Received interrupt signal.
            if (stopped && errno == EINTR)
                break;

            return print_err_code("Netlink recv failed");
        }

        struct proc_event ev = nlcn_msg.proc_ev;

        // https://github.com/tijko/pevent
        if (ev.event_data.ack.err == 22)
            continue;

        switch (ev.what)
        {
        case PROC_EVENT_NONE:
            print_out("Listening to proc event multicast...");
            break;
        case PROC_EVENT_FORK:
            if (print)
                printf("FORK: parent tid=%d pid=%d -> child tid=%d pid=%d\n",
                       ev.event_data.fork.parent_pid,
                       ev.event_data.fork.parent_tgid,
                       ev.event_data.fork.child_pid,
                       ev.event_data.fork.child_tgid);
            if (cb)
                cb(ev.event_data.fork.child_tgid, ev.event_data.fork.child_pid);
            break;
        case PROC_EVENT_EXEC:
            if (print)
                printf("EXEC: tid=%d pid=%d\n",
                       ev.event_data.exec.process_pid,
                       ev.event_data.exec.process_tgid);
            break;
        case PROC_EVENT_UID:
            if (print)
                printf("UID: tid=%d pid=%d from %d to %d\n",
                       ev.event_data.id.process_pid,
                       ev.event_data.id.process_tgid,
                       ev.event_data.id.r.ruid,
                       ev.event_data.id.e.euid);
            break;
        case PROC_EVENT_GID:
            if (print)
                printf("GID: tid=%d pid=%d from %d to %d\n",
                       ev.event_data.id.process_pid,
                       ev.event_data.id.process_tgid,
                       ev.event_data.id.r.rgid,
                       ev.event_data.id.e.egid);
            break;
        case PROC_EVENT_COMM:
            if (print)
                printf("COMM: tid=%d pid=%d comm=%s\n",
                       ev.event_data.comm.process_pid,
                       ev.event_data.comm.process_tgid,
                       ev.event_data.comm.comm);
            break;
        case PROC_EVENT_EXIT:
            if (print)
                printf("EXIT: tid=%d pid=%d exit_code=%d\n",
                       ev.event_data.exit.process_pid,
                       ev.event_data.exit.process_tgid,
                       ev.event_data.exit.exit_code);
            break;
        default:
            if (print)
                printf("UNHANDLED: 0x%x\n", ev.what);
            break;
        }

        if ((pfd.revents & POLLHUP) != 0)
            // EOF
            break;
    }

    return EXIT_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////////

// Callback to receive (int pid, int tid) for fork()
static int start_proc_events(void (*cb)(int, int))
{
    int rc = EXIT_FAILURE;

    int nl_sock = nl_connect();

    if (nl_sock > 0)
    {
        if (!set_proc_ev_listen(nl_sock, true))
        {
            if (!handle_proc_events(nl_sock, cb))
                rc = EXIT_SUCCESS;

            set_proc_ev_listen(nl_sock, false);
        }

        close(nl_sock);
    }

    return rc;
}

static void stop_proc_events()
{
    stopped = true;
}

//////////////////////////////////////////////////////////////////////////////

int main(void)
{
    if (set_sig_actions(&stop_proc_events))
        return EXIT_FAILURE;

    print = true;

    return start_proc_events(NULL);
}
