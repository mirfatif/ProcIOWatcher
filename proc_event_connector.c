/* https://cirosantilli.com/linux-kernel-module-cheat#config-proc-events
 * https://github.com/cirosantilli/linux-kernel-module-cheat/blob/master/userland/linux/proc_events.c
 *
 * https://github.com/tijko/pevent
 */

#include <errno.h>
#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/netlink.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>

// Why use volatile: https://stackoverflow.com/q/246127/9165920
static volatile bool terminate = false;

static int nl_connect()
{
    int rc;
    int nl_sock;
    struct sockaddr_nl sa_nl;

    nl_sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (nl_sock == -1)
    {
        perror("Failed to create socket");
        return -1;
    }

    sa_nl.nl_family = AF_NETLINK;
    sa_nl.nl_groups = CN_IDX_PROC;
    sa_nl.nl_pid = getpid();
    rc = bind(nl_sock, (struct sockaddr *)&sa_nl, sizeof(sa_nl));
    if (rc == -1)
    {
        perror("Failed to bind to socket");
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
    {
        perror("Failed to send msg");
        return -1;
    }

    return 0;
}

static int handle_proc_ev(int nl_sock, void (*cb)(int))
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

    struct pollfd pfd = {.fd = nl_sock, .events = POLLIN};

    while (!terminate)
    {
        rc = poll(&pfd, 1, 500);
        if (rc == 0)
            // 500ms timed out
            continue;

        if (rc < 0)
        {
            /*
             * poll() is always interrupted despite of SA_RESTART
             * https://www.man7.org/linux/man-pages/man7/signal.7.html
             */
            if (errno == EINTR)
                // Will check if 'terminate' set in signal handler.
                continue;
            else
            {
                perror("Netlink poll failed");
                return -1;
            }
        }

        if ((pfd.revents & POLLERR) != 0 || (pfd.revents & POLLNVAL) != 0)
        {
            fprintf(stderr, "Netlink poll failed");
            return -1;
        }

        // Should not happen.
        if ((pfd.revents & POLLIN) == 0)
            continue;

        // Do not receive event if stopped.
        if (terminate)
            break;

        rc = recv(nl_sock, &nlcn_msg, sizeof(nlcn_msg), 0);
        if (rc == 0)
            // EOF
            break;

        if (rc == -1)
        {
            perror("Netlink recv failed");
            return -1;
        }

        struct proc_event ev = nlcn_msg.proc_ev;

        // https://github.com/tijko/pevent
        if (ev.event_data.ack.err == 22)
            continue;

        switch (ev.what)
        {
        case PROC_EVENT_NONE:
            printf("Listening to proc event multicast...\n");
            break;
        case PROC_EVENT_FORK:
            if (!cb)
                printf("FORK: parent tid=%d pid=%d -> child tid=%d pid=%d\n",
                       ev.event_data.fork.parent_pid,
                       ev.event_data.fork.parent_tgid,
                       ev.event_data.fork.child_pid,
                       ev.event_data.fork.child_tgid);
            break;
        case PROC_EVENT_EXEC:
            if (!cb)
                printf("EXEC: tid=%d pid=%d\n",
                       ev.event_data.exec.process_pid,
                       ev.event_data.exec.process_tgid);
            else
                cb(ev.event_data.exec.process_tgid);
            break;
        case PROC_EVENT_UID:
            if (!cb)
                printf("UID: tid=%d pid=%d from %d to %d\n",
                       ev.event_data.id.process_pid,
                       ev.event_data.id.process_tgid,
                       ev.event_data.id.r.ruid,
                       ev.event_data.id.e.euid);
            break;
        case PROC_EVENT_GID:
            if (!cb)
                printf("GID: tid=%d pid=%d from %d to %d\n",
                       ev.event_data.id.process_pid,
                       ev.event_data.id.process_tgid,
                       ev.event_data.id.r.rgid,
                       ev.event_data.id.e.egid);
            break;
        case PROC_EVENT_EXIT:
            if (!cb)
                printf("EXIT: tid=%d pid=%d exit_code=%d\n",
                       ev.event_data.exit.process_pid,
                       ev.event_data.exit.process_tgid,
                       ev.event_data.exit.exit_code);
            break;
        default:
            if (!cb)
                printf("Unhandled event: %d\n", ev.what);
            break;
        }

        if ((pfd.revents & POLLHUP) != 0)
            // EOF
            break;
    }

    return 0;
}

static void stop_proc_events()
{
    terminate = true;
}

static void do_terminate(int sig)
{
    stop_proc_events();
}

static int set_sigaction(int sig)
{
    struct sigaction act;
    if (sigaction(sig, NULL, &act))
    {
        perror("Failed to get sigaction");
        return -1;
    }

    act.sa_handler = &do_terminate;
    act.sa_flags |= SA_RESTART;

    if (sigaction(sig, &act, NULL))
    {
        perror("Failed to set sigaction");
        return -1;
    }

    return 0;
}

static int start_proc_events(void (*cb)(int))
{
    int rc = EXIT_FAILURE;

    int nl_sock = nl_connect();

    if (nl_sock > 0)
    {
        if (!set_proc_ev_listen(nl_sock, true))
        {
            if (!handle_proc_ev(nl_sock, cb))
                rc = EXIT_SUCCESS;

            set_proc_ev_listen(nl_sock, false);
        }

        close(nl_sock);
    }

    return rc;
}

int main(void)
{
    int sigs[] = {SIGHUP, SIGINT, SIGQUIT, SIGTERM};
    for (int i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++)
    {
        // if (signal(sigs[i], &do_terminate) == SIG_ERR)
        // {
        //     perror("Failed to set signal action");
        //     return EXIT_FAILURE;
        // }

        /*
         * SA_RESTART will make recv() restart after signal handler returns.
         * https://www.man7.org/linux/man-pages/man7/signal.7.html
         *
         * signal() also sets SA_RESTART, but be explicit.
         */
        if (set_sigaction(sigs[i]))
            return EXIT_FAILURE;
    }

    return start_proc_events(NULL);
}
