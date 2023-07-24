// https://docs.kernel.org/accounting/taskstats.html
// https://github.com/torvalds/linux/blob/v6.0-rc7/tools/accounting/getdelays.c

// To remove "struct sigaction incomplete type" syntax error.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dirent.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/cgroupstats.h>
#include <linux/genetlink.h>
#include <sys/socket.h>

//////////////////////////////////////////////////////////////////////////////

#define TAG "task_stats"

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

// Print stats to terminal.
static bool print = false;

// Why use volatile: https://stackoverflow.com/q/246127/9165920
static volatile bool stopped = false;

static int nl_sock_fd = -1;

static unsigned short family_id;

//////////////////////////////////////////////////////////////////////////////

#define GENLMSG_DATA(glh) ((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))
#define GENLMSG_PAYLOAD(glh) (NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN)
#define NLA_DATA(na) ((void *)((char *)(na) + NLA_HDRLEN))
#define NLA_PAYLOAD(len) (len - NLA_HDRLEN)

// Maximum size of response requested or message sent
#define MAX_MSG_SIZE 1024

struct msgtemplate
{
	struct nlmsghdr n;
	struct genlmsghdr g;
	char buf[MAX_MSG_SIZE];
};

static int create_nl_socket()
{
	int nl_sd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (nl_sd < 0)
		print_err_code("Error creating socket");
	else
	{
		struct sockaddr_nl local;
		memset(&local, 0, sizeof(local));
		local.nl_family = AF_NETLINK;

		if (!bind(nl_sd, (struct sockaddr *)&local, sizeof(local)))
			return nl_sd;

		else
		{
			print_err_code("Error binding to socket");
			close(nl_sd);
		}
	}

	return -1;
}

static int send_cmd(int nl_sd, __u16 nlmsg_type, __u8 genl_cmd, __u16 nla_type, void *nla_data, int nla_len)
{
	struct msgtemplate msg;

	msg.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	msg.n.nlmsg_type = nlmsg_type;
	msg.n.nlmsg_flags = NLM_F_REQUEST;
	msg.n.nlmsg_seq = 0;
	msg.n.nlmsg_pid = getpid();
	msg.g.cmd = genl_cmd;
	msg.g.version = 0x1;

	struct nlattr *na;
	na = (struct nlattr *)GENLMSG_DATA(&msg);
	na->nla_type = nla_type;
	na->nla_len = nla_len + NLA_HDRLEN;

	memcpy(NLA_DATA(na), nla_data, nla_len);
	msg.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	struct sockaddr_nl nladdr;
	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	char *buf = (char *)&msg;
	int buflen = msg.n.nlmsg_len;
	int r;

	while ((r = sendto(nl_sd, buf, buflen, 0, (struct sockaddr *)&nladdr, sizeof(nladdr))) < buflen)
	{
		if (r > 0)
		{
			buf += r;
			buflen -= r;
		}
		else if (errno != EAGAIN)
			return print_err_code("Error sending cmd");
	}

	return EXIT_SUCCESS;
}

static int get_family_id(int nl_sd)
{
	char name[strlen(TASKSTATS_GENL_NAME) + 1];
	strcpy(name, TASKSTATS_GENL_NAME);

	int rc = send_cmd(nl_sd, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, CTRL_ATTR_FAMILY_NAME, (void *)name, strlen(name) + 1);
	if (!rc)
	{
		struct
		{
			struct nlmsghdr n;
			struct genlmsghdr g;
			char buf[256];
		} ans;

		int rep_len = recv(nl_sd, &ans, sizeof(ans), 0);
		if (ans.n.nlmsg_type != NLMSG_ERROR && rep_len > 0 && NLMSG_OK((&ans.n), rep_len))
		{
			struct nlattr *na;
			na = (struct nlattr *)GENLMSG_DATA(&ans);
			na = (struct nlattr *)((char *)na + NLA_ALIGN(na->nla_len));

			if (na->nla_type == CTRL_ATTR_FAMILY_ID)
			{
				family_id = *(__u16 *)NLA_DATA(na);
				return EXIT_SUCCESS;
			}
		}
		else
			print_err_code("Error getting family id");
	}

	return EXIT_FAILURE;
}

struct ts_reader
{
	struct pollfd pfd;

	struct msgtemplate msg;
	struct nlattr *na;
	struct taskstats *ts;
};

struct tid_stats
{
	int ppid;
	int tid;
	int uid;
	int gid;
	long long btime;
	long long read_bytes;
	long long write_bytes;
	char *comm;
};

static int get_task_stats(struct ts_reader *r, void (*cb)(struct tid_stats))
{
	int rep_len, len, aggr_len, len2;

	struct msgtemplate msg = r->msg;
	struct nlattr *na = r->na;
	struct taskstats *ts = r->ts;

	// Use poll() to allow terminate from another thread in Python code.
	int rc;
	while ((rc = poll(&r->pfd, 1, 500)) == 0 && !stopped)
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
			return EXIT_SUCCESS;
		else
			return print_err_code("Netlink poll failed");
	}

	if ((r->pfd.revents & POLLERR) != 0 || (r->pfd.revents & POLLNVAL) != 0)
	{
		int err = 0;
		socklen_t len = sizeof(err);
		getsockopt(r->pfd.fd, SOL_SOCKET, SO_ERROR, (void *)&err, &len);

		if (err)
			print_err("Netlink poll failed: %s", strerror(err));
		else
			return print_err("Netlink poll failed");

		// No sure if there is data to read with recv() or not.
		// https://stackoverflow.com/q/45846900/9165920
		return err == ENOBUFS ? EXIT_SUCCESS : EXIT_FAILURE;
	}

	// Should not happen.
	if ((r->pfd.revents & POLLIN) == 0)
		return EXIT_SUCCESS;

	// Do not receive event if stopped.
	if (stopped)
		return EXIT_SUCCESS;

	rep_len = recv(r->pfd.fd, &msg, sizeof(msg), 0);

	if (rep_len < 0)
	{
		if (!stopped || errno != EINTR)
			return print_err_code("Non-fatal reply error");

		return EXIT_SUCCESS;
	}

	if (msg.n.nlmsg_type == NLMSG_ERROR || !NLMSG_OK((&msg.n), rep_len))
	{
		struct nlmsgerr *err = NLMSG_DATA(&msg);
		errno = abs(err->error);
		return print_err_code("Fatal reply error");
	}

	len = 0;
	rep_len = GENLMSG_PAYLOAD(&msg.n);

	na = (struct nlattr *)GENLMSG_DATA(&msg);

	while (len < rep_len)
	{
		len += NLA_ALIGN(na->nla_len);

		switch (na->nla_type)
		{
		case TASKSTATS_TYPE_AGGR_TGID:
			// _TGID does not include I/O stats.
			break;
		case TASKSTATS_TYPE_AGGR_PID:
			aggr_len = NLA_PAYLOAD(na->nla_len);
			len2 = 0;
			na = (struct nlattr *)NLA_DATA(na);

			while (len2 < aggr_len)
			{
				switch (na->nla_type)
				{
				case TASKSTATS_TYPE_TGID:
					// _TGID does not include I/O stats.
					break;
				case TASKSTATS_TYPE_PID:
					if (print)
						printf("tid=%d ", *(int *)NLA_DATA(na));
					break;
				case TASKSTATS_TYPE_STATS:
					ts = (struct taskstats *)NLA_DATA(na);
					if (print)
					{
						printf("ppid=%u tid=%u uid=%u gid=%u starttime=%llu read=%llu write=%llu cancelled_write=%llu %s\n",
							   ts->ac_ppid, ts->ac_pid, ts->ac_uid, ts->ac_gid, ts->ac_btime64,
							   ts->read_bytes, ts->write_bytes, ts->cancelled_write_bytes, ts->ac_comm);
						fflush(stdout);
					}

					if (cb)
					{
						struct tid_stats tid_st = {
							.ppid = ts->ac_ppid,
							.tid = ts->ac_pid,
							.uid = ts->ac_uid,
							.gid = ts->ac_gid,
							.btime = ts->ac_btime64,
							.read_bytes = ts->read_bytes,
							.write_bytes = ts->write_bytes,
							.comm = ts->ac_comm};
						cb(tid_st);
					}

					break;
				case TASKSTATS_TYPE_NULL:
					break;
				default:
					print_err("Unknown nested nla_type %d", na->nla_type);
					break;
				}

				len2 += NLA_ALIGN(na->nla_len);
				na = (struct nlattr *)((char *)na + NLA_ALIGN(na->nla_len));
			}
			break;
		case CGROUPSTATS_TYPE_CGROUP_STATS:
		case TASKSTATS_TYPE_NULL:
			break;
		default:
			print_err("Unknown nla_type %d", na->nla_type);
			break;
		}
		na = (struct nlattr *)(GENLMSG_DATA(&msg) + len);
	}

	return EXIT_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////////

static int start_task_stats(void (*cb)(struct tid_stats))
{
	int rc = EXIT_FAILURE;

	int nl_sd = create_nl_socket();

	if (nl_sd < 0)
		return rc;

	// We need two Netlink sockets. One for exit listener (TASKSTATS_CMD_ATTR_REGISTER_CPUMASK),
	// other for per-tid stats (TASKSTATS_CMD_ATTR_PID).
	nl_sock_fd = nl_sd;

	nl_sd = create_nl_socket();

	if (nl_sd < 0)
	{
		close(nl_sock_fd);
		return rc;
	}

	if (get_family_id(nl_sd))
		goto end;

	char cpu_mask[8];
	snprintf(cpu_mask, sizeof(cpu_mask), "0-%ld", sysconf(_SC_NPROCESSORS_ONLN) - 1);

	if (send_cmd(nl_sd, family_id, TASKSTATS_CMD_GET, TASKSTATS_CMD_ATTR_REGISTER_CPUMASK, &cpu_mask, strlen(cpu_mask) + 1))
		goto end;

	print_out("Listening to exit task stats...");

	rc = EXIT_SUCCESS;
	struct ts_reader r = {.pfd = {.fd = nl_sd, .events = POLLIN}};

	while (!stopped)
	{
		if (get_task_stats(&r, cb))
		{
			rc = EXIT_FAILURE;
			break;
		}
	}

	rc = send_cmd(nl_sd, family_id, TASKSTATS_CMD_GET, TASKSTATS_CMD_ATTR_DEREGISTER_CPUMASK, &cpu_mask, strlen(cpu_mask) + 1) || rc;

end:
	close(nl_sock_fd);
	close(nl_sd);

	return rc;
}

static int get_tid_stats(pid_t tid, void (*cb)(struct tid_stats))
{
	// start_task_stats() must be called before get_tid_stats()
	if (stopped || nl_sock_fd < 0)
		return print_err("Netlink socket has not been created");

	if (send_cmd(nl_sock_fd, family_id, TASKSTATS_CMD_GET, TASKSTATS_CMD_ATTR_PID, &tid, sizeof(pid_t)))
		return EXIT_FAILURE;

	struct ts_reader r = {.pfd = {.fd = nl_sock_fd, .events = POLLIN}};

	if (get_task_stats(&r, cb))
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

static void stop_task_stats()
{
	stopped = true;
}

//////////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[])
{
	if (argc != 2)
		return print_err("One argument expected");

	pid_t pid = 0;

	if (strcmp(argv[1], "-l"))
	{
		pid = atoi(argv[1]);

		if (pid <= 0)
			return print_err("Bad PID: %s", argv[1]);
	}

	if (set_sig_actions(&stop_task_stats))
		return EXIT_FAILURE;

	print = true;

	if (!pid)
		return start_task_stats(NULL);

	int rc = EXIT_FAILURE;

	nl_sock_fd = create_nl_socket();

	if (nl_sock_fd < 0)
		return rc;

	if (get_family_id(nl_sock_fd))
		goto end;

	char path[PATH_MAX];
	snprintf(path, sizeof(path), "/proc/%d/task", pid);

	DIR *task_dir = opendir(path);

	if (!task_dir)
	{
		print_err_code("Failed to read %s", path);
		goto end;
	}

	const struct dirent *tid_dir;

	// _TGID does not include I/O stats. So we have to manually check all threads.
	while ((tid_dir = readdir(task_dir)))
	{
		pid = atoi(tid_dir->d_name);
		if (pid <= 0)
			continue; // Ignore . and ..

		rc = get_tid_stats(pid, NULL);

		if (rc)
			break;
	}

	closedir(task_dir);

end:
	close(nl_sock_fd);

	return rc;
}
