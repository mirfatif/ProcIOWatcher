#!/usr/bin/python

import collections
import datetime
import errno
import getopt
import hashlib
import inspect
import os
import pickle
import signal
import stat
import subprocess
import sys
import threading
import time
import traceback
from types import SimpleNamespace
from typing import Iterator, Iterable, Callable

import pynng
from pyroute2.netlink.exceptions import NetlinkError
from pyroute2.netlink.nlsocket import nlmsgerr
from pyroute2.netlink.taskstats import TaskStats
from pyroute2.netlink.taskstats import taskstatsmsg

NNG_SOCK_PATH = f'/tmp/{os.path.basename(sys.argv[0])}.sock'
DUMP_FILE_PATH = f'{os.getenv("HOME") or "/var/log/"}/{os.path.basename(sys.argv[0])}.dump'

MAX_RESULTS = 10
DEBUG_LEVEL = 0

COLS: int = 10000
if sys.stdout.isatty():
    COLS = os.get_terminal_size().columns


def print_d1(msg: str):
    if debug_level >= 1:
        print(msg[:COLS])


def print_d2(msg: str):
    if debug_level >= 2:
        print(msg[:COLS])


def print_exc_line():
    etype, value, tb = sys.exc_info()
    print(''.join(traceback.format_exception_only(etype, value)), file=sys.stderr, end='')


def print_err(msg: str, no_newline: bool = False):
    end = '\n'
    if no_newline:
        end = ''

    print(msg, file=sys.stderr, end=end)


class ProcParser:
    JIFFY_MILLI_SECS = 1000 / os.sysconf('SC_CLK_TCK')

    def __init__(self):
        self._dir = '/proc'

    def get_pids(self) -> Iterator[int]:
        for pid in os.listdir(self._dir):
            if pid.isdecimal():
                yield int(pid)

    def _read_file(self, pid: int, file: str, lines: bool = False) -> str | list[str] | None:
        try:
            with open(os.path.join(self._dir, str(pid), file)) as f:
                if lines:
                    return f.readlines()
                else:
                    return f.read()
        except (FileNotFoundError, ProcessLookupError):
            pass
            return None

    @staticmethod
    def _get_st_line_val(st_line: str) -> str:
        return st_line[st_line.index('\t') + 1:-1]

    @staticmethod
    def _str_to_uid_gid(st_line: str) -> int:
        return int(st_line[(i := st_line.index('\t') + 1):st_line.index('\t', i)])

    def get_status(self, pid: int) -> tuple[int, int, int, str, str, str] | None:
        if not (status := self._read_file(pid, 'status', True)):
            return None

        ppid = uid = gid = uid_str = gid_str = groups = None

        for line in status:
            if line.startswith('PPid:'):
                ppid = int(self._get_st_line_val(line))
            elif line.startswith('Uid:'):
                uid_str = self._get_st_line_val(line)
                uid = self._str_to_uid_gid(line)
            elif line.startswith('Gid:'):
                gid_str = self._get_st_line_val(line)
                gid = self._str_to_uid_gid(line)
            elif line.startswith('Groups:'):
                groups = self._get_st_line_val(line)
                break

        return ppid, uid, gid, uid_str, gid_str, groups

    def get_cmd(self, pid: int) -> str | None:
        if not (cmd := self._read_file(pid, 'cmdline')):
            return None
        else:
            return cmd.replace('\0', ' ').strip()

    @staticmethod
    def _get_io_val(io_line: str):
        return int(io_line[io_line.index(' ') + 1:-1])

    # This is not reliable approach b/c values include the I/O of all dead children.
    def get_io(self, pid: int) -> tuple[int | None, int | None] | None:
        if not (io := self._read_file(pid, 'io', True)):
            return None

        r_io = w_io = None

        for line in io:
            if line.startswith('read_bytes: '):
                r_io = self._get_io_val(line)
            elif line.startswith('write_bytes: '):
                w_io = self._get_io_val(line)
                break

        return r_io, w_io

    # Milliseconds since system boot.
    def get_start_time(self, pid: int) -> int | None:
        if not (st := self._read_file(pid, 'stat')):
            return None

        # Jump to 22nd field
        i: int = st.index(')') + 1
        for _ in range(20):
            i = st.index(' ', i) + 1

        return int(int(st[i:st.index(' ', i)]) * ProcParser.JIFFY_MILLI_SECS / 1000)

    def get_eff_caps(self, pid: int = os.getpid()) -> int | None:
        if not (status := self._read_file(pid, 'status', True)):
            return None

        eff_caps = None

        for line in status:
            if line.startswith('CapEff:'):
                eff_caps = int(self._get_st_line_val(line), 16)
                break

        return eff_caps


class Proc:
    def __init__(self, uid: int, gid: int, cmd: str):
        self.uid = uid
        self.gid = gid
        self.cmd = cmd
        self.pid_count: int = 0
        self.pid_records: dict[str, SimpleNamespace] = {}
        self.dead_pid_io = SimpleNamespace(r_io=0, w_io=0)

    def get_r_io(self, humanize: bool = False) -> float | str:
        io: float = self.dead_pid_io.r_io
        for r in self.pid_records.values():
            io += r.r_io

        if humanize:
            return HumanSize.do(io)
        else:
            return io

    def get_w_io(self, humanize: bool = False):
        io: float = self.dead_pid_io.w_io
        for r in self.pid_records.values():
            io += r.w_io

        if humanize:
            return HumanSize.do(io)
        else:
            return io

    def get_total_io(self, humanize: bool = False):
        io: float = self.dead_pid_io.r_io + self.dead_pid_io.w_io
        for r in self.pid_records.values():
            io += r.r_io + r.w_io

        if humanize:
            return HumanSize.do(io)
        else:
            return io


DeadPid = collections.namedtuple(
    'DeadPid',
    ['pid_key', 'pid', 'ppid', 'uid', 'gid', 'cmd', 'r_io', 'w_io']
)


class PidTaskStats:
    CPU_MASK = '0-%d' % (os.cpu_count() - 1)

    def __init__(self):
        self.ts = TaskStats()
        self.ts.bind()
        self.ts.register_mask(self.CPU_MASK)

    def close(self):
        self.check_open()
        self.ts.deregister_mask(self.CPU_MASK)
        self.ts.close()

    class TaskStatsSocketClosed(ConnectionError):
        def __str__(self):
            return 'Netlink socket is closed'

    def check_open(self):
        if self.ts.closed:
            raise self.TaskStatsSocketClosed

    def get_events(self):
        self.check_open()
        # TODO https://github.com/svinota/pyroute2/issues/1039
        return self.ts.get()

    @staticmethod
    def parse_msg(msg: taskstatsmsg | nlmsgerr, sent_pid: int = None) -> DeadPid | tuple[int, int] | None:
        if err := msg.get('header').get('error'):
            if not isinstance(err, NetlinkError) or not err.code == errno.ESRCH:
                print_err('Error in received msg:')
                traceback.print_exception(err)
            return None

        if not isinstance(msg, taskstatsmsg):
            print_err(f'Bad msg type: {type(msg)}')
            return None

        # attr = msg['attrs']
        # assert len(attr) == 1
        # attr = attr[0]
        # assert attr.name == 'TASKSTATS_TYPE_AGGR_PID'
        # a = attr.value['attrs']
        # assert a[0][0] == 'TASKSTATS_TYPE_PID'
        # assert a[1][0] == 'TASKSTATS_TYPE_STATS'
        # pid = a[0][1]
        # s = a[1][1]
        # s['ac_pid'], s['ac_ppid'], s['ac_uid'], s['ac_gid']
        # s['ac_comm'], s['read_bytes'], s['write_bytes']

        # Sometimes s['ac_pid'] and s['ac_ppid'] are 0
        pid = msg.get_nested('TASKSTATS_TYPE_AGGR_PID', 'TASKSTATS_TYPE_PID')
        s = msg.get_nested('TASKSTATS_TYPE_AGGR_PID', 'TASKSTATS_TYPE_STATS')

        ac_pid, ppid, uid, gid = s['ac_pid'], s['ac_ppid'], s['ac_uid'], s['ac_gid']
        cmd, r_io, w_io = s['ac_comm'], s['read_bytes'], s['write_bytes']
        # start_time: int = int((s['ac_btime'] - UPTIME_EPOCH_SECS))

        if pid <= 0:
            print_d1(f'Bsd PID: uid: {uid}, gid: {gid}, cmd: [{cmd}]')
            return None

        if not ac_pid and not ppid:
            print_d1(f'PPID and PID are zero: uid: {uid}, gid: {gid}, cmd: [{cmd}]')
        elif not ac_pid:
            print_d1(f'PID is zero: uid: {uid}, gid: {gid}, '
                     f'cmd: [{cmd}], parent_cmd: {parser.get_cmd(ppid)}')
        elif pid != 1 and not ppid:
            print_d1(f'PPID is zero: uid: {uid}, gid: {gid}, '
                     f'cmd: [{cmd}], procfs_cmd: {parser.get_cmd(pid)}')
        if ac_pid and pid != ac_pid:
            print_d1(f'PIDs are unequal (AGGR_PID: {pid}, AC_PID: {ac_pid}): uid: {uid}, gid: {gid}, '
                     f'cmd: [{cmd}], procfs_cmds:')
            print_d1(f'    AGGR_PID: [{parser.get_cmd(pid)}]')
            print_d1(f'    AC_PID: [{parser.get_cmd(ac_pid)}]')

        if sent_pid:
            if pid != sent_pid:
                print_d1(f'Sent ({sent_pid}) and received (AGGR_PID: {pid}) PIDs '
                         f'are different: uid: {uid}, gid: {gid}, cmd: [{cmd}]')
                return None
            else:
                return r_io, w_io
        else:
            return DeadPid(
                pid_key=create_pid_record_key(pid, uid, gid),
                pid=pid,
                ppid=ppid,
                uid=uid,
                gid=gid,
                cmd=cmd,
                r_io=r_io,
                w_io=w_io
            )

    def get_pid_io(self, pid: int) -> tuple[int, int] | None:
        self.check_open()
        try:
            pid_s = self.ts.get_pid_stat(pid)
        except NetlinkError as e:
            if e.code == errno.ESRCH:
                return None
            else:
                raise
        else:
            if not len(pid_s):
                return None

            if len(pid_s) != 1:
                print_err('Multiple messages for one pid:')
                print_err(pid_s)

            return self.parse_msg(pid_s[0], pid)


def create_pid_record_key(pid: int, uid: int, gid: int) -> str:
    return str(pid) + '|' + str(uid) + '|' + str(gid)


class HumanSize:
    SIZE_SUFFIXES = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']

    @staticmethod
    def do(n_bytes: float, spaced: bool = False) -> str:
        i: int = 0
        while n_bytes >= 1024 and i < len(HumanSize.SIZE_SUFFIXES) - 1:
            n_bytes /= 1024.
            i += 1

        space = ''
        if spaced:
            space = ' '

        n_bytes = ('%.1f' % n_bytes).rstrip('0').rstrip('.')
        return '%s%s%s' % (n_bytes, space, HumanSize.SIZE_SUFFIXES[i])


def create_proc(pid: int, clean_up: bool = False, is_nl: bool = False) -> None:
    if pid == 2:
        return

    if not (status := parser.get_status(pid)):
        return

    ppid, uid, gid, uid_str, gid_str, groups = status

    if ppid == 2:
        return

    if any(var is None for var in (ppid, uid, gid, uid_str, gid_str, groups)):
        print_err(f'Failed to read status of PID {pid}')
        return

    if not (io := task_stats.get_pid_io(pid)):
        return

    r_io, w_io = io

    if None in (r_io, w_io):
        print_err(f'Failed to read io for PID {pid}')
        return

    if not r_io and not w_io:
        return

    if not (cmd := parser.get_cmd(pid)):
        return

    # if not (start_time := parser.get_start_time(pid)):
    #     continue

    proc_key = uid_str + '|' + gid_str + '|' + groups + '|' + cmd
    proc_key: str = hashlib.md5(proc_key.encode()).hexdigest()
    # pid_key = pid + '|' + str(start_time)

    # Process start time differs in taskstats and /proc/<PID>/stat.
    # The former has accuracy up to -1 points, while the latter has up
    # to 2 points. So we can not match the start time on process death.
    pid_key = create_pid_record_key(pid, uid, gid)

    pid_record = None

    if proc := proc_cmd_records.get(proc_key):
        if pid_record := proc.pid_records.get(pid_key):
            pid_record.r_io = r_io
            pid_record.w_io = w_io
            if clean_up:
                pid_record.live = True
        elif is_nl:
            print_d2(f'Creating PID (NL): {pid_key} {cmd}')
        else:
            print_d2(f'Creating PID (procfs): {pid_key} {cmd}')
    else:
        proc = Proc(uid, gid, cmd)
        proc_cmd_records[proc_key] = proc
        if is_nl:
            print_d2(f'Creating proc (NL): {cmd}')
        else:
            print_d2(f'Creating proc (procfs): {cmd}')

    if not pid_record:
        # If new PID instantly does exec(), it has not been removed from our lists
        # so far. So we'll get same pid_key in two Proc. And proc_pid_records will
        # crash when trying to remove the same key twice.
        if old_proc := proc_pid_records.get(pid_key):
            print_d1(f'Replacing {pid_key}: [{old_proc.cmd}] with [{cmd}]')

            pid_record = old_proc.pid_records[pid_key]
            old_proc.dead_pid_io.r_io += pid_record.r_io
            old_proc.dead_pid_io.w_io += pid_record.w_io

            del old_proc.pid_records[pid_key]
            del proc_pid_records[pid_key]

        pid_record = SimpleNamespace(r_io=r_io, w_io=w_io, live=True)
        proc.pid_records[pid_key] = pid_record
        proc_pid_records[pid_key] = proc

        proc.pid_count += 1


def do_clean_up(proc: Proc, dead_pid: DeadPid = None, initial_clean_up: bool = False):
    removed = False

    if dead_pid:
        assert not initial_clean_up
    elif initial_clean_up:
        assert not dead_pid

    for key in list(proc.pid_records):
        if dead_pid:
            if key != dead_pid.pid_key:
                continue

            r_io = dead_pid.r_io
            w_io = dead_pid.w_io
        elif not (pid_record := proc.pid_records[key]).live:
            r_io = pid_record.r_io
            w_io = pid_record.w_io
        else:
            pid_record.live = False
            continue

        proc.dead_pid_io.r_io += r_io
        proc.dead_pid_io.w_io += w_io

        del proc.pid_records[key]

        if initial_clean_up:
            continue

        del proc_pid_records[key]

        removed = True

        if dead_pid:
            print_d2(f'Removing (NL): {key} {proc.cmd}')
            break
        else:
            print_d2(f'Removing: {key} {proc.cmd}')

    if dead_pid and not removed:
        print_d1(f'Failed to remove dead PID: {dead_pid.pid_key}]')


def create_dump_msg():
    return f'Dumped: Proc (cmd): {len(proc_cmd_records)}, Proc (ppid): ' \
           f'{len(proc_ppid_records)}, PID: {len(proc_pid_records)}'


def save_dump():
    with open(f'{dump_file_path}.tmp', 'wb') as f:
        pickle.dump(dump_start_time, f)
        pickle.dump(int(UPTIME_EPOCH_SECS), f)
        pickle.dump(proc_cmd_records, f)
        pickle.dump(proc_ppid_records, f)

    os.rename(f'{dump_file_path}.tmp', dump_file_path)


def load_dumps():
    try:
        with open(dump_file_path, 'rb') as f:
            start_time: float = pickle.load(f)
            uptime: int = pickle.load(f)
            cmd_r = pickle.load(f)
            ppid_r = pickle.load(f)
    except FileNotFoundError:
        pass
    else:
        global dump_start_time, proc_cmd_records, proc_ppid_records, proc_pid_records
        dump_start_time = start_time
        proc_cmd_records = cmd_r
        proc_ppid_records = ppid_r

        rebooted: bool = uptime != int(UPTIME_EPOCH_SECS)

        for proc in proc_cmd_records.values():
            for key in proc.pid_records:
                pid_record = proc.pid_records[key]
                if rebooted:
                    pid_record.live = False
                else:
                    proc_pid_records[key] = proc

            if rebooted:
                do_clean_up(proc, initial_clean_up=True)

        print(f'Loaded dump: Proc (cmd): {len(proc_cmd_records)}, '
              f'Proc (ppid): {len(proc_ppid_records)}, '
              f'PID: {len(proc_pid_records)}')


def parse_procfs() -> None:
    global procfs_iter_count
    clean_up: bool = procfs_iter_count % (10 / PROCFS_PARSE_DELAY_SECS) == 0
    save_data: bool = procfs_iter_count % (300 / PROCFS_PARSE_DELAY_SECS) == 0
    procfs_iter_count += 1

    for pid in parser.get_pids():
        create_proc(pid, clean_up=clean_up)

    if clean_up:
        for proc in proc_cmd_records.values():
            do_clean_up(proc)

        print_d2(f'Count: Proc (cmd): {len(proc_cmd_records)}, '
                 f'Proc (ppid): {len(proc_ppid_records)}, '
                 f'PID: {len(proc_pid_records)}')

    if save_data:
        save_dump()
        print_d2(create_dump_msg())


def parse_procfs_locked() -> None:
    with lists_lock:
        parse_procfs()


def handle_dead_pid(dp: DeadPid) -> None:
    # [] operator will throw KeyError if process is short-lived.
    if proc := proc_pid_records.get(dp.pid_key):
        do_clean_up(proc, dead_pid=dp)
        return

    if dp.r_io == 0 and dp.w_io == 0:
        return

    # PPID can be 0
    if ppid_cmd := parser.get_cmd(dp.ppid):
        ppid_key = str(dp.uid) + '|' + str(dp.gid) + '|' + ppid_cmd + '|' + dp.cmd
        ppid_key: str = hashlib.md5(ppid_key.encode()).hexdigest()

        if not (proc := proc_ppid_records.get(ppid_key)):
            proc = Proc(dp.uid, dp.gid, f'[{dp.cmd}] [{ppid_cmd}]')
            proc_ppid_records[ppid_key] = proc
            print_d2(f'Creating proc (ppid): {proc.cmd}')
        else:
            print_d2(f'Creating PID (ppid): {proc.cmd}')

        proc.dead_pid_io.r_io += dp.r_io
        proc.dead_pid_io.w_io += dp.w_io

        proc.pid_count += 1
    elif dp.w_io > 0:
        print_d1(f'Quick killer: '
                 f'{dp.uid}.{dp.gid} '
                 f'{HumanSize.do(dp.w_io)} '
                 f'[{dp.cmd}]')


def handle_dead_pids() -> None:
    while not terminated.is_set():
        try:
            events = task_stats.get_events()
        except PidTaskStats.TaskStatsSocketClosed:
            Thread.exit_msg_exc(inspect.currentframe().f_lineno)
            break

        with lists_lock:
            for evt in events:
                if dp := task_stats.parse_msg(evt):
                    handle_dead_pid(dp)


def handle_new_pid(pid: int) -> None:
    assert pid > 0

    with lists_lock:
        try:
            create_proc(pid, is_nl=True)
        except PidTaskStats.TaskStatsSocketClosed:
            # This should not happen. Close ProcEvent socket before closing TaskStats socket.
            Thread.exit_msg_exc(inspect.currentframe().f_lineno)


def handle_new_pids():
    native_bind.start_proc_events_nat(handle_new_pid)


class ClientCmd:
    CMD_GET_START_TIME: int = 0
    CMD_GET_PROC_LIST: int = 1
    CMD_GET_QUICK_PROC_LIST: int = 2

    def __init__(self, cmd: int):
        self.cmd: int = cmd


def start_nng_server():
    while not terminated.is_set():
        try:
            msg: pynng.Message = nng_server.recv_msg()
        except pynng.exceptions.Closed:
            Thread.exit_msg_exc(inspect.currentframe().f_lineno)
            return

        try:
            cmd: ClientCmd = pickle.loads(msg.bytes)
        except pickle.UnpicklingError:
            print_err('Bad command received from client: ', no_newline=True)
            print_exc_line()
            continue

        if not isinstance(cmd, ClientCmd):
            print_err(f'Bad command type "{type(cmd)}"')
            continue

        if cmd.cmd == ClientCmd.CMD_GET_START_TIME:
            msg.pipe.send(pickle.dumps(dump_start_time))
        elif cmd.cmd == ClientCmd.CMD_GET_PROC_LIST:
            with lists_lock:
                lst = list(proc_cmd_records.values())
            msg.pipe.send(pickle.dumps(lst))
        elif cmd.cmd == ClientCmd.CMD_GET_QUICK_PROC_LIST:
            with lists_lock:
                lst = list(proc_ppid_records.values())
            msg.pipe.send(pickle.dumps(lst))
        else:
            print_err(f'Bad command received from client: {cmd.cmd}')
            continue


def kill_me(sig: int = None, *_):
    if sys.stdout.isatty():
        print(f'\r')

    if sig:
        print(f'{signal.strsignal(sig)}, exiting...')
    else:
        print('Exiting...')

    with lists_lock:
        save_dump()
        print(create_dump_msg())

    if nng_server:
        nng_server.close()

    native_bind.stop_proc_events()
    if task_stats:
        task_stats.close()

    terminated.set()


class Thread(threading.Thread):
    def __init__(self, target: Callable, name=None, daemon=False):
        super(Thread, self).__init__(target=Thread._run_target, args=[target], name=name, daemon=daemon)

    @staticmethod
    def _run_target(func: Callable):
        Thread.set_excepthook()
        print(f'Starting thread {threading.current_thread().name}...')
        func()
        Thread.exit_msg()

    @staticmethod
    def set_excepthook():
        if threading.current_thread() is threading.main_thread():
            sys.excepthook = Thread.handle_uncaught_err
        else:
            threading.excepthook = lambda args: Thread.handle_uncaught_err(*args[:-1])

    @staticmethod
    def handle_uncaught_err(err_type, value, tb):
        print_err(f'Uncaught exception in thread: {threading.current_thread().name}:')
        traceback.print_exception(err_type, value, tb)
        kill_me()

    @staticmethod
    def exit_msg():
        print(f'Exiting {threading.current_thread().name}...')

    @staticmethod
    def exit_msg_exc(lineno: int = None):
        if lineno:
            print_err(f'line {lineno}: '
                      f'Exception in {threading.current_thread().name}: ', no_newline=True)
            print_exc_line()
        else:
            print_err(f'Exception in {threading.current_thread().name}')
            traceback.print_exc()


def to_str(lst: list, joiner: str = ' '):
    return joiner.join(str(s) for s in lst)


def check_caps():
    # include <linux/capability.h>
    cap_net_admin = 1 << 12

    if sys.stdin.isatty() and parser.get_eff_caps() & cap_net_admin == 0:
        print_err('cap_net_admin is required for netlink socket, restarting...')
        os.execvp('priv_exec', ['priv_exec', '--caps=net_admin', '--', *sys.argv])
        print_err('Failed to execute priv_exec')
        sys.exit(1)


def start_server():
    for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM):
        signal.signal(sig, kill_me)

    load_dumps()

    global nng_server
    nng_server = pynng.Rep0(listen=ipc_address, send_timeout=2000)
    os.chmod(nng_sock_path,
             stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH | stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)

    global task_stats
    task_stats = PidTaskStats()

    Thread(target=start_nng_server, name='NNGServer').start()
    Thread(target=handle_new_pids, name='NewPidHandler').start()
    Thread(target=handle_dead_pids, name='DeadPidHandler').start()

    Thread.set_excepthook()

    print(f'Watching procfs on {threading.current_thread().name}...')
    while not terminated.is_set():
        try:
            parse_procfs_locked()
        except PidTaskStats.TaskStatsSocketClosed:
            Thread.exit_msg_exc(inspect.currentframe().f_lineno)
            break
        else:
            terminated.wait(PROCFS_PARSE_DELAY_SECS)

    Thread.exit_msg()


def start_client() -> None:
    if not os.path.exists(nng_sock_path):
        print_err('Server not running')
        print_usage()
        sys.exit(1)

    def print_line(count: int, ch: str = '='):
        print(''.join([ch for _ in range(count)]))

    def print_proc_list(proc_list: Iterable[Proc], has_parent: bool = False) -> None:
        def sort_key(pr: Proc):
            if sort_by_read:
                return pr.get_r_io()
            else:
                return pr.get_w_io()

        sorted_procs: list[Proc] = sorted(proc_list, key=sort_key, reverse=True)
        del sorted_procs[max_results:]

        cmd = 'CMD'
        wid = 42
        if has_parent:
            cmd = '[CMD] [PARENT]'
            wid = 53

        print('{:<5} {:<12} {:>8} {:>8}   {}'.format('CNT', 'UID.GID', 'READ', 'WRITE', cmd))
        print_line(wid, '-')

        for p in sorted_procs:
            print(f'{p.pid_count:<5} {f"{p.uid}.{p.gid}":<12} '
                  f'{p.get_r_io(True):>8} {p.get_w_io(True):>8}   '
                  f'{p.cmd}'[:COLS])

    client = pynng.Req0(dial=ipc_address, send_timeout=1000, recv_timeout=2000)

    try:
        client.send(pickle.dumps(ClientCmd(ClientCmd.CMD_GET_START_TIME)))
        start_time: float = pickle.loads(client.recv())
        print('Since:', datetime.datetime.fromtimestamp(start_time).strftime("%d-%b-%y %I:%M%p"))

        client.send(pickle.dumps(ClientCmd(ClientCmd.CMD_GET_PROC_LIST)))
        print('\nProcesses')
        print_line(9)
        print_proc_list(pickle.loads(client.recv()))

        client.send(pickle.dumps(ClientCmd(ClientCmd.CMD_GET_QUICK_PROC_LIST)))
        lst = pickle.loads(client.recv())
        if len(lst):
            print('\nQuick Processes')
            print_line(15)
            print_proc_list(lst, has_parent=True)
    finally:
        client.close()


def print_usage():
    print(f'\nUsage:\n\t{os.path.basename(sys.argv[0])} [OPTIONS]')
    print(f'\nOptions:')
    print(f'\t-h|--help           Show help')
    print(f'\t--sock=<PATH>       Unix socket path (default: {NNG_SOCK_PATH})')
    print(f'\t--max=all|<NUM>     Max no. of results (default: {MAX_RESULTS})')
    print(f'\t--sort-by-read      Sort list by read I/O')
    print(f'\t--server            Run server')
    print(f'\t--dump-file=<PATH>  Dump file path (default: {DUMP_FILE_PATH})')
    print(f'\t--debug=1|2         Debug level (default: {DEBUG_LEVEL})')
    print()


def get_opts():
    try:
        opts, args = getopt.getopt(
            sys.argv[1:],
            'h',
            ['help', 'sock=', 'max=', 'sort-by-read', 'server', 'dump-file=', 'debug='])
    except getopt.GetoptError:
        print_exc_line()
        print_usage()
        sys.exit(1)

    if args:
        print_err(f'Unexpected arguments: {to_str(args)}')
        sys.exit(1)

    max_count = dump_file = debug_lvl = sort_read = None
    global nng_sock_path, is_server, max_results, sort_by_read, dump_file_path, debug_level

    for opt, val in opts:
        if opt == '--sock':
            nng_sock_path = val

        elif opt == '--server':
            is_server = True
        elif opt == '--debug':
            if not val.isdecimal():
                print_err(f'"{val}" is not an integer')
                sys.exit(1)

            debug_lvl = int(val)
        elif opt == '--dump-file':
            dump_file = val
        elif opt == '--max':
            if val.startswith('all'):
                max_count = 100000
            elif not val.isdecimal():
                print_err(f'"{val}" is not an integer')
                sys.exit(1)
            else:
                max_count = int(val)
        elif opt == '--sort-by-read':
            sort_read = True
        elif opt == '-h' or opt == '--help':
            print_usage()
            sys.exit(0)
        else:
            sys.exit(1)  # Should not happen.

    if max_count is not None:
        if is_server:
            print_err('--max option is for client only')
            print_usage()
            sys.exit(1)
        else:
            max_results = max_count

    if sort_read is not None:
        if is_server:
            print_err('--sort-by-read option is for client only')
            print_usage()
            sys.exit(1)
        else:
            sort_by_read = sort_read

    if dump_file is not None:
        if not is_server:
            print_err('--dump-file option is for server only')
            print_usage()
            sys.exit(1)
        else:
            dump_file_path = dump_file

    if debug_lvl is not None:
        if not is_server:
            print_err('--debug option is for server only')
            print_usage()
            sys.exit(1)
        else:
            debug_level = debug_lvl


def build_library(mod) -> None:
    if not sys.stdin.isatty():
        return

    my_dir = os.path.dirname(os.path.realpath(sys.argv[0]))

    lib = f'{mod}.so'
    if os.path.exists(os.path.join(my_dir, lib)):
        return

    cwd = os.getcwd()
    os.chdir(my_dir)

    print('Building native library...')

    def del_file(*files):
        for file in files:
            if os.path.exists(file):
                os.remove(file)

    c = f'{mod}.c'

    # cproto -f1 proc_event_connector.c | grep -vE '/\*' | sed 's|;\s$||'

    try:
        if not (err := subprocess.call(f'cython -3 {mod}.pyx -o {c}'.split())):
            ver = f'{sys.version_info[0]}.{sys.version_info[1]}'
            cp = subprocess.run(f'python{ver}-config --includes'.split(),
                                stdout=subprocess.PIPE, text=True)

            if not (err := cp.returncode):
                include = cp.stdout[:-1]
                err = err or subprocess.call(f'cc -shared -fPIC {include} {c} -o {lib}'.split())
                err = err or subprocess.call(f'strip -s -S --strip-unneeded {lib}'.split())

        if err:
            del_file(lib)
            print_err('Failed to build native library')
            sys.exit(err)
    finally:
        del_file(c)
        os.chdir(cwd)


if __name__ == '__main__':
    nng_sock_path: str = NNG_SOCK_PATH
    is_server: bool = False
    dump_file_path = DUMP_FILE_PATH
    max_results: int = MAX_RESULTS
    debug_level: int = DEBUG_LEVEL
    sort_by_read: bool = False

    get_opts()

    ipc_address: str = f'ipc://{nng_sock_path}'

    if not is_server:
        start_client()
        sys.exit()

    build_library('native_bind')
    import native_bind

    dump_start_time: float = time.time()
    UPTIME_EPOCH_SECS = dump_start_time - time.clock_gettime(time.CLOCK_BOOTTIME)

    PROCFS_PARSE_DELAY_SECS = 2

    parser: ProcParser = ProcParser()
    task_stats: PidTaskStats
    nng_server: pynng.Socket

    check_caps()

    proc_cmd_records: dict[str, Proc] = {}
    proc_ppid_records: dict[str, Proc] = {}
    proc_pid_records: dict[str, Proc] = {}
    procfs_iter_count: int = 0

    lists_lock: threading.Lock = threading.Lock()
    terminated = threading.Event()

    start_server()
