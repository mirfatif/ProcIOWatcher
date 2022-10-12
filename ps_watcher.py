#!/usr/bin/python

import collections
import errno
import hashlib
import os
import pickle
import signal
import sys
import threading
import time
import getopt
from types import SimpleNamespace
from typing import Iterator, Iterable

import pynng

import native_bind
from pyroute2.netlink.exceptions import NetlinkError
from pyroute2.netlink.taskstats import TaskStats
from pyroute2.netlink.taskstats import taskstatsmsg

JIFFY_MILLI_SECS = 1000 / os.sysconf('SC_CLK_TCK')
UPTIME_EPOCH_SECS = time.time() - time.clock_gettime(time.CLOCK_BOOTTIME)

_SIZE_SUFFIXES = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
PROCFS_PARSE_DELAY_SECS = 1
DUMP_FILE = '/home/irfan/ps_watcher.dump'

_COLS: int = 10000
if sys.stdout.isatty():
    _COLS = os.get_terminal_size().columns

NNG_SOCK_PATH = 'ipc:///tmp/ps_watcher.sock'

DEBUG_LEVEL: int = 0


def print_d1(msg: str):
    if DEBUG_LEVEL >= 1:
        print(msg[:_COLS])


def print_d2(msg: str):
    if DEBUG_LEVEL >= 2:
        print(msg[:_COLS])


class ProcParser:
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
        if not (stat := self._read_file(pid, 'stat')):
            return None

        # Jump to 22nd field
        i: int = stat.index(')') + 1
        for _ in range(20):
            i = stat.index(' ', i) + 1

        return int(int(stat[i:stat.index(' ', i)]) * JIFFY_MILLI_SECS / 1000)

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
            return humansize(io)
        else:
            return io

    def get_w_io(self, humanize: bool = False):
        io: float = self.dead_pid_io.w_io
        for r in self.pid_records.values():
            io += r.w_io

        if humanize:
            return humansize(io)
        else:
            return io

    def get_total_io(self, humanize: bool = False):
        io: float = self.dead_pid_io.r_io + self.dead_pid_io.w_io
        for r in self.pid_records.values():
            io += r.r_io + r.w_io

        if humanize:
            return humansize(io)
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
        # TODO make non-blocking
        return self.ts.get()

    @staticmethod
    def parse_msg(msg: taskstatsmsg, sent_pid: int = None) -> DeadPid | tuple[int, int] | None:
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

        _pid, ppid, uid, gid = s['ac_pid'], s['ac_ppid'], s['ac_uid'], s['ac_gid']
        cmd, r_io, w_io = s['ac_comm'], s['read_bytes'], s['write_bytes']
        # start_time: int = int((s['ac_btime'] - UPTIME_EPOCH_SECS))

        if pid <= 0:
            print_d1(f'Bsd PID: uid: {uid}, gid: {gid}, cmd: [{cmd}]')
            return None

        if not _pid and not ppid:
            print_d1(f'PPID and PID are zero: uid: {uid}, gid: {gid}, cmd: [{cmd}]')
        elif not _pid:
            print_d1(f'PID is zero: uid: {uid}, gid: {gid}, '
                     f'cmd: [{cmd}], parent_cmd: {_parser.get_cmd(ppid)}')
        elif pid != 1 and not ppid:
            print_d1(f'PPID is zero: uid: {uid}, gid: {gid}, '
                     f'cmd: [{cmd}], procfs_cmd: {_parser.get_cmd(pid)}')
        if _pid and pid != _pid:
            print_d1(f'PIDs are unequal (AGGR_PID: {pid}, AC_PID: {_pid}): uid: {uid}, gid: {gid}, '
                     f'cmd: [{cmd}], procfs_cmds:')
            print_d1(f'    AGGR_PID: [{_parser.get_cmd(pid)}]')
            print_d1(f'    AC_PID: [{_parser.get_cmd(_pid)}]')

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
            assert len(pid_s) == 1
            return self.parse_msg(pid_s[0], pid)


def create_pid_record_key(pid: int, uid: int, gid: int) -> str:
    return str(pid) + '|' + str(uid) + '|' + str(gid)


def humansize(n_bytes: float, spaced: bool = False) -> str:
    i: int = 0
    while n_bytes >= 1024 and i < len(_SIZE_SUFFIXES) - 1:
        n_bytes /= 1024.
        i += 1

    space = ''
    if spaced:
        space = ' '

    n_bytes = ('%.1f' % n_bytes).rstrip('0').rstrip('.')
    return '%s%s%s' % (n_bytes, space, _SIZE_SUFFIXES[i])


def create_proc(pid: int, clean_up: bool = False, is_nl: bool = False) -> None:
    if pid == 2:
        return

    if not (status := _parser.get_status(pid)):
        return

    ppid, uid, gid, uid_str, gid_str, groups = status

    if ppid == 2:
        return

    if any(var is None for var in (ppid, uid, gid, uid_str, gid_str, groups)):
        print('Failed to read status of PID', pid, file=sys.stderr)
        return

    if not (cmd := _parser.get_cmd(pid)):
        return

    # if not (start_time := _parser.get_start_time(pid)):
    #     continue

    if not (io := _task_stats.get_pid_io(pid)):
        return

    r_io, w_io = io

    if None in (r_io, w_io):
        print('Failed to read io for PID', pid, file=sys.stderr)
        return

    proc_key = uid_str + '|' + gid_str + '|' + groups + '|' + cmd
    proc_key: str = hashlib.md5(proc_key.encode()).hexdigest()
    # pid_key = pid + '|' + str(start_time)

    # Process start time differs in taskstats and /proc/<PID>/stat.
    # The former has accuracy up to -1 points, while the latter has up
    # to 2 points. So we can not match the start time on process death.
    pid_key = create_pid_record_key(pid, uid, gid)

    pid_record = None

    if proc := _proc_cmd_records.get(proc_key):
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
        _proc_cmd_records[proc_key] = proc
        if is_nl:
            print_d2(f'Creating proc (NL): {cmd}')
        else:
            print_d2(f'Creating proc (procfs): {cmd}')

    if not pid_record:
        # If new PID instantly does exec(), it has not been removed from our lists
        # so far. So we'll get same pid_key in two Proc. And _proc_pid_records will
        # crash when trying to remove the same key twice.
        if old_proc := _proc_pid_records.get(pid_key):
            print_d1(f'Replacing {pid_key}: [{old_proc.cmd}] with [{cmd}]')

            pid_record = old_proc.pid_records[pid_key]
            old_proc.dead_pid_io.r_io += pid_record.r_io
            old_proc.dead_pid_io.w_io += pid_record.w_io

            del old_proc.pid_records[pid_key]
            del _proc_pid_records[pid_key]

        pid_record = SimpleNamespace(r_io=r_io, w_io=w_io, live=True)
        proc.pid_records[pid_key] = pid_record
        _proc_pid_records[pid_key] = proc

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

        del _proc_pid_records[key]

        removed = True

        if dead_pid:
            print_d2(f'Removing (NL): {key} {proc.cmd}')
            break
        else:
            print_d2(f'Removing: {key} {proc.cmd}')

    if dead_pid and not removed:
        print_d1(f'Failed to remove dead PID: {dead_pid.pid_key}]')


def create_dump_msg():
    return f'Dumped: Proc (cmd): {len(_proc_cmd_records)}, Proc (ppid): ' \
           f'{len(_proc_ppid_records)}, PID: {len(_proc_pid_records)}'


def save_dump():
    with open(f'{DUMP_FILE}.tmp', 'wb') as f:
        pickle.dump(int(UPTIME_EPOCH_SECS), f)
        pickle.dump(_proc_cmd_records, f)
        pickle.dump(_proc_ppid_records, f)

    os.rename(f'{DUMP_FILE}.tmp', DUMP_FILE)


def load_dumps():
    try:
        with open(DUMP_FILE, 'rb') as f:
            uptime = pickle.load(f)
            cmd_r = pickle.load(f)
            ppid_r = pickle.load(f)
    except FileNotFoundError:
        pass
    else:
        global _proc_cmd_records, _proc_ppid_records, _proc_pid_records
        _proc_cmd_records = cmd_r
        _proc_ppid_records = ppid_r

        rebooted: bool = uptime != int(UPTIME_EPOCH_SECS)

        for proc in _proc_cmd_records.values():
            for key in proc.pid_records:
                pid_record = proc.pid_records[key]
                if rebooted:
                    pid_record.live = False
                else:
                    _proc_pid_records[key] = proc

            if rebooted:
                do_clean_up(proc, initial_clean_up=True)

        print(f'Loaded dump: Proc (cmd): {len(_proc_cmd_records)}, '
              f'Proc (ppid): {len(_proc_ppid_records)}, '
              f'PID: {len(_proc_pid_records)}')


def parse_procfs() -> None:
    global _procfs_iter_count
    clean_up: bool = _procfs_iter_count % (10 / PROCFS_PARSE_DELAY_SECS) == 0
    save_data: bool = _procfs_iter_count % (300 / PROCFS_PARSE_DELAY_SECS) == 0
    _procfs_iter_count += 1

    for pid in _parser.get_pids():
        create_proc(pid, clean_up=clean_up)

    if clean_up:
        for proc in _proc_cmd_records.values():
            do_clean_up(proc)

        print_d2(f'Count: Proc (cmd): {len(_proc_cmd_records)}, '
                 f'Proc (ppid): {len(_proc_ppid_records)}, '
                 f'PID: {len(_proc_pid_records)}')

    if save_data:
        save_dump()
        print_d2(create_dump_msg())


def parse_procfs_locked() -> None:
    with _lists_lock:
        parse_procfs()


def handle_dead_pid(dp: DeadPid) -> None:
    # [] operator will throw KeyError if process is short-lived.
    if proc := _proc_pid_records.get(dp.pid_key):
        do_clean_up(proc, dead_pid=dp)
        return

    if dp.r_io == 0 and dp.w_io == 0:
        return

    # PPID can be 0
    if ppid_cmd := _parser.get_cmd(dp.ppid):
        ppid_key = str(dp.uid) + '|' + str(dp.gid) + '|' + ppid_cmd + '|' + dp.cmd
        ppid_key: str = hashlib.md5(ppid_key.encode()).hexdigest()

        if not (proc := _proc_ppid_records.get(ppid_key)):
            proc = Proc(dp.uid, dp.gid, f'[{dp.cmd}][{ppid_cmd}]')
            _proc_ppid_records[ppid_key] = proc
            print_d2(f'Creating proc (ppid): {proc.cmd}')
        else:
            print_d2(f'Creating PID (ppid): {proc.cmd}')

        proc.dead_pid_io.r_io += dp.r_io
        proc.dead_pid_io.w_io += dp.w_io

        proc.pid_count += 1
    elif dp.w_io > 0:
        print_d1(f'Quick killer: '
                 f'{dp.uid}.{dp.gid} '
                 f'{humansize(dp.w_io)} '
                 f'[{dp.cmd}]')


def handle_dead_pids() -> None:
    while True:
        if _terminated:
            print('Exiting', threading.current_thread().name)
            break

        try:
            events = _task_stats.get_events()
        except PidTaskStats.TaskStatsSocketClosed as e:
            print(f'Exiting {threading.current_thread().name}.', e)
            break

        with _lists_lock:
            for evt in events:
                if dp := _task_stats.parse_msg(evt):
                    handle_dead_pid(dp)


def handle_new_pid(pid: int) -> None:
    assert pid > 0

    with _lists_lock:
        try:
            create_proc(pid, is_nl=True)
        except PidTaskStats.TaskStatsSocketClosed as e:
            # This should not happen. Close ProcEvent socket before closing TaskStats socket.
            print(f'Exiting {threading.current_thread().name}.', e)
            # Force stop the thread.
            sys.exit()


def handle_new_pids():
    native_bind.start_proc_events_nat(handle_new_pid)
    print('Exiting', threading.current_thread().name)


class ClientCmd:
    CMD_GET_PROC_LIST: int = 0
    CMD_GET_QUICK_PROC_LIST: int = 2

    def __init__(self, cmd: int):
        self.cmd: int = cmd


def start_nng_server():
    while not _terminated:
        try:
            msg: pynng.Message = nng_server.recv_msg()
        except pynng.exceptions.Closed as e:
            print(f'Exiting {threading.current_thread().name}:', e)
            return

        try:
            cmd: ClientCmd = pickle.loads(msg.bytes)
        except pickle.UnpicklingError as e:
            print('Bad command received from client:', e)
            continue

        if not isinstance(cmd, ClientCmd):
            print(f'Bad command type "{type(cmd)}"')
            continue

        if cmd.cmd == ClientCmd.CMD_GET_PROC_LIST:
            with _lists_lock:
                lst = list(_proc_cmd_records.values())
            msg.pipe.send(pickle.dumps(lst))
        elif cmd.cmd == ClientCmd.CMD_GET_QUICK_PROC_LIST:
            with _lists_lock:
                lst = list(_proc_ppid_records.values())
            msg.pipe.send(pickle.dumps(lst))
        else:
            print(f'Bad command received from client: {cmd.cmd}')
            continue

    print('Exiting', threading.current_thread().name)


def _quit(*_):
    with _lists_lock:
        if sys.stdout.isatty():
            print('\r', end='')

        save_dump()
        print(create_dump_msg())

    nng_server.close()

    native_bind.stop_proc_events()
    _task_stats.close()

    global _terminated
    _terminated = True


def check_caps():
    # include <linux/capability.h>
    cap_net_admin = 1 << 12

    if _parser.get_eff_caps() & cap_net_admin == 0:
        print('cap_net_admin is required for netlink socket', file=sys.stderr)


def start_server():
    check_caps()

    for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM):
        signal.signal(sig, _quit)

    load_dumps()

    print('Starting command server...')
    threading.Thread(target=start_nng_server, name='NNGServer', daemon=False).start()

    threading.Thread(target=handle_new_pids, name='NewPidHandler', daemon=False).start()

    print('Starting dead PID handler...')
    threading.Thread(target=handle_dead_pids, name='DeadPidHandler', daemon=False).start()

    print('Watching procfs...')
    while True:
        if _terminated:
            print('Exiting', threading.current_thread().name)
            break

        try:
            parse_procfs_locked()
        except PidTaskStats.TaskStatsSocketClosed as e:
            print(f'Exiting {threading.current_thread().name}.', e)
            break
        else:
            time.sleep(PROCFS_PARSE_DELAY_SECS)


def start_client() -> None:
    def print_proc_list(proc_list: Iterable[Proc]) -> None:
        sorted_procs: list[Proc] = \
            sorted(proc_list, key=lambda pr: pr.get_w_io(), reverse=True)
        if not full_proc_list:
            del sorted_procs[10:]

        for p in sorted_procs:
            print(f'{p.pid_count} {p.uid}.{p.gid} {p.get_r_io(True)} {p.get_w_io(True)} {p.cmd}'[:_COLS])

    client = pynng.Req0(dial=NNG_SOCK_PATH, send_timeout=1000, recv_timeout=2000)

    print('Processes\n=========')
    client.send(pickle.dumps(ClientCmd(ClientCmd.CMD_GET_PROC_LIST)))
    print_proc_list(pickle.loads(client.recv()))

    print('\nQuick Processes\n===============')
    client.send(pickle.dumps(ClientCmd(ClientCmd.CMD_GET_QUICK_PROC_LIST)))
    print_proc_list(pickle.loads(client.recv()))

    client.close()


def get_opts():
    try:
        opts, args = getopt.getopt(sys.argv[1:], '', ['debug=', 'server', 'full'])
    except getopt.GetoptError as e:
        print(e)
        print(f'Usage:\n\t{os.path.basename(sys.argv[0])} [--debug=1|2] [--server] [--full]')
        sys.exit(1)

    if args:
        print('Unexpected arguments:', *args)
        sys.exit(1)

    for opt, val in opts:
        if opt == '--debug':
            if not val.isdecimal():
                print(f'{val} is not an integer')
                sys.exit(1)

            global DEBUG_LEVEL
            DEBUG_LEVEL = int(val)
        elif opt == '--server':
            global is_server
            is_server = True
        elif opt == '--full':
            global full_proc_list
            full_proc_list = True
        else:
            sys.exit(1)  # Should not happen.


if __name__ == '__main__':
    is_server: bool = False
    full_proc_list: bool = False
    get_opts()

    if is_server:
        if full_proc_list:
            print('--full option is for client only')
            sys.exit(1)

        _parser: ProcParser = ProcParser()
        _proc_cmd_records: dict[str, Proc] = {}
        _proc_ppid_records: dict[str, Proc] = {}
        _proc_pid_records: dict[str, Proc] = {}
        _procfs_iter_count: int = 0
        _task_stats: PidTaskStats = PidTaskStats()
        _terminated: bool = False
        _lists_lock: threading.Lock = threading.Lock()

        nng_server = pynng.Rep0(listen=NNG_SOCK_PATH, send_timeout=2000)

        start_server()
    else:
        start_client()
