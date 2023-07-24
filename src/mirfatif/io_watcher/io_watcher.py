#!/usr/bin/python

import builtins
import copy
import datetime
import enum
import functools
import getopt
import hashlib
import inspect
import os
import pickle
import queue
import signal
import stat
import sys
import threading
import time
import traceback
from collections import namedtuple
from dataclasses import dataclass, field
from typing import Callable, Iterable, Iterator

import mirfatif.io_watcher.proc_events as proc_events
import mirfatif.io_watcher.task_stats as task_stats
import pynng

NNG_SOCK_PATH = f'/tmp/{os.path.basename(sys.argv[0])}.sock'
COLS: int = os.get_terminal_size().columns if sys.stdout.isatty() else 10000

# Server options
DUMP_FILE_PATH = f'{os.getenv("HOME") or "/var/log/"}/{os.path.basename(sys.argv[0])}.dump'
DUMP_FILE_SIZE = 50  # MB
DUMP_SAVE_INTERVAL = 1800  # Seconds
PROCFS_PARSE_INTERVAL = 5  # Seconds
DEBUG_LEVEL = 0

# Client options
MAX_RESULTS = 10
INC_OLD_DUMPS = False

UPTIME_EPOCH_MS: float = (time.time_ns() - time.clock_gettime_ns(time.CLOCK_BOOTTIME)) / 1000000

Tid = namedtuple('Tid', ['pid', 'tid'])

DeadTidStats = namedtuple(
    'DeadTidStats',
    ['ppid', 'tid', 'uid', 'gid', 'btime', 'read_bytes', 'write_bytes', 'comm']
)


class ProcParser:
    JIFFY_MILLI_SECS = 1000 / os.sysconf('SC_CLK_TCK')

    @staticmethod
    def get_tid_list() -> Iterator[Tid]:
        for pid in os.listdir('/proc'):
            if pid.isdecimal():
                pid = int(pid)
                try:
                    for tid in os.listdir(f'/proc/{pid}/task'):
                        yield Tid(pid, int(tid))
                except FileNotFoundError:
                    pass

    @staticmethod
    def _read_file(pid: int, file: str, lines: bool = False) -> str | list[str] | None:
        try:
            with open(os.path.join('/proc', str(pid), file)) as f:
                return f.readlines() if lines else f.read()
        except (FileNotFoundError, ProcessLookupError):
            pass
            return None

    @staticmethod
    def _get_st_line_val(st_line: str) -> str:
        return st_line[st_line.index('\t') + 1:-1]

    @staticmethod
    def _str_to_uid_gid(st_line: str) -> int:
        return int(st_line[(i := st_line.index('\t') + 1):st_line.index('\t', i)])

    @staticmethod
    def get_status(pid: int) -> tuple[int, int, int] | None:
        if not (status := ProcParser._read_file(pid, 'status', True)):
            return None

        ppid = uid = gid = None

        for line in status:
            if line.startswith('PPid:'):
                ppid = int(ProcParser._get_st_line_val(line))
            elif line.startswith('Uid:'):
                uid = ProcParser._str_to_uid_gid(line)
            elif line.startswith('Gid:'):
                gid = ProcParser._str_to_uid_gid(line)

            if ppid and uid and gid:
                break

        assert ppid is not None and uid is not None and gid is not None

        return ppid, uid, gid

    @staticmethod
    def get_cmd(pid: int) -> str | None:
        if not (cmd := ProcParser._read_file(pid, 'cmdline')):
            return None
        else:
            return cmd.replace('\0', ' ').strip()

    @staticmethod
    def _get_io_val(io_line: str) -> int:
        return int(io_line[io_line.index(' ') + 1:-1])

    @staticmethod
    # '/proc/[pid]/io' includes the I/O of live threads, dead threads, and dead children.
    # So we cannot use '/proc/[tid]/io' for main thread (TGID; where PID == TID).
    def get_io(pid: int, tid: int = None) -> tuple[int, int] | None:
        if not (io := ProcParser._read_file(pid, f'task/{tid}/io' if tid else 'io', True)):
            return None

        r_io = w_io = None

        for line in io:
            if line.startswith('read_bytes: '):
                r_io = ProcParser._get_io_val(line)
            elif line.startswith('write_bytes: '):
                w_io = ProcParser._get_io_val(line)

            if r_io and w_io:
                break

        assert r_io is not None and w_io is not None

        return r_io, w_io

    @staticmethod
    # Seconds since epoch.
    def get_start_time(pid: int) -> int | None:
        if not (st := ProcParser._read_file(pid, 'stat')):
            return None

        # Jump to 22nd field
        i: int = st.index(')') + 1
        for _ in range(20):
            i = st.index(' ', i) + 1

        age_since_boot_ms = float(st[i:st.index(' ', i)]) * ProcParser.JIFFY_MILLI_SECS
        return round((UPTIME_EPOCH_MS + age_since_boot_ms) / 1000)

    @staticmethod
    def is_live(pid: int, start_time: int) -> bool:
        t = ProcParser.get_start_time(pid)
        return t and adjust_start_time(t) == adjust_start_time(start_time)

    @staticmethod
    def get_eff_caps(pid: int = os.getpid()) -> int | None:
        if not (status := ProcParser._read_file(pid, 'status', True)):
            return None

        eff_caps = None

        for line in status:
            if line.startswith('CapEff:'):
                eff_caps = int(ProcParser._get_st_line_val(line), 16)
                break

        return eff_caps


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


class Proc:
    @dataclass(slots=True)
    class TidIO:
        r_io: int
        w_io: int

    @dataclass(slots=True)
    class TidRecord(TidIO):
        tid: int
        start_time: int

    @dataclass(slots=True)
    class DeadTidRecord(TidIO):
        count: int

    def __init__(self, uid: int, gid: int, cmd: str):
        self.uid = uid
        self.gid = gid

        # PID's cmdline. Or TID's comm + PPID's cmdline
        self.cmd = cmd

        # Key: TID + start_time
        self.tid_records: dict[str, Proc.TidRecord] = {}

        self.dead_tid_record = self.DeadTidRecord(0, 0, 0)


class Thread(threading.Thread):
    def __init__(self, target: Callable, name=None, daemon=False):
        super(Thread, self).__init__(target=Thread._run_target, args=[target], name=name, daemon=daemon)

    @staticmethod
    def _run_target(func: Callable):
        print(f'Starting thread {threading.current_thread().name}...')
        Thread.run_target(func)

    @staticmethod
    def run_target(func: Callable):
        if threading.current_thread() is threading.main_thread():
            sys.excepthook = Thread._handle_uncaught_err
        else:
            threading.excepthook = lambda args: Thread._handle_uncaught_err(*args[:-1])

        func()

        print(f'Exiting {threading.current_thread().name}...')

    @staticmethod
    def _handle_uncaught_err(err_type, value, tb):
        print_err(f'Uncaught exception in thread: {threading.current_thread().name}:')
        traceback.print_exception(err_type, value, tb)
        kill_me()


# A blocking queue which can be unblocked anytime from other threads.
class TidQueue:
    # Use PriorityQueue to give preference to TIDs from fork() events and /proc parsing
    # as they may contain a new TID which is required to identify a dead TID.
    class ItemType(enum.Flag):
        NEW = enum.auto()  # Coming from fork() proc events
        PROCFS = enum.auto()  # Coming from /proc parsing
        DEAD = enum.auto()  # Coming from task stats

    @dataclass(slots=True, order=True)
    class PrioritizedItem:
        priority: int
        item: Tid | DeadTidStats = field(compare=False)

    pri_new: int
    pri_procfs: int
    pri_dead: int

    def _reset_priority(self):
        self.pri_new = 0
        self.pri_procfs = 10000000
        self.pri_dead = 2 * self.pri_procfs

    # Items in PriorityQueue with same priority are not arranged by
    # insert order. So we keep them all in-order using priority.
    def _get_priority(self, item_type: ItemType) -> int:
        if item_type is self.ItemType.NEW:
            self.pri_new += 1
            return self.pri_new

        if item_type is self.ItemType.PROCFS:
            self.pri_procfs += 1
            return self.pri_procfs

        self.pri_dead += 1
        return self.pri_dead

    def __init__(self):
        self.queue = queue.PriorityQueue()
        self.lock = threading.Lock()
        self.waiter = threading.Condition(self.lock)
        self.terminated = False
        self._reset_priority()

    def put(self, item_type: ItemType, item: Tid | DeadTidStats, print_msg: bool = True) -> None:
        with self.waiter:
            if print_msg:
                print_d2(f'Adding to queue: {item}')
            self.queue.put(self.PrioritizedItem(self._get_priority(item_type), item))
            self.waiter.notify()

            if self.empty():
                self._reset_priority()

    def empty(self) -> bool:
        return self.queue.empty()

    def get(self) -> Tid | DeadTidStats | None:
        with self.waiter:
            while not self.terminated and self.empty():
                self.waiter.wait()

            return None if self.terminated else self.queue.get_nowait().item

    # Return from get() if blocked.
    def end(self):
        self.terminated = True
        with self.waiter:
            self.waiter.notify()


class ClientRequest:
    def __init__(self):
        self.max_results: int = MAX_RESULTS
        self.sort_by_read: bool = False
        self.include_old_dumps: bool = INC_OLD_DUMPS


@dataclass(slots=True)
class ClientData:
    start_time: float
    file_count: int
    proc_list: list[Proc]
    quick_proc_list: list[Proc] | None


def print_d(msg: str, level: int):
    if debug_level >= level:
        print(msg[:COLS])


def print_d1(msg: str):
    print_d(msg, 1)


def print_d2(msg: str):
    print_d(msg, 2)


def print_d3(msg: str):
    print_d(msg, 3)


def print_exc_line():
    etype, value, tb = sys.exc_info()
    print(''.join(traceback.format_exception_only(etype, value)), file=sys.stderr, end='')


def print_exc_line_thread(lineno: int = None):
    if lineno:
        print_err(f'line {lineno}: '
                  f'Exception in {threading.current_thread().name}: ', no_newline=True)
        print_exc_line()
    else:
        print_err(f'Exception in {threading.current_thread().name}')
        traceback.print_exc()


def print_err(msg: str, no_newline: bool = False):
    end = '\n'
    if no_newline:
        end = ''

    print(msg, file=sys.stderr, end=end)


def to_str(lst: list, joiner: str = ' '):
    return joiner.join(str(s) for s in lst)


def cleanup_dead_tid_record(
        proc: Proc,
        tid: int,
        start_time: int,
        r_io: int,
        w_io: int,
        key: str,
        remove_global_tid_record: bool = True
):
    proc.dead_tid_record.r_io += r_io
    proc.dead_tid_record.w_io += w_io

    proc.dead_tid_record.count += 1

    del proc.tid_records[key]
    if remove_global_tid_record:
        del tid_records[key]

    print_d2(f'Removing dead TID: {tid}, start time: {start_time}, cmd: {proc.cmd}')


def cleanup_proc(
        records: dict[str, Proc],
        proc_key: str,
        proc: Proc,
        force: bool = False,
        remove_global_tid_record: bool = True
):
    for key in list(proc.tid_records):
        tr: Proc.TidRecord = proc.tid_records[key]
        if force or not ProcParser.is_live(tr.tid, tr.start_time):
            cleanup_dead_tid_record(proc, tr.tid, tr.start_time, tr.r_io, tr.w_io, key, remove_global_tid_record)

    if not len(proc.tid_records) and not proc.dead_tid_record.r_io and not proc.dead_tid_record.w_io:
        print_d2(f'Removing empty proc: {proc.uid}.{proc.gid} {proc.cmd}')
        del records[proc_key]


def save_dump(print_msg: bool = False):
    for key, proc in proc_records.copy().items():
        cleanup_proc(proc_records, key, proc)

    with open(f'{dump_file_path}.tmp', 'wb') as f:
        pickle.dump(dump_start_time, f)
        pickle.dump(int(UPTIME_EPOCH_MS / 1000), f)
        pickle.dump(proc_records, f)
        pickle.dump(quick_proc_records, f)

    os.rename(f'{dump_file_path}.tmp', dump_file_path)

    if print_msg:
        print(f'Dumped: Proc: {len(proc_records)} (with {len(tid_records)} TID records), '
              f'Quick Proc: {len(quick_proc_records)}')


def load_dump_file(file: str) -> tuple[float, int, dict[str, Proc], dict[str, Proc]] | None:
    if not os.path.isfile(file):
        return None

    try:
        with open(file, 'rb') as f:
            return pickle.load(f), pickle.load(f), pickle.load(f), pickle.load(f)
    except FileNotFoundError:
        return None
    except pickle.UnpicklingError:
        print_err(f'Failed to load dump file {file}')
        return None


def load_dumps():
    if not (dump := load_dump_file(dump_file_path)):
        return

    global dump_start_time, proc_records, quick_proc_records, tid_records
    dump_start_time = dump[0]
    proc_records = dump[2]
    quick_proc_records = dump[3]

    uptime: int = dump[1]
    rebooted: bool = uptime != int(UPTIME_EPOCH_MS / 1000)
    rotate: bool = \
        rebooted and \
        os.path.isfile(dump_file_path) and \
        os.path.getsize(dump_file_path) >= dump_file_size * 1000 * 1000

    for proc_key, proc in proc_records.copy().items():
        for key in proc.tid_records:
            tid_records[key] = proc

        cleanup_proc(proc_records, proc_key, proc, rebooted or rotate)

    print(f'Loaded dump: Proc: {len(proc_records)} (with {len(tid_records)} TID records), '
          f'Quick Proc: {len(quick_proc_records)}')

    if not rotate:
        return

    slot = None

    for i in range(1, 10):
        rotated_file = f'{dump_file_path}.{i}'
        if not os.path.exists(rotated_file):
            slot = rotated_file
            break

    if not slot:
        ts: float = 0
        for i in range(1, 10):
            rotated_file = f'{dump_file_path}.{i}'
            if not (dump := load_dump_file(rotated_file)):
                slot = rotated_file
                break
            elif ts == 0 or ts < dump[0]:
                ts = dump[0]
                slot = rotated_file

    if os.path.exists(slot):
        os.rename(
            slot,
            f'{slot}_{datetime.datetime.fromtimestamp(time.time()).strftime("%d-%m-%y_%H-%M-%S")}'
        )

    os.rename(dump_file_path, slot)
    print(f'Rotated {dump_file_path} to {slot}')

    dump_start_time = time.time()

    proc_records.clear()
    quick_proc_records.clear()
    tid_records.clear()


def parse_procfs() -> None:
    count: int = 0
    for tid in ProcParser.get_tid_list():
        count += 1
        tid_queue.put(TidQueue.ItemType.PROCFS, tid, False)

    print_d2(f'Added {count} TIDs to queue')

    global last_dump_ts

    if last_dump_ts + dump_save_interval > time.time():
        return

    with records_lock:
        save_dump(debug_level >= 2)
        last_dump_ts = time.time()


def start_procfs_parse_loop():
    while not terminated.is_set():
        parse_procfs()
        terminated.wait(procfs_parse_interval)


def create_hashed_key(lst: list) -> str:
    return hashlib.md5(to_str(lst, '|').encode()).hexdigest()


# 'btime' in kernel's taskstats struct does not match with 'start_time'
# in /proc/[pid]/task/[tid]/stat.
# So we assume that no thread is created with same number within 10 seconds.
def adjust_start_time(start_time: int) -> int:
    return round(start_time / 10)


def create_tid_record_key(tid: int, start_time: int) -> str:
    return str(tid) + '|' + str(adjust_start_time(start_time))


def update_tid_record(tid: int, start_time: int, r_io: int, w_io: int, dead: bool = False) -> bool:
    key: str = create_tid_record_key(tid, start_time)

    if not (proc := tid_records.get(key)):
        return False

    tid_record = proc.tid_records[key]

    if dead:
        cleanup_dead_tid_record(proc, tid, start_time, r_io, w_io, key)
        if start_time != tid_record.start_time:
            print_d3(f'Time diff: {tid_record.start_time - start_time}, '
                     f'stat: {tid_record.start_time}, '
                     f'task_stats: {start_time}')
    elif tid_record.r_io != r_io or tid_record.w_io != w_io:
        tid_record.r_io = r_io
        tid_record.w_io = w_io

        print_d2(f'Updating TID: {tid}, start time: {start_time}, cmd: {proc.cmd}')

    return True


def run_queue_parser():
    item: Tid | DeadTidStats
    key: str

    proc: Proc
    tid_record: Proc.TidRecord

    ppid: int
    pid: int
    tid: int
    uid: int
    gid: int
    r_io: int
    w_io: int
    cmd: str
    comm: str
    start_time: int
    r_w_io: tuple[int, int]
    ppid_uid_gid: tuple[int, int, int]

    while item := tid_queue.get():
        with records_lock:
            if isinstance(item, DeadTidStats):
                ppid = item.ppid
                tid = item.tid
                uid = item.uid
                gid = item.gid
                start_time = item.btime
                r_io = item.read_bytes
                w_io = item.write_bytes
                comm = item.comm.decode()

                if ppid == 2:
                    continue

                # Remove the dead TID record even if IO is zero.
                if update_tid_record(tid, start_time, r_io, w_io, True):
                    continue

                if not r_io and not w_io:
                    continue

                if not (cmd := ProcParser.get_cmd(ppid)):
                    cmd = 'DEAD'

                key = create_hashed_key([uid, gid, comm, cmd])

                if not (proc := quick_proc_records.get(key)):
                    proc = Proc(uid, gid, f'[{comm}] [{cmd}]')
                    quick_proc_records[key] = proc
                    print_d2(f'Creating proc (ppid): {proc.cmd}')
                else:
                    print_d2(f'Adding TID: {tid}, start time: {start_time} to proc: {proc.cmd}')

                proc.dead_tid_record.r_io += r_io
                proc.dead_tid_record.w_io += w_io

                proc.dead_tid_record.count += 1

                continue

            pid = item.pid
            tid = item.tid

            if pid == 2:
                continue

            start_time = ProcParser.get_start_time(tid)
            r_w_io = ProcParser.get_io(pid, tid)
            ppid_uid_gid = ProcParser.get_status(tid)
            cmd = ProcParser.get_cmd(tid)

            if not start_time or not r_w_io:
                continue

            # Create the TID record even if IO is zero.
            # It might be needed later when TID dies.
            r_io, w_io = r_w_io

            if update_tid_record(tid, start_time, r_io, w_io):
                continue

            if not ppid_uid_gid or not cmd:
                continue

            ppid, uid, gid = ppid_uid_gid

            if ppid == 2:
                continue

            key = create_hashed_key([uid, gid, cmd])

            if not (proc := proc_records.get(key)):
                proc = Proc(uid, gid, cmd)
                proc_records[key] = proc

                print_d2(f'Creating proc: {cmd}')
            else:
                print_d2(f'Adding TID: {tid}, start time: {start_time} to proc: {cmd}')

            tid_record = Proc.TidRecord(r_io, w_io, tid, start_time)
            key = create_tid_record_key(tid, start_time)
            proc.tid_records[key] = tid_record
            tid_records[key] = proc


def start_server():
    for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM):
        signal.signal(sig, kill_me)

    load_dumps()

    # Put all live TIDs in queue before receiving dead TID stats.
    parse_procfs()

    global nng_server
    nng_server = pynng.Rep0(listen=ipc_address, send_timeout=2000)
    os.chmod(
        nng_sock_path,
        stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH | stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH
    )

    Thread(
        target=start_nng_server,
        name='NNGServer'
    ).start()

    Thread(
        target=lambda: proc_events.start_proc_events_nat(
            lambda pid, tid: tid_queue.put(TidQueue.ItemType.NEW, Tid(pid, tid))),
        name='TidHandler'
    ).start()

    Thread(
        target=lambda: task_stats.start_task_stats_nat(
            lambda dead_tid_stats: tid_queue.put(TidQueue.ItemType.DEAD, DeadTidStats(**dead_tid_stats))),
        name='DeadTidHandler'
    ).start()

    Thread(
        target=run_queue_parser,
        name='QueueParser'
    ).start()

    print(f'Watching procfs on {threading.current_thread().name}...')
    Thread.run_target(start_procfs_parse_loop)


def kill_me(sig: int = None, *_):
    if sys.stdout.isatty():
        print(f'\r')

    if sig:
        print(f'{signal.strsignal(sig)}, exiting...')
    else:
        print('Exiting...')

    # NNG Server and procfs parser depends on it.
    terminated.set()

    # poll() in C receives EINTR only if running on main
    # thread. So we need to exit the loop manually.
    proc_events.stop_proc_events()
    task_stats.stop_task_stats()

    if nng_server:
        try:
            nng_server.close()
        except (Exception,):
            print_exc_line_thread(inspect.currentframe().f_lineno)

    if tid_queue:
        try:
            # Return from blocking get().
            tid_queue.end()
        except (Exception,):
            print_exc_line_thread(inspect.currentframe().f_lineno)

    with records_lock:
        try:
            save_dump(True)
        except (Exception,):
            print_exc_line_thread(inspect.currentframe().f_lineno)


def create_client_data(req: ClientRequest) -> ClientData:
    with records_lock:
        tmp_proc_records = copy.deepcopy(proc_records)
        tmp_quick_proc_records = copy.deepcopy(quick_proc_records)

    key: str
    proc1: Proc
    proc2: Proc

    file_count: int = 1
    start_time: float = dump_start_time

    for key, proc1 in tmp_proc_records.copy().items():
        cleanup_proc(tmp_proc_records, key, proc1, True, False)

    if req.include_old_dumps:
        d_start_time: float
        d_proc_records: dict[str, Proc]
        d_quick_proc_records: dict[str, Proc]

        def merge_proc(p1: Proc, p2: Proc):
            p1.dead_tid_record.r_io += p2.dead_tid_record.r_io
            p1.dead_tid_record.w_io += p2.dead_tid_record.w_io
            p1.dead_tid_record.count += p2.dead_tid_record.count

        for i in range(1, 10):
            if not (dump := load_dump_file(f'{dump_file_path}.{i}')):
                continue

            d_start_time = dump[0]
            d_proc_records = dump[2]
            d_quick_proc_records = dump[3]

            file_count += 1

            if d_start_time < start_time:
                start_time = d_start_time

            for key, proc2 in d_proc_records.copy().items():
                cleanup_proc(d_proc_records, key, proc2, True, False)

                if proc1 := tmp_proc_records.get(key):
                    merge_proc(proc1, proc2)
                else:
                    tmp_proc_records[key] = proc2

            for key, proc2 in d_quick_proc_records.copy().items():
                cleanup_proc(d_quick_proc_records, key, proc2, True, False)

                if proc1 := tmp_quick_proc_records.get(key):
                    merge_proc(proc1, proc2)
                else:
                    tmp_quick_proc_records[key] = proc2

    def finalize_list(lst: Iterable[Proc]) -> list[Proc]:
        def sort_key(pr: Proc):
            return pr.dead_tid_record.r_io if req.sort_by_read else pr.dead_tid_record.w_io

        sorted_procs: list[Proc] = sorted(lst, key=sort_key, reverse=True)
        del sorted_procs[req.max_results:]
        return sorted_procs

    data: ClientData = ClientData(
        start_time,
        file_count,
        finalize_list(tmp_proc_records.values()),
        finalize_list(tmp_quick_proc_records.values())
    )

    return data


def start_nng_server():
    while not terminated.is_set():
        try:
            msg: pynng.Message = nng_server.recv_msg()
        except pynng.exceptions.Closed:
            if not terminated.is_set():
                print_exc_line_thread(inspect.currentframe().f_lineno)
            return

        try:
            req: ClientRequest = pickle.loads(msg.bytes)
        except pickle.UnpicklingError:
            print_err('Bad request received from client: ', no_newline=True)
            print_exc_line()
            continue

        if not isinstance(req, ClientRequest):
            print_err(f'Bad request type "{type(req)}"')
            continue

        msg.pipe.send(pickle.dumps(create_client_data(req)))


def run_client() -> None:
    if not os.path.exists(nng_sock_path):
        print_err('Server not running')
        print_usage()
        sys.exit(1)

    def print_line(count: int, ch: str = '='):
        print(''.join([ch for _ in range(count)]))

    def print_proc_list(proc_list: Iterable[Proc], has_parent: bool = False) -> None:
        cmd = 'CMD'
        wid = 42
        if has_parent:
            cmd = '[COMM] [PARENT]'
            wid = 54

        print('{:<5} {:<12} {:>8} {:>8}   {}'.format('CNT', 'UID.GID', 'READ', 'WRITE', cmd))
        print_line(wid, '-')

        for p in proc_list:
            tid_count = len(p.tid_records) + p.dead_tid_record.count
            cmd = p.cmd.replace('\n', ' ')
            print(f'{tid_count:<5} {f"{p.uid}.{p.gid}":<12} '
                  f'{HumanSize.do(p.dead_tid_record.r_io):>8} '
                  f'{HumanSize.do(p.dead_tid_record.w_io):>8}   '
                  f'{cmd}'[:COLS])

    client = pynng.Req0(dial=ipc_address, send_timeout=1000, recv_timeout=30000)

    try:
        client.send(pickle.dumps(client_req))
        data: ClientData = pickle.loads(client.recv())
    finally:
        client.close()

    class Color:
        GRAY = '\x1b[38;5;74m'
        BOLD = '\033[1m'
        END = '\033[0m'

    print(f'{Color.BOLD}{Color.GRAY}PROCESS I/O STATS{Color.END}')

    print(f'\n{Color.BOLD}Since:{Color.END}',
          datetime.datetime.fromtimestamp(data.start_time).strftime("%d-%b-%y %I:%M %p"))

    print(f'\n{Color.BOLD}Dumped files:{Color.END} {data.file_count}')

    print(f'\n{Color.BOLD}{Color.GRAY}Processes{Color.END}')
    print_line(9)
    print_proc_list(data.proc_list)

    if data.quick_proc_list:
        print(f'\n{Color.BOLD}{Color.GRAY}Quick Processes{Color.END}')
        print_line(15)
        print_proc_list(data.quick_proc_list, True)


def print_usage():
    print(f'\nUsage:\n\t{os.path.basename(sys.argv[0])} [OPTIONS]')
    print(f'\nFind out which processes have the highest disk I/O.')

    print(f'\nCommon Options:')
    print(f'\t-h|--help                Show help')
    print(f'\t--sock=<PATH>            Unix socket path (default: {NNG_SOCK_PATH})')

    print(f'\nClient Options:')
    print(f'\t--max=all|<NUM>          Max no. of results (default: {MAX_RESULTS})')
    print(f'\t--sort-by-read           Sort list by read I/O')
    print(f'\t--old                    Include rotated files too (default: {INC_OLD_DUMPS})')

    print(f'\nServer Options:')
    print(f'\t--server                 Run server')
    print(f'\t--procfs-interval=<SEC>  /proc parse interval (default: {PROCFS_PARSE_INTERVAL})')
    print(f'\t--dump-file=<PATH>       Dump file path (default: {DUMP_FILE_PATH})')
    print(f'\t--dump-interval=<SEC>    Dump auto-save interval (default: {DUMP_SAVE_INTERVAL})')
    print(f'\t--rotate=<MBs>           Rotate dump file if exceeds this size (default: {DUMP_FILE_SIZE} MB)')
    print(f'\t--debug=1-3              Debug level (default: {DEBUG_LEVEL})')

    print('\n\tRotated Files:')
    print(f'\t\tOld / archived / rotated dump files have numbers (1 to 10) appended to them with dot.')
    print(f'\t\tExample: {DUMP_FILE_PATH}.1')
    print(f'\n\t\tAuto rotation will rename the oldest file if all numbers (1 to 10) are taken.')

    print()


def get_opts():
    opt_help: str = 'help'
    opt_socket: str = 'sock'

    # Client
    opt_max_res: str = 'max'
    opt_sort_read: str = 'sort-by-read'
    opt_old_dumps: str = 'old'

    # Server
    opt_server: str = 'server'
    opt_procfs_interval: str = 'procfs-interval'
    opt_dump_file: str = 'dump-file'
    opt_dump_interval: str = 'dump-interval'
    opt_rotate_size: str = 'rotate'
    opt_debug: str = 'debug'

    try:
        opts, args = getopt.getopt(
            sys.argv[1:],
            'h',
            [
                opt_help,
                f'{opt_socket}=',

                f'{opt_max_res}=',
                f'{opt_sort_read}',
                f'{opt_old_dumps}',

                opt_server,
                f'{opt_procfs_interval}=',
                f'{opt_dump_file}=',
                f'{opt_dump_interval}=',
                f'{opt_rotate_size}=',
                f'{opt_debug}='
            ])
    except getopt.GetoptError:
        print_exc_line()
        print_usage()
        sys.exit(1)

    if args:
        print_err(f'Unexpected arguments: {to_str(args)}')
        sys.exit(1)

    global nng_sock_path, client_req
    global dump_file_path, dump_save_interval, dump_file_size, procfs_parse_interval, debug_level

    if not (f'--{opt_server}', '') in opts:
        client_req = ClientRequest()

    def assert_client(option: str):
        if not client_req:
            print_err(f'{option} is mutually exclusive with --{opt_server}')
            sys.exit(1)

    def assert_server(option: str):
        if client_req:
            print_err(f'{option} can only be used with --{opt_server}')
            sys.exit(1)

    def assert_integer(num: str):
        if not num.isdecimal():
            print_err(f'"{num}" is not an integer')
            sys.exit(1)

    for opt, val in opts:
        if opt == '-h' or opt == f'--{opt_help}':
            print_usage()
            sys.exit(0)
        elif opt == f'--{opt_socket}':
            nng_sock_path = val

        elif opt == f'--{opt_max_res}':
            assert_client(opt)
            if val.startswith('all'):
                client_req.max_results = 100000
            else:
                assert_integer(val)
                client_req.max_results = int(val)
        elif opt == f'--{opt_sort_read}':
            assert_client(opt)
            client_req.sort_by_read = True
        elif opt == f'--{opt_old_dumps}':
            assert_client(opt)
            client_req.include_old_dumps = True

        elif opt == f'--{opt_server}':
            pass
        elif opt == f'--{opt_procfs_interval}':
            assert_server(opt)
            assert_integer(val)
            procfs_parse_interval = int(val)
        elif opt == f'--{opt_dump_file}':
            assert_server(opt)
            dump_file_path = val
        elif opt == f'--{opt_dump_interval}':
            assert_server(opt)
            assert_integer(val)
            dump_save_interval = int(val)
        elif opt == f'--{opt_rotate_size}':
            assert_server(opt)
            assert_integer(val)
            dump_file_size = int(val)
        elif opt == f'--{opt_debug}':
            assert_server(opt)
            assert_integer(val)
            debug_level = int(val)

        else:
            sys.exit(1)  # Should not happen.


def check_caps():
    # include <linux/capability.h>
    cap_net_admin = 1 << 12
    cap_sys_ptrace = 1 << 19
    cap_dac_read_search = 1 << 2

    eff_caps: int = ProcParser.get_eff_caps()

    if not eff_caps or (
            eff_caps & cap_net_admin == 0 or
            eff_caps & cap_sys_ptrace == 0 or
            eff_caps & cap_dac_read_search == 0
    ):
        print_err('cap_net_admin is required for netlink socket, '
                  'cap_sys_ptrace and cap_dac_read_search to read process IO.')

        if sys.stdin.isatty() and sys.stdout.isatty():
            print_err(' Restarting...')
            os.execvp(
                'priv_exec',
                [
                    'priv_exec',
                    '-kHOME,PYTHONUSERBASE',
                    '--caps=net_admin,sys_ptrace,dac_read_search',
                    '--',
                    'python3',
                    *sys.argv
                ]
            )
            print_err('Failed to execute priv_exec')

        print_err('Run with root')
        sys.exit(1)


# Builtin print() throws BrokenPipeError on SIGINT when stdout is redirected to pipe.
def override_print():
    if sys.stdout.isatty():
        return

    def _print(*args, **kwargs):
        try:
            builtins.print(*args, **kwargs, flush=True)
        except BrokenPipeError:
            global print
            print = functools.partial(builtins.print, flush=True, file=sys.stderr)

    global print
    print = _print


def main():
    global nng_sock_path, ipc_address

    get_opts()

    # Better if it's abstract.
    ipc_address = f'ipc://{nng_sock_path}'

    if client_req:
        run_client()
        sys.exit()

    check_caps()
    override_print()
    start_server()


################
# GLOBAL STATE #
################

nng_sock_path: str = NNG_SOCK_PATH

# Server options
procfs_parse_interval: int = PROCFS_PARSE_INTERVAL
dump_file_path = DUMP_FILE_PATH
dump_save_interval: int = DUMP_SAVE_INTERVAL
dump_file_size = DUMP_FILE_SIZE
debug_level: int = DEBUG_LEVEL

# Client options
client_req: ClientRequest | None = None

nng_server: pynng.Socket
ipc_address: str

tid_queue = TidQueue()

# We create a Proc record for each unique combination of UID, GID and cmdline.
# Key: UID + GID + PID's cmdline
proc_records: dict[str, Proc] = {}

# Quickly died TIDs before we could read PID's cmdline
# Key: UID + GID + PPID's cmdline + TID's comm
quick_proc_records: dict[str, Proc] = {}

# Key: TID + start_time
# All TidRecords in complete Proc list. Same records as in proc_records.
tid_records: dict[str, Proc] = {}

records_lock: threading.Lock = threading.Lock()

# /proc parser waits on this lock.
terminated = threading.Event()

dump_start_time: float = time.time()
last_dump_ts: float = 0

print = builtins.print

if __name__ == '__main__':
    main()
