from libc.stdlib cimport EXIT_FAILURE

cdef extern from 'task_stats.c':
    struct tid_stats:
        int ppid
        int tid
        int uid
        int gid
        long long btime
        long long read_bytes
        long long write_bytes
        char *comm

    cdef int start_task_stats(void (*cb)(tid_stats)) noexcept nogil
    cdef int get_tid_stats(int tid, void (*cb)(tid_stats)) noexcept nogil
    cpdef void stop_task_stats() noexcept

cdef void start_task_stats_cy_cb(tid_stats ts) noexcept nogil:
    with gil:
        global start_task_stats_py_cb, start_task_stats_py_cb_exc
        try:
            start_task_stats_py_cb(ts)
        except Exception as e:
            start_task_stats_py_cb_exc = e
            stop_task_stats()

def start_task_stats_nat(cb_func):
    global start_task_stats_py_cb, start_task_stats_py_cb_exc
    start_task_stats_py_cb = cb_func
    start_task_stats_py_cb_exc =None

    with nogil:
        if start_task_stats(&start_task_stats_cy_cb) == EXIT_FAILURE:
            raise OSError('Task stats listener failed')

    if start_task_stats_py_cb_exc:
        raise start_task_stats_py_cb_exc

cdef void get_tid_stats_cy_cb(tid_stats ts) noexcept nogil:
    with gil:
        global get_tid_stats_py_cb, get_tid_stats_py_cb_exc
        try:
            get_tid_stats_py_cb(ts)
        except Exception as e:
            get_tid_stats_py_cb_exc = e

def get_tid_stats_nat(tid, cb_func):
    global get_tid_stats_py_cb, get_tid_stats_py_cb_exc
    get_tid_stats_py_cb = cb_func
    get_tid_stats_py_cb_exc = None

    cdef int t = tid
    with nogil:
        if get_tid_stats(t, &get_tid_stats_cy_cb) == EXIT_FAILURE:
            raise OSError('Get TID stats failed')

    if get_tid_stats_py_cb_exc:
        raise get_tid_stats_py_cb_exc
