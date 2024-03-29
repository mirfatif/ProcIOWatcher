from libc.stdlib cimport EXIT_FAILURE

cdef extern from 'proc_events.c':
    # https://cython.readthedocs.io/en/stable/src/userguide/language_basics.html#error-return-values
    #
    # 'except EXIT_FAILURE' throws:
    #   'SystemError: <built-in function start_proc_events_nat> returned NULL without setting an exception'
    # So we handle it manually.
    cdef int start_proc_events(void (*cb)(int, int)) noexcept nogil
    cpdef void stop_proc_events() noexcept

cdef void proc_evt_cy_cb(int pid, int tid) noexcept nogil:
    with gil:
        global proc_evt_py_cb, proc_evt_py_cb_exc
        try:
            proc_evt_py_cb(pid, tid)
        except Exception as e:
            proc_evt_py_cb_exc = e
            stop_proc_events()

def start_proc_events_nat(cb_func):
    global proc_evt_py_cb, proc_evt_py_cb_exc
    proc_evt_py_cb = cb_func
    proc_evt_py_cb_exc = None

    with nogil:
        if start_proc_events(&proc_evt_cy_cb) == EXIT_FAILURE:
            raise OSError('Process event listener failed')

    if proc_evt_py_cb_exc:
        raise proc_evt_py_cb_exc
