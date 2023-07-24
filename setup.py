from Cython.Build import cythonize
from setuptools import Extension, setup

setup(
    ext_modules=cythonize(
        [
            Extension('mirfatif.io_watcher.proc_events', ['native/proc_events-bind.pyx']),
            Extension('mirfatif.io_watcher.task_stats', ['native/task_stats-bind.pyx'])
        ]
    )
)
