# Linux Process I/O Watcher

Find out which processes have the highest disk I/O.

Run `io_watcher.py --server` in background (preferably as a `systemd` service). Then run `io_watcher.py` from terminal
to view collected stats.

```
~$ io_watcher.py -h

Usage:
	io_watcher.py [OPTIONS]

Find out which processes have the highest disk I/O.

Common Options:
	-h|--help                Show help
	--sock=<PATH>            Unix socket path (default: /tmp/io_watcher.py.sock)

Client Options:
	--max=all|<NUM>          Max no. of results (default: 10)
	--sort-by-read           Sort list by read I/O
	--old                    Include rotated files too (default: False)

Server Options:
	--server                 Run server
	--procfs-interval=<SEC>  /proc parse interval (default: 5)
	--dump-file=<PATH>       Dump file path (default: /home/irfan/io_watcher.py.dump)
	--dump-interval=<SEC>    Dump auto-save interval (default: 1800)
	--rotate=<MBs>           Rotate dump file if exceeds this size (default: 50 MB)
	--debug=1-3              Debug level (default: 0)

	Rotated Files:
		Old / archived / rotated dump files have numbers (1 to 10) appended to them with dot.
		Example: /home/irfan/io_watcher.py.dump.1

		Auto rotation will rename the oldest file if all numbers (1 to 10) are taken.
```

## Installation

Optional dependency: [`priv_exec`](https://github.com/mirfatif/priv_exec). Put the binary on your `$PATH`.

```
~$ export PYTHONUSERBASE=/opt/python_user_base
~$ export PATH=$PYTHONUSERBASE/bin:$PATH

~$ sudo mkdir -p $PYTHONUSERBASE
~$ sudo chown $(id -u) $PYTHONUSERBASE

~$ pip install --ignore-installed --upgrade pip
~$ pip install --upgrade "io_watcher @ git+https://github.com/mirfatif/ProcIOWatcher"

~$ sudo ln -s $PYTHONUSERBASE/lib/python3.*/site-packages/mirfatif/io_watcher/etc/systemd/system/io_watcher.service /etc/systemd/system/
~$ sudo systemctl enable io_watcher.service
~$ sudo systemctl start io_watcher.service

~$ io_watcher.py
```
