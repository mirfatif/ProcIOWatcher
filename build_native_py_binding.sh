#!/bin/bash -e

trap 'rm -f native_bind.c' EXIT

#cproto -f1 proc_event_connector.c | grep -vE '/\*' | sed 's|;\s$||'

cython -3 native_bind.pyx -o native_bind.c
cc -shared -fPIC $(python3.10-config --includes) native_bind.c -o native_bind.so
strip -s -S --strip-unneeded -R=.eh_frame -R=.eh_frame_ptr -R .comment -R .note -R .note.gnu.gold-version \
	-R .note.gnu.build-id -R .note.gnu.property -R .note.ABI-tag native_bind.so
