#!/bin/sh
# Prints how many compilers the image build runs at once: one for every
# 2 GiB of the memory this machine has, at least one, and never more than
# it has processors. CARGO_BUILD_JOBS, when set, is printed as it is.
#
# The Dockerfile calls it. See the comment there for why.

if [ -n "$CARGO_BUILD_JOBS" ]; then
    echo "$CARGO_BUILD_JOBS"
    exit
fi
awk -v cpus="$(nproc)" '
    /^MemTotal:/ {
        jobs = int($2 / 2097152)
        if (jobs < 1) jobs = 1
        if (jobs > cpus) jobs = cpus
        print jobs
    }' /proc/meminfo
