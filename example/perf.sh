#!/bin/bash

cd "$(dirname "${0}")/../" || exit 1

PERF=perf
PCAP_FILE=$1

#https://stackoverflow.com/questions/74340680/perf-record-after-my-code-reaches-a-certain-point
#https://man7.org/linux/man-pages/man1/perf-record.1.html

ctl_dir=/tmp/

ctl_fifo=${ctl_dir}perf_ctl.fifo
test -p ${ctl_fifo} && unlink ${ctl_fifo}
mkfifo ${ctl_fifo}
exec {ctl_fd}<>${ctl_fifo}

ctl_ack_fifo=${ctl_dir}perf_ctl_ack.fifo
test -p ${ctl_ack_fifo} && unlink ${ctl_ack_fifo}
mkfifo ${ctl_ack_fifo}
exec {ctl_fd_ack}<>${ctl_ack_fifo}

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:./src/lib/
#--call-graph dwarf
PERF_CTL_FD=$ctl_fd PERF_CTL_ACK_FD=$ctl_fd_ack \
	taskset -c 4 \
	${PERF} record --delay=-1 --control fd:${ctl_fd},${ctl_fd_ack} --call-graph dwarf -- \
	./example/ndpiReader -i ${PCAP_FILE} --conf=./example/perf.conf

exec {ctl_fd_ack}>&-
unlink ${ctl_ack_fifo}

exec {ctl_fd}>&-
unlink ${ctl_fifo}

#
# Report
#

#${PERF} report #-d libndpi.so.5.1.0,libc.so.6
${PERF} report --call-graph --stdio -G
