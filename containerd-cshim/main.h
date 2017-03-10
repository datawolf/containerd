/*
 * Copyright 2017 HUAWEI
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __MAIN_H
#define __MAIN_H

#include <stdbool.h>

struct process_state {
	bool terminal;
	bool exec;
	char *containerd_stdin;
	char *containerd_stdout;
	char *containerd_stderr;
	char **runtime_args;
	int  runtime_args_len;
	char **args;
	int args_len;
	bool no_pivot_root;
	char *checkpoint;
	int root_uid;
	int root_gid;
};

struct io {
	int std_in;
	int std_out;
	int std_err;
};

struct pipe {
	int out[2];
	int in[2];
	int err[2];
};

struct checkpoint{
       char *name;
       bool tcp;
       bool unix_sockets;
       bool shell;
};

struct process {
	char *id;
	char *bundle;
	char *runtime;
	int console;
	char *console_path;
	struct process_state state;
	struct checkpoint checkpoint;
	int container_pid;
	struct io io;
	int stdin_closer;
	struct pipe pipe;
	int	shim_signal;
	pid_t shim_pid;
	int exit_fd, control_fd;
};


#define _cleanup_(x) __attribute__((cleanup(x)))
static inline void freep(void *p) {
	free(*(void**)p);
}
static inline void closep(int *fd) {
	if (*fd >= 0)
		close(*fd);
	*fd = -1;
}
static inline void fclosep(FILE **fp) {
	if (*fp)
		fclose(*fp);
	*fp = NULL;
}
#define _cleanup_free_ _cleanup_(freep)
#define _cleanup_close_ _cleanup_(closep)
#define _cleanup_fclose_ _cleanup_(fclosep)

#endif  /* __MAIN_H */
