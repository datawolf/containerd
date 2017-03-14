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
#define _GNU_SOURCE
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>

#include <sys/signalfd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/epoll.h>

#include <yajl/yajl_tree.h>

#include "utils.h"
#include "mainloop.h"
#include "main.h"


static int log;		// The file descriptor for shim-log
static int slog;

#define DEBUG(fmt,...)							\
	do {								\
		dprintf(slog, "[%d]shim: " fmt ": %m\n", getpid(), ##__VA_ARGS__);	\
	} while(0)

struct exec_args {
	char **args;
	size_t	len;
	size_t	count;
};


// Handlers
int io_copy_handler(int fd, uint32_t events, void *data, int *epfd);
int signal_handler(int fd, uint32_t events, void *data, int *epfd);
int control_handler(int fd, uint32_t events, void *data, int *epfd);

int start(struct process* p);
int load_process(struct process_state* ps);
int load_checkpoint(struct checkpoint* pc, const char *bundle, const char
		    *name);
void free_process(struct process *p);
int open_io(struct process* p);
int get_signal_fd(int *signal_fd);
int write_exit_status(int status);
int append_args(struct exec_args *exec_args, size_t count, ...);
void write_message(const char *level, const char *fmt, ...);


// containerd-shim is a small shim that sits in front of a runtime implementation
// that allows it to be repartented to init and handle reattach from the caller.
//
// the cwd of the shim should be the bundle for the container. argc[1] should be
// the path to the state directory wherer the shim can locate fifos and other
// information.
int main(int argc, char **argv)
{
	int err;
	char cwd[PATH_MAX] = {0};
	_cleanup_free_	char *shim_log;
	struct process process;

	// FOR debug
	slog = open("/tmp/shim.log",
		    O_APPEND | O_CREAT | O_SYNC| O_WRONLY, 0666);
	if (slog == -1) {
		write_message("error", "Failed to open shim.log file");
		exit(EXIT_FAILURE);
	}
	// For debug end

	process.id = argv[1];
	process.bundle = argv[2];
	process.runtime = argv[3];

	if (!getcwd(cwd, PATH_MAX)) {
		write_message("error", "Failed to allocate memory for current working dir path");
		exit(EXIT_FAILURE);
	}
	write_message("info", "current working dir path : %s", cwd);
	shim_log = append_paths(cwd, "shim-log.json");
	if (!shim_log) {
		write_message("error", "Failed to allocate memory for shim-log.json file path");
		exit(EXIT_FAILURE);
	}

	// Open the shim-log, if it does not exist, the create it.
	log = open(shim_log, O_APPEND | O_CREAT | O_SYNC| O_WRONLY, 0666);
	if (log == -1) {
		write_message("error", "Failed to open shim-log file");
		exit(EXIT_FAILURE);
	}

	// Start handling signals as soon as possible so that things are
	// properly reaped.
	err = get_signal_fd(&process.shim_signal);
	if (err < 0) {
		write_message("error", "Failed to get signal_fd");
		goto error;
	}

	// Set the shim as the subreaper for all orphaned processes created by
	// the container
	err = prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0, 0);
	if (err < 0) {
		write_message("error", "Failed to set prctl(PR_SET_CHILD_SUBREAPER)");
		goto error;
	}

	// set the parent death signal to SIGKILL so that if the shim dies the
	// container process also dies
	err = prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0, 0);
	if (err < 0) {
		write_message("error", "Failed to set prctl(PR_SET_PDEATHSIG)");
		goto error;
	}

	// Open the exit pipe
	process.exit_fd = open("exit", O_WRONLY);
	if (process.exit_fd < 0) {
		write_message("error", "Failed to open exit pipe");
		goto error;
	}

	// Open the control pipe
	process.control_fd = open("control", O_RDWR);
	if (process.control_fd < 0) {
		write_message("error", "Failed to open control pipe");
		goto error;
	}

	DEBUG("load process");
	err = load_process(&process.state);
	if (err < 0) {
		write_message("error", "Failed to get process state");
		goto error;
	}

	if (strlen(process.state.checkpoint) > 0) {
		err = load_checkpoint(&process.checkpoint, process.bundle, process.state.checkpoint);
		if (err < 0) {
			write_message("error", "Failed to get checkpint info");
			goto error;
		}
	}

	err = open_io(&process);
	if (err < 0) {
		write_message("error", "Failed to prepare IO");
		goto error;
	}

	err = start(&process);
	if (err != 0) {
		goto error;
	}
	free_process(&process);
	return EXIT_SUCCESS;
error:
	free_process(&process);
	return EXIT_FAILURE;
}

int open_io(struct process* p) {
	int ret;
	int uid = p->state.root_uid;
	int gid = p->state.root_gid;
	int *master = &p->console;

	p->stdin_closer = open(p->state.containerd_stdin, O_WRONLY);
	if (p->stdin_closer < 0) {
		return -1;
	}

	if (p->state.terminal == true) {
		p->console_path =(char *)malloc(100*sizeof(char*));
		memset((void*)p->console_path, 0, 100);
		if (p->console_path == NULL)
			return -1;
		ret = new_console(uid, gid, master, p->console_path, 100);
		if (ret < 0)
			return ret;
		p->io.std_in = open(p->state.containerd_stdin, O_RDONLY);
		if (p->io.std_in < 0) {
			return -1;
		}
		p->io.std_out = open(p->state.containerd_stdout, O_RDWR);
		if (p->io.std_out < 0) {
			return -1;
		}
		return 0;
	}

	ret = open_pipe(p->state.root_uid, p->pipe.in);
	if (ret < 0)
		return ret;
	ret = open_pipe(p->state.root_uid, p->pipe.out);
	if (ret < 0)
		return ret;
	ret = open_pipe(p->state.root_uid, p->pipe.err);
	if (ret < 0)
		return ret;
	p->io.std_in = open(p->state.containerd_stdin, O_RDONLY);
	if (p->io.std_in < 0) {
		return -1;
	}
	p->io.std_err = open(p->state.containerd_stderr, O_RDWR);
	if (p->io.std_out < 0) {
		return -1;
	}
	p->io.std_out = open(p->state.containerd_stdout, O_RDWR);
	if (p->io.std_out < 0) {
		return -1;
	}
	return 0;
}

int append_args(struct exec_args *exec_args, size_t count, ...) {
	va_list ap;
	int r;

	r = grow_array((void ***)&exec_args->args,
		&exec_args->len, exec_args->count+count, 4);
	if (r < 0)
		return -1;

	va_start(ap, count);
        while (count--) {
                char* arg = va_arg(ap, char *);
		exec_args->args[exec_args->count++] = strdup(arg);
        }
        va_end(ap);
	return 0;
}

int start(struct process* p){
	int err;
	int i;
	char cwd[PATH_MAX] = {0};
	_cleanup_free_ char *log_path = NULL;
	_cleanup_free_ char *pid_path = NULL;
	_cleanup_free_ char *process_path = NULL;
	_cleanup_free_ char *image_path = NULL;
	_cleanup_fclose_ FILE *pid_file = NULL;
	struct exec_args exec_args = {NULL, 0, 0};
	char *delete_args[] = {NULL, "delete", NULL, NULL};
	int epfd;
	pid_t delete_pid;
	int wstatus;


	if (!getcwd(cwd, PATH_MAX)) {
		write_message("error", "Failed to allocate memory for current working dir path");
		return -1;
	}
	log_path = append_paths(cwd, "log.json");
	if (!log_path) {
		write_message("error", "Failed to allocate memory for log.json file path");
		return -1;
	}
	process_path = append_paths(cwd, "process.json");
	if (!process_path) {
		write_message("error", "Failed to allocate memory for process.json file path");
		return -1;
	}
	pid_path= append_paths(cwd, "pid");
	if (!pid_path) {
		write_message("error", "Failed to allocate memory for pid file path");
		return -1;
	}

	//if ((err = append_args(&exec_args, p->runtime, "--debug", "--log", log_path, "--log-format", "json")) < 0)
	if ((err = append_args(&exec_args, 6, p->runtime, "--debug", "--log", "/tmp/runc.txt", "--log-format", "json")) < 0)
		return err;
	for (i = 0; i < p->state.runtime_args_len; i++) {
		if ((err = append_args(&exec_args, 1, p->state.runtime_args[i])) < 0)
			return err;
	}

	if (p->state.exec == true) {
		if ((err = append_args(&exec_args, 6, "exec", "-d", "--process", process_path,
			"--console", p->console_path == NULL ? "foo": p->console_path)) < 0)
			return err;
	}else if (strlen(p->state.checkpoint) > 0) {
		image_path = append_paths(p->bundle, "checkpoints");
		if (!image_path) {
			write_message("error", "Failed to allocate memory for log.json file path");
			return -1;
		}
		image_path = append_paths(image_path, p->checkpoint.name);
		if (!image_path) {
			write_message("error", "Failed to allocate memory for log.json file path");
			return -1;
		}
		if ((err = append_args(&exec_args, 2, "restore", "--image-path", image_path)) < 0)
			return err;
		if (p->checkpoint.shell == true) {
			if ((err = append_args(&exec_args, 1, "--shell-job")) < 0)
				return err;
		}
		if (p->checkpoint.tcp== true) {
			if ((err = append_args(&exec_args, 1, "--tcp-established")) < 0)
				return err;
		}
		if (p->checkpoint.unix_sockets == true) {
			if ((err = append_args(&exec_args, 1, "--ext-unix-sk")) < 0)
				return err;
		}
		if (p->state.no_pivot_root == true) {
			if ((err = append_args(&exec_args, 1, "--no-pivot")) < 0)
				return err;
		}
	}else{
		if ((err = append_args(&exec_args, 5, "create",
				 "--bundle", p->bundle,
				 "--console", p->console_path == NULL ? "foo": p->console_path)) < 0)
			return err;
		if (p->state.no_pivot_root == true) {
			if ((err = append_args(&exec_args, 1, "--no-pivot")) < 0)
				return err;
		}
	}

	if ((err = append_args(&exec_args, 3, "--pid-file", pid_path, p->id)) < 0)
		return err;

	exec_args.args = (char **)append_null_to_array((void **)exec_args.args,
					     exec_args.count);
	DEBUG("Runtime Args:");
	DEBUG("\tArgs's len = %d", (int)exec_args.len);
	DEBUG("\tArgs's count = %d", (int)exec_args.count);
	for (i = 0; i < exec_args.count; i++) {
		DEBUG("\targs[%d] = %s", i, exec_args.args[i]);
	}

	if (mainloop_open(&epfd)) {
		write_message("error", "Failed to create epoll file descriptor");
		return err;
	}

	if (mainloop_add_handler(&epfd, p->control_fd, control_handler, p)) {
		write_message("error", "add contorl handler failed");
		return err;
	}
	if (p->state.terminal == true) {
		if (mainloop_add_handler(&epfd, p->console, io_copy_handler, &p->io.std_out)) {
			write_message("error", "Failed to add console out handler");
			return err;
		}
		if (mainloop_add_handler(&epfd, p->io.std_in, io_copy_handler, &p->console)) {
			write_message("error", "Failed add console in handler");
			return err;
		}
	} else {
		if (mainloop_add_handler(&epfd, p->pipe.out[0], io_copy_handler, &p->io.std_out)) {
			write_message("error", "Failed to add pipe out handler");
			return err;
		}
		if (mainloop_add_handler(&epfd, p->pipe.err[0], io_copy_handler, &p->io.std_err)) {
			write_message("error", "Failed to add pipe err handler");
			return err;
		}
		if (mainloop_add_handler(&epfd, p->io.std_in, io_copy_handler, &p->pipe.in[1])) {
			write_message("error", "Failed to add pipe in handler");
			return err;
		}
	}

	//fork off child process to run the user provided command
	DEBUG("fork child");
	p->shim_pid = fork();

	// Child
	if(p->shim_pid == 0) {
		DEBUG("chdir to bundle directory");
		err = chdir(p->bundle);
		if (err == -1) {
			write_message("error", "chdir bundle directory failed");
			exit(EXIT_FAILURE);
		}
		if (p->state.terminal == false) {
			if (dup2(p->pipe.in[0], STDIN_FILENO) == -1) {
				exit(-1);
			}
			close(p->pipe.in[1]);
			if (dup2(p->pipe.out[1], STDOUT_FILENO) == -1) {
				exit(-1);
			}
			close(p->pipe.out[0]);
			if (dup2(p->pipe.err[1], STDERR_FILENO) == -1) {
				exit(-1);
			}
			close(p->pipe.err[0]);
		}
		err = execvp(exec_args.args[0], exec_args.args);
		if (err < 0) {
			DEBUG("child: error = %d", err);
			exit(EXIT_FAILURE);
		}
	}

	// Parent
	close(p->pipe.in[0]);
	close(p->pipe.out[1]);
	close(p->pipe.err[1]);

	DEBUG("shim_pid = %d", p->shim_pid);
	while (waitpid(p->shim_pid, &wstatus, 0) < 0 && errno == EINTR)
		continue;

	pid_file = fopen(pid_path, "r");
	if (pid_file == NULL) {
		write_message("error", "Failed to open pid file");
		return err;
	}
	err = fscanf(pid_file, "%d", &p->container_pid);
	if (err < 0) {
		write_message("error", "Failed to read container pid");
		return err;
	}

	DEBUG("containerpid = %d", p->container_pid);
	DEBUG("shim_signal = %d", p->shim_signal);

	// Add signal fd
	DEBUG("add shim_signal handler");
	if (mainloop_add_handler(&epfd, p->shim_signal, signal_handler, &p->container_pid)) {
		write_message("error", "add shim_signal handler");
		return err;
	}

	DEBUG("mainloop");
	err = mainloop(epfd, -1);
	if (err < 0) {
		write_message("error", "mainloop error");
		return err;
	}
	DEBUG("mainloop return = %d", err);
	if (err == 2) {
		DEBUG("shim exit");
		delete_pid = fork();
		if (delete_pid == 0) {	// child
			execvp(delete_args[0], delete_args);
		}
		// parent
		DEBUG("wait for delete task: delete_pid = %d", delete_pid);
		while (waitpid(delete_pid, &wstatus, 0) < 0 && errno == EINTR)
			continue;
	}
	DEBUG("done");
	return 0;
}

int write_exit_status(int status)
{
	int fd;
	fd = open("exitStatus", O_CREAT | O_WRONLY,
		 S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	if (fd == -1) {
		write_message("error", "open exitStatus failed");
		return -1;
	}
	dprintf(fd, "%d", status);
	close(fd);
	return 0;
}

int load_checkpoint(struct checkpoint* pc, const char *bundle, const char *name) {
	_cleanup_free_ char *config;
	// 25 = strlen("checkpoints") + strlen("config.json") + 3
	size_t len = strlen(bundle) + strlen(name) + 25 + 1;
	size_t rd;
	yajl_val node, v;
	char errbuf[1024];
	char *str;
	_cleanup_fclose_ FILE* file;
	unsigned char fileData[65536];

	config = calloc(1, len);
	if (!config)
		return -1;
	snprintf(config, len, "%s/checkpoints/%s/config.json", bundle, name);

	file = fopen(config, "r");
	if (file == NULL) {
		write_message("error", "open checkpoint config.json failed: %s", config);
		return -1;
	}
	/* null plug buffers */
	fileData[0] = errbuf[0] = 0;

	/* read the entire config file */
	rd = fread((void *)fileData, 1, sizeof(fileData) - 1, file);

	 /* file read error handling */
	if (rd == 0 && !feof(stdin)) {
		write_message("error", "error encountered on file read");
	        return 1;
	} else if (rd >= sizeof(fileData) - 1) {
		write_message("error", "config file too big");
		return 1;
	}

	/* Parse the process.json */
	node = yajl_tree_parse((const char *)fileData, errbuf, sizeof(errbuf));

	/* parse error handling */
	if (node == NULL) {
		write_message("error", "parse_error: ");
		if (strlen(errbuf))
			write_message("error", " %s", errbuf);
		else
			write_message("error", "unknown error");
		return 1;
	}

	pc->name = NULL;
	pc->tcp = false;
	pc->unix_sockets = false;
	pc->shell = false;

	/* Extract values from the checkpoint config.json */
	const char *tcp_path[] = {"tcp", (const char*)0};
	if ((v = yajl_tree_get(node, tcp_path, yajl_t_true)) != NULL) {
		pc->tcp = YAJL_IS_TRUE(v) ? true : false;
	}
	if ((v = yajl_tree_get(node, tcp_path, yajl_t_false)) != NULL) {
		pc->tcp = YAJL_IS_FALSE(v) ? false : true;
	}

	const char *unix_sockets_path[] = {"unixSockets", (const char*)0};
	if ((v = yajl_tree_get(node, unix_sockets_path, yajl_t_true)) != NULL) {
		pc->unix_sockets = YAJL_IS_TRUE(v) ? true : false;
	}
	if ((v = yajl_tree_get(node, unix_sockets_path, yajl_t_false)) != NULL) {
		pc->unix_sockets = YAJL_IS_FALSE(v) ? false : true;
	}


	const char *shell_path[] = {"shell", (const char*)0};
	if ((v = yajl_tree_get(node, shell_path, yajl_t_true)) != NULL) {
		pc->shell = YAJL_IS_TRUE(v) ? true : false;
	}
	if ((v = yajl_tree_get(node, shell_path, yajl_t_false)) != NULL) {
		pc->shell = YAJL_IS_FALSE(v) ? false : true;
	}

	const char *name_path[] = {"name", (const char*)0};
        if ((v = yajl_tree_get(node, name_path, yajl_t_string)) != NULL) {
		str = YAJL_GET_STRING(v);
		pc->name = (char *)malloc((strlen(str)+1)*sizeof(char));
		memcpy((void*)pc->name, (void *)str, strlen(str)+1);
	}

	yajl_tree_free(node);
	return 0;
}

int load_process(struct process_state* ps)
{
	size_t rd;
	yajl_val node, v;
	char errbuf[1024];
	char *str;
	_cleanup_fclose_ FILE* file;
	unsigned char fileData[65536];
	int i;

	file = fopen("process.json", "r");
	if (file == NULL) {
		write_message("error", "open process.json failed: %s", strerror(errno));
		return -1;
	}
	/* null plug buffers */
	fileData[0] = errbuf[0] = 0;

	/* read the entire config file */
	rd = fread((void *)fileData, 1, sizeof(fileData) - 1, file);

	 /* file read error handling */
	if (rd == 0 && !feof(stdin)) {
		write_message("error", "error encountered on file read");
	        return 1;
	} else if (rd >= sizeof(fileData) - 1) {
		write_message("error", "config file too big");
		return 1;
	}

	/* Parse the process.json */
	node = yajl_tree_parse((const char *)fileData, errbuf, sizeof(errbuf));

	/* parse error handling */
	if (node == NULL) {
		write_message("error", "parse_error: ");
		if (strlen(errbuf))
			write_message("error", " %s", errbuf);
		else
			write_message("error", "unknown error");
		return 1;
	}


	ps->terminal = false;
	ps->exec = false;
	ps->containerd_stdin = NULL;
	ps->containerd_stdout = NULL;
	ps->containerd_stderr = NULL;
	ps->runtime_args_len = 0;
	ps->runtime_args = NULL;
	ps->args_len = 0;
	ps->args = NULL;
	ps->checkpoint = NULL;
	ps->no_pivot_root = false;
	ps->root_uid = 0;
	ps->root_gid = 0;

	/* Extract values from the process json */
	const char *terminal_path[] = {"terminal", (const char*)0};
	if ((v = yajl_tree_get(node, terminal_path, yajl_t_true)) != NULL) {
		ps->terminal = YAJL_IS_TRUE(v) ? true : false;
	}
	if ((v = yajl_tree_get(node, terminal_path, yajl_t_false)) != NULL) {
		ps->terminal = YAJL_IS_FALSE(v) ? false : true;
	}

	const char *exec_path[] = {"exec", (const char*)0};
        if ((v = yajl_tree_get(node, exec_path, yajl_t_true)) != NULL) {
		ps->exec = YAJL_IS_TRUE(v) ? true : false;
	}
        if ((v = yajl_tree_get(node, exec_path, yajl_t_false)) != NULL) {
		ps->exec = YAJL_IS_FALSE(v) ? false : true;
	}

	const char *containerd_stdin_path[] = {"containerdStdin", (const char*)0};
        if ((v = yajl_tree_get(node, containerd_stdin_path, yajl_t_string)) != NULL) {
		str = YAJL_GET_STRING(v);
		ps->containerd_stdin =
			(char *)malloc((strlen(str)+1)*sizeof(char));
		memcpy((void *)ps->containerd_stdin, (void *)str, strlen(str)+1);
	}

	const char *containerd_stdout_path[] = {"containerdStdout", (const char*)0};
        if ((v = yajl_tree_get(node, containerd_stdout_path, yajl_t_string)) != NULL) {
		str = YAJL_GET_STRING(v);
		ps->containerd_stdout =
			(char *)malloc((strlen(str)+1)*sizeof(char));
		memcpy((void *)ps->containerd_stdout, (void *)str, strlen(str)+1);
	}

	const char *containerd_stderr_path[] = {"containerdStderr", (const char*)0};
        if ((v = yajl_tree_get(node, containerd_stderr_path, yajl_t_string)) != NULL) {
		str = YAJL_GET_STRING(v);
		ps->containerd_stderr = (char *)malloc((strlen(str)+1)*sizeof(char));
		memcpy((void *)ps->containerd_stderr, (void *)str, strlen(str)+1);
	}

	const char *runtime_args_path[] = {"runtimeArgs", (const char*)0};
        if ((v = yajl_tree_get(node, runtime_args_path, yajl_t_array)) != NULL) {
		int len = YAJL_GET_ARRAY(v)->len;
		ps->runtime_args_len = len;
		ps->runtime_args = (char **)malloc(len*sizeof(char *));
		for (i = 0; i < len; i++) {
			str = YAJL_GET_STRING(YAJL_GET_ARRAY(v)->values[i]);
			ps->runtime_args[i] =
				(char *)malloc((strlen(str)+1)*sizeof(char));
			memcpy((void*)ps->runtime_args[i], (void*)str, strlen(str)+1);
		}
	}

	const char *args_path[] = {"args", (const char*)0};
        if ((v = yajl_tree_get(node, args_path, yajl_t_array)) != NULL) {
		int len = YAJL_GET_ARRAY(v)->len;
		ps->args_len = len;
		ps->args = (char **)malloc(len*sizeof(char *));
		for (i = 0; i < len; i++) {
			str = YAJL_GET_STRING(YAJL_GET_ARRAY(v)->values[i]);
			ps->args[i] =
				(char *)malloc((strlen(str)+1)*sizeof(char));
			memcpy((void*)ps->args[i], (void*)str, strlen(str)+1);
		}
	}

	const char *checkpoint_path[] = {"checkpoint", (const char*)0};
        if ((v = yajl_tree_get(node, checkpoint_path, yajl_t_string)) != NULL) {
		str = YAJL_GET_STRING(v);
		ps->checkpoint = (char *)malloc((strlen(str)+1)*sizeof(char));
		memcpy((void*)ps->checkpoint, (void *)str, strlen(str)+1);
	}

	const char *no_pivot_root_path[] = {"noPivotRoot", (const char*)0};
        if ((v = yajl_tree_get(node, no_pivot_root_path, yajl_t_true)) != NULL) {
		ps->no_pivot_root = YAJL_IS_TRUE(v) ? true : false;
	}
        if ((v = yajl_tree_get(node, no_pivot_root_path, yajl_t_false)) != NULL) {
		ps->no_pivot_root = YAJL_IS_FALSE(v) ? false : true;
	}

	const char *root_uid_path[] = {"rootUID", (const char*)0};
        if ((v = yajl_tree_get(node, root_uid_path, yajl_t_number)) != NULL) {
		ps->root_uid = YAJL_GET_INTEGER(v);
	}

	const char *root_gid_path[] = {"rootGID", (const char*)0};
        if ((v = yajl_tree_get(node, root_gid_path, yajl_t_number)) != NULL) {
		ps->root_gid = YAJL_GET_INTEGER(v);
	}

	yajl_tree_free(node);

	return 0;
}

ssize_t	write_nointr(int fd, const void* buf, size_t count) {
	ssize_t	ret;
again:
	ret = write(fd, buf, count);
	if (ret < 0 && errno == EINTR)
		goto again;
	return ret;
}

ssize_t read_nointr(int fd, void* buf, size_t count) {
	ssize_t	ret;
again:
	ret = read(fd, buf, count);
	if (ret <0 && errno == EINTR)
		goto again;
	return ret;
}

// callback for IO Copy
int io_copy_handler(int fd, uint32_t events, void *data, int *epfd) {
	char buf[1024];
	int r, w;
	int to = *(int *)data;

	w = r = read_nointr(fd, buf, sizeof(buf));
	if (r <= 0) {
		mainloop_del_handler(epfd, fd);
		close(fd);
		return 0;
	}

	if (to >= 0) {
		w = write_nointr(to, buf, r);
	}

	if (w != r) {
		write_message("error", "console short writer: %d w: %d", r, w);
	}
	return 0;
}

int signal_handler(int fd, uint32_t events, void *data, int *epfd) {
	struct signalfd_siginfo siginfo;
	pid_t reap_pid;
	pid_t pid = *(pid_t*)data;
	int status, wstatus;
	int ret;

	for (;;) {
		ret = read(fd, &siginfo, sizeof(struct signalfd_siginfo));
		if (ret < 0 && errno == EAGAIN) {
			write_message("error", "Failed to read signal info");
			break;
		}
		if (ret != sizeof(struct signalfd_siginfo)) {
			write_message("error", "unexpected siginfo size");
			break;
		}

		for (;;) {
			reap_pid = waitpid(-1, &wstatus, WNOHANG);
			if (reap_pid <= 0)
				break;
			DEBUG("get SIGCHLD signal, reap pid = %d", reap_pid);
			if ((reap_pid > 0) && (reap_pid == pid)) {
				status = WEXITSTATUS(wstatus);
				if (WIFSIGNALED(wstatus)) {
					status += WTERMSIG(wstatus) + 128;
				}
				write_exit_status(status);
				return 2;
			}
		}
	}
	return 0;
}

int control_handler(int fd, uint32_t events, void *data, int *epfd) {
	struct process  *p = (struct process*)data;
	char buf[1024];
	int msg, w, h;
	struct winsize wsz;
	ssize_t ret;

	ret = read(fd, buf, sizeof(buf));
	if (ret < 0) {
		DEBUG("read control file error");
		return 0;
	}

	sscanf(buf, "%d %d %d\n", &msg, &w, &h);
	wsz.ws_col = w;
	wsz.ws_row = h;

	DEBUG("Change tty size: msg = %d, col = %d, row = %d", msg, w, h);
	switch (msg){
	case 0:
		// close stdin
		if (p->stdin_closer >= 0)
			close(p->stdin_closer);
		break;
	case 1:
		// 修改tty的size
		ioctl(p->console, TIOCSWINSZ, &wsz);
		break;
	}

	return 0;
}

void write_message(const char *level, const char *fmt, ...)
{
#define BUF_SIZE 1024
	va_list arg_list;
	char buf[BUF_SIZE];

	if (log < 0)
		return;
	va_start(arg_list, fmt);
	vsnprintf(buf, BUF_SIZE, fmt, arg_list);
	dprintf(log, "{\"level\": \"%s\",\"msg\": \"%s\"}", level, buf);
	DEBUG("%s", buf);
	va_end(arg_list);
}

int get_signal_fd(int *signal_fd)
{
	int err;
	sigset_t mask;

	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	err = sigprocmask(SIG_BLOCK, &mask, NULL);
	if (err < 0) {
		write_message("error", "sigprocmask");
		return -1;
	}

	// Create a new file descriptor that can be used to read the signals in
	// sigset and set the close-on-exec and non-blcok flags for the new file descriptor.
	*signal_fd = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
	if (*signal_fd < 0) {
		write_message("error", "signalfd");
		return -1;
	}
	return 0;
}


#define FREEP(x)				\
	{					\
		if (x != NULL)			\
			free(*(void**)x);	\
	}
#define CLOSE(fd)				\
	{					\
		if (fd >= 0)			\
			close(fd);		\
		fd = -1;			\
	}

void free_process(struct process *p) {
	int i;

	// Free memory
	FREEP(p->console_path);
	FREEP(p->state.containerd_stdin);
	FREEP(p->state.containerd_stdout);
	FREEP(p->state.containerd_stderr);
	for (i = 0; i < p->state.runtime_args_len; i++) {
		FREEP(p->state.runtime_args[i])
	}
	for (i = 0; i < p->state.args_len; i++) {
		FREEP(p->state.args[i])
	}
	FREEP(p->state.runtime_args);
	FREEP(p->state.args);
	FREEP(p->state.checkpoint);
	FREEP(p->checkpoint.name);

	// Close file descriptor
	CLOSE(p->console);
	CLOSE(p->io.std_in);
	CLOSE(p->io.std_out);
	CLOSE(p->io.std_err);
	CLOSE(p->pipe.in[0]);
	CLOSE(p->pipe.in[1]);
	CLOSE(p->pipe.out[0]);
	CLOSE(p->pipe.out[1]);
	CLOSE(p->pipe.err[0]);
	CLOSE(p->pipe.err[1]);
	CLOSE(p->shim_signal);
	CLOSE(p->exit_fd);
	CLOSE(p->control_fd);
}
