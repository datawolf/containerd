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
#include <stdlib.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

#include "mainloop.h"

#define MAX_EVENTS 10
int mainloop(int epfd, int timeout) {
	struct mainloop_handler *handler;
	struct epoll_event events[MAX_EVENTS];
	int nfds, i;
	int ret;

	for(;;) {
		nfds = epoll_wait(epfd, events, MAX_EVENTS, timeout);
		if (nfds < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}

		for (i = 0; i < nfds; i++) {
			handler =
				(struct mainloop_handler*)events[i].data.ptr;
			ret = handler->callback(handler->fd, events[i].events,
					      handler->data, &epfd);
			if (ret > 0)
				return ret;
		}
	}
}

int mainloop_add_handler(int *epfd, int fd, mainloop_callback_t callback,
				void *data) {
	struct epoll_event ev;
	struct mainloop_handler *handler;

	handler = malloc(sizeof(*handler));
	if (!handler)
		return -1;

	handler->callback = callback;
	handler->fd = fd;
	handler->data = data;

	ev.events = EPOLLIN;
	ev.data.ptr = handler;

	if (epoll_ctl(*epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
		free(handler);
		return -1;
	}

	return 0;
}

int mainloop_del_handler(int *epfd, int fd) {
	if (epoll_ctl(*epfd, EPOLL_CTL_DEL, fd, NULL))
		return -1;
	return 0;
}

int mainloop_open(int *epfd) {
	*epfd = epoll_create(2);
	if (*epfd < 0)
		return -1;

	if (fcntl(*epfd, F_SETFD, FD_CLOEXEC)) {
		close(*epfd);
		return -1;
	}
	return 0;
}

int mainloop_close(int *epfd) {
	return close(*epfd);
}
