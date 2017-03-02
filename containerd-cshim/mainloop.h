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
#ifndef __MAINLOOP_H
#define __MAINLOOP_H

typedef int (*mainloop_callback_t)(int fd, uint32_t event, void *data, int *epfd);

struct mainloop_handler {
        mainloop_callback_t callback;
        int fd;
        void *data;
};

int mainloop(int epfd, int timeout);
int mainloop_add_handler(int *epfd, int fd, mainloop_callback_t callback, void
			 *data);
int mainloop_del_handler(int *epfd, int fd);
int mainloop_open(int *epfd);
int mainloop_close(int *epfd);

#endif /*__MAINLOOP_H */
