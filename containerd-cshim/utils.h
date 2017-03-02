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
#ifndef __UTILS_H
#define __UTILS_H

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

extern char *append_paths(const char *first, const char *second);
extern size_t array_len(void **array);
extern int grow_array(void ***array, size_t* capacity, size_t new_size,
			  size_t capacity_increment);
typedef void (*free_fn)(void *);
extern void free_array(void **array, free_fn element_free_fn);
extern void **append_null_to_array(void **array, size_t count);
extern int open_pipe(int uid, int fds[2]);
extern int new_console(int uid, int gid, int* console, char* console_path,
		       size_t len);
#endif /*__UTILS_H */
