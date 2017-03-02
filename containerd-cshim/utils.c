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
#include <errno.h>
#include "utils.h"

char *append_paths(const char *first, const char *second) {
	size_t	len = strlen(first) + strlen(second) + 1;
	const char *pattern = "%s%s";
	char *result = NULL;

	if (second[0] != '/') {
		len += 1;
		pattern = "%s/%s";
	}

	result = calloc(1, len);
	if (!result)
		return NULL;

	snprintf(result, len, pattern, first, second);
	return result;
}


size_t array_len(void **array)
{
        void **p;
        size_t result = 0;

        for (p = array; p && *p; p++)
                result++;

        return result;
}

void free_array(void **array, free_fn element_free_fn)
{
        void **p;
        for (p = array; p && *p; p++)
                element_free_fn(*p);
        free((void*)array);
}

int grow_array(void ***array, size_t* capacity, size_t new_size, size_t capacity_increment)
{
        size_t new_capacity;
        void **new_array;

        /* first time around, catch some trivial mistakes of the user
         * only initializing one of these */
        if (!*array || !*capacity) {
                *array = NULL;
                *capacity = 0;
        }

        new_capacity = *capacity;
        while (new_size + 1 > new_capacity)
                new_capacity += capacity_increment;
        if (new_capacity != *capacity) {
                /* we have to reallocate */
                new_array = realloc(*array, new_capacity * sizeof(void *));
                if (!new_array)
                        return -1;
                memset(&new_array[*capacity], 0, (new_capacity - (*capacity)) * sizeof(void *));
                *array = new_array;
                *capacity = new_capacity;
        }

        /* array has sufficient elements */
        return 0;
}

void **append_null_to_array(void **array, size_t count)
{
        void **temp;

        /* Append NULL to the array */
        if (count) {
                temp = realloc(array, (count + 1) * sizeof(*array));
                if (!temp) {
                        size_t i;
                        for (i = 0; i < count; i++) 
                                free(array[i]);
                        free(array);
                        return NULL;
                }
                array = temp;
                array[count] = NULL;
        }
        return array;
}

int open_pipe(int uid, int fds[2]) {
        int ret;

        if (pipe(fds) == -1)
                return -1;

        if ((ret = fchown(fds[0], uid, uid)) < 0) {
                close(fds[0]);
                close(fds[1]);
                return ret;
        }

        if ((ret = fchown(fds[1], uid, uid)) < 0) {
                close(fds[0]);
                close(fds[1]);
                return ret;
        }

        return 0;
}

int new_console(int uid, int gid, int* console, char* console_path, size_t len)
{
        int ret;
        int master_fd;
        char *p;

        master_fd = open("/dev/ptmx", O_RDWR| O_NOCTTY | O_CLOEXEC);
        if (master_fd == -1)
                return -1;
        if ((ret = grantpt(master_fd)) < 0) {
                close(master_fd);
                return ret;
        }

        if ((ret = unlockpt(master_fd))< 0) {
                close(master_fd);
                return ret;
        }
        p = ptsname(master_fd);
        if (p == NULL) {
                close(master_fd);
                return -1;
        }

        if (strlen(p) < len) {
                strncpy(console_path, p, strlen(p));
        }else { /* Return an error if buffer too small */
                close(master_fd);
                errno = EOVERFLOW;
                return -1;
        }

        if ((ret = chmod(console_path, 0600)) < 0) {
                return ret;
        }

        if ((ret = chown(console_path, uid, gid)) < 0) {
                return ret;
        }

        *console = master_fd;
        return 0;
}
