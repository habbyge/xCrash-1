// Copyright (c) 2020-present, HexHacking Team. All rights reserved.
// Copyright (c) 2019, iQIYI, Inc. All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

// Created on 2019-03-07.

#ifndef XCD_MEMORY_REMOTE_H
#define XCD_MEMORY_REMOTE_H 1

#include <stdint.h>
#include <sys/types.h>
#include "xcd_map.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct xcd_memory_remote xcd_memory_remote_t;

int xcd_memory_remote_create(void** obj, xcd_map_t* map, pid_t pid);

void xcd_memory_remote_destroy(void** obj);

size_t xcd_memory_remote_read(void* obj, uintptr_t addr, void* dst, size_t size);

#ifdef __cplusplus
}
#endif

#endif
