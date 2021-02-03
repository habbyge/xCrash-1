// Copyright (c) 2020-present, HexHacking Team. All rights reserved.
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

// Created on 2020-10-04.

#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <ctype.h>
#include <elf.h>
#include <link.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <android/api-level.h>
#include "xc_dl_iterate.h"
#include "xc_dl.h"
#include "xc_dl_util.h"
#include "xc_dl_const.h"

// - <dlfcn.h>学习
// Linux的so库显式调用:
// (1) 用 dlopen() 打开库文件，并指定打开方式:
// dllope的第一个参数为共享库的名称，将会在下面位置查找指定的共享库
// ① 环境变量 LD_LIBRARY_PATH 列出的用分号间隔的所有目录
// ② 文件 /etc/ld.so.cache 中找到的库的列表，由 ldconfig 命令刷新
// ③ 目录 usr/lib
// ④ 目录/lib
// ⑤ 当前目录
// 第二个参数为打开共享库的方式。有两个取值:
// ① RTLD_NOW：将共享库中的所有函数加载到内存
// ② RTLD_LAZY：会推后共享库中的函数的加载操作，直到调用dlsym()时方加载某函数
// (2) 用 dlerror() 测试是否打开成功，并进行错误处理
// (3) 用 dlsym() 获得函数地址，存放在一个函数指针中
// (4) 用获得的函数指针进行函数调用
// (5) 程序结束时用 dlclose() 打开的动态库，防止资源泄露。
// (6) 用 ldconfig 工具把动态库的路径加到系统库列表中

// 定位内存泄漏基本上是从宏观到微观，进而定位到代码位置。
// 从/proc/meminfo可以看到整个系统内存消耗情况，使用top可以看到每个进程的VIRT(虚拟内存)和RES(实际占用内存)，基本
// 上就可以将泄漏内存定位到进程范围。之前也大概了解过/proc/self/maps，基于里面信息能大概判断泄露的内存的属性，是哪
// 个区域在泄漏、对应哪个文件。
// /proc/[pid]/maps文件格式：
// address               perms offset   dev   inode   pathname
// 00400000-00452000     r-xp  00000000 08:02 173521  /usr/bin/dbus-daemon
// 35b1800000-35b1820000 r-xp  00000000 08:02 135522  /usr/lib64/ld-2.15.so

/*
 * =================================================================================================
 * API-LEVEL  ANDROID-VERSION  SOLUTION
 * 16         4.1      /proc/self/maps
 * =================================================================================================
 * 17         4.2      /proc/self/maps
 * 18         4.3      /proc/self/maps
 * 19         4.4      /proc/self/maps
 * 20         4.4W     /proc/self/maps
 * -------------------------------------------------------------------------------------------------
 * 21         5.0      dl_iterate_phdr() + __dl__ZL10g_dl_mutex + linker/linker64 in /proc/self/maps
 * 22         5.1      dl_iterate_phdr() + __dl__ZL10g_dl_mutex + linker/linker64 in /proc/self/maps
 * --------------------------------------------------------------------
 * 23         6.0      dl_iterate_phdr() + linker/linker64 in /proc/self/maps
 * 24         7.0      dl_iterate_phdr() + linker/linker64 in /proc/self/maps
 * 25         7.1      dl_iterate_phdr() + linker/linker64 in /proc/self/maps
 * 26         8.0      dl_iterate_phdr() + linker/linker64 in /proc/self/maps
 * -------------------------------------------------------------------------------------------------
 * >= 27      >= 8.1   dl_iterate_phdr()
 * =================================================================================================
 */
// Linux中libunwind.so(Android中已经删除了个so)中的一个函数，用于获取so库(elf文件)中的一个函数地址，
// dl_iterate_phdr可以查到当前进程所装载的所有符号，每查到一个就会调用你指定的回调函数.
extern __attribute((weak)) int dl_iterate_phdr(int (*)(struct dl_phdr_info*, size_t, void*), void*);

// Android 5.0/5.1 linker's global mutex in .symtab
static pthread_mutex_t* xc_dl_iterate_linker_mutex = NULL;

static void xc_dl_iterate_linker_mutex_init() {
  xc_dl_t* linker = xc_dl_open(XC_DL_CONST_PATHNAME_LINKER, XC_DL_SYMTAB);
  if (NULL == linker) {
    return;
  }

  xc_dl_iterate_linker_mutex = xc_dl_symtab_object(linker, XC_DL_CONST_SYM_LINKER_MUTEX);

  xc_dl_close(&linker);
}

static uintptr_t xc_dl_iterate_get_min_vaddr(struct dl_phdr_info* info) {
  uintptr_t min_vaddr = UINTPTR_MAX;
  for (size_t i = 0; i < info->dlpi_phnum; i++) {
    const ElfW(Phdr)* phdr = &(info->dlpi_phdr[i]);
    if (PT_LOAD == phdr->p_type) {
      if (min_vaddr > phdr->p_vaddr) {
        min_vaddr = phdr->p_vaddr;
      }
    }
  }
  return min_vaddr;
}

static int xc_dl_iterate_open_or_rewind_maps(FILE** maps) {
  if (NULL == *maps) {
    *maps = fopen("/proc/self/maps", "r");
    if (NULL == *maps) return -1;
  } else
    rewind(*maps);

  return 0;
}

static uintptr_t xc_dl_iterate_get_pathname_from_maps(struct dl_phdr_info* info,
                                                      char* buf, size_t buf_len,
                                                      FILE** maps) {

  // get base address
  uintptr_t min_vaddr = xc_dl_iterate_get_min_vaddr(info);
  if (UINTPTR_MAX == min_vaddr) return 0; // failed
  uintptr_t base = (uintptr_t) (info->dlpi_addr + min_vaddr);

  // open or rewind maps-file
  if (0 != xc_dl_iterate_open_or_rewind_maps(maps))
    return 0; // failed

  char line[1024];
  while (fgets(line, sizeof(line), *maps)) {
    // check base address
    uintptr_t start, end;
    if (2 != sscanf(line, "%"SCNxPTR"-%"SCNxPTR" r", &start, &end)) continue;
    if (base < start) break; // failed
    if (base >= end) continue;

    // get pathname
    char* pathname = strchr(line, '/');
    if (NULL == pathname) break; // failed
    xc_dl_util_trim_ending(pathname);

    // found it
    strlcpy(buf, pathname, buf_len);
    return (uintptr_t) buf; // OK
  }

  return 0; // failed
}

static int xc_dl_iterate_by_linker_cb(struct dl_phdr_info* info, size_t size, void* arg) {
  uintptr_t* pkg = (uintptr_t*) arg;
  xc_dl_iterate_cb_t cb = (xc_dl_iterate_cb_t) *pkg++;
  void* cb_arg = (void*) *pkg++;
  FILE** maps = (FILE**) *pkg++;
  uintptr_t linker_load_bias = *pkg;

  if (0 == info->dlpi_addr || NULL == info->dlpi_name || '\0' == info->dlpi_name[0])
    return 0; // ignore invalid ELF
  if (linker_load_bias == info->dlpi_addr)
    return 0; // ignore linker if we have returned it already

  if ('/' != info->dlpi_name[0] && '[' != info->dlpi_name[0]) {
    // get pathname from /proc/self/maps
    char buf[512];
    uintptr_t pathname = xc_dl_iterate_get_pathname_from_maps(info, buf, sizeof(buf), maps);
    if (0 == pathname) return 0; // ignore this ELF

    // callback
    struct dl_phdr_info info_fixed;
    info_fixed.dlpi_addr = info->dlpi_addr;
    info_fixed.dlpi_name = (const char*) pathname;
    info_fixed.dlpi_phdr = info->dlpi_phdr;
    info_fixed.dlpi_phnum = info->dlpi_phnum;
    return cb(&info_fixed, size, cb_arg);
  } else {
    // callback
    return cb(info, size, cb_arg);
  }
}

static uintptr_t xc_dl_iterate_find_linker_base(FILE** maps) {
  // open or rewind maps-file
  if (0 != xc_dl_iterate_open_or_rewind_maps(maps))
    return 0; // failed

  size_t linker_pathname_len = strlen(" "XC_DL_CONST_PATHNAME_LINKER);

  char line[1024];
  while (fgets(line, sizeof(line), *maps)) {
    // check pathname
    size_t line_len = xc_dl_util_trim_ending(line);
    if (line_len < linker_pathname_len)
      continue;

    if (0 != memcmp(line + line_len - linker_pathname_len,
                    " "XC_DL_CONST_PATHNAME_LINKER,
                    linker_pathname_len)) {
      // todo:
      continue;
    }

    // get base address
    uintptr_t base, offset;
    if (2 != sscanf(line, "%"SCNxPTR"-%*"SCNxPTR" r%*2sp %"SCNxPTR" ", &base, &offset))
      continue;
    if (0 != offset) continue;
    if (0 != memcmp((void*) base, ELFMAG, SELFMAG)) continue;

    // find it
    return base;
  }

  return 0;
}

static int xc_dl_iterate_do_callback(xc_dl_iterate_cb_t cb, void* cb_arg,
                                     uintptr_t base, const char* pathname,
                                     uintptr_t* load_bias) { // TODO: ing......

  ElfW(Ehdr)* ehdr = (ElfW(Ehdr)*) base; // Elf32_Ehdr/Elf64_Ehdr

  struct dl_phdr_info info;
  info.dlpi_name = pathname;
  info.dlpi_phdr = (const ElfW(Phdr)*) (base + ehdr->e_phoff);
  info.dlpi_phnum = ehdr->e_phnum;

  // get load bias
  uintptr_t min_vaddr = xc_dl_iterate_get_min_vaddr(&info);
  if (UINTPTR_MAX == min_vaddr) {
    return 0; // ignore invalid ELF
  }
  info.dlpi_addr = (ElfW(Addr)) (base - min_vaddr);
  if (NULL != load_bias) {
    *load_bias = info.dlpi_addr;
  }

  return cb(&info, sizeof(struct dl_phdr_info), cb_arg);
}

static int xc_dl_iterate_by_linker(xc_dl_iterate_cb_t cb, void* cb_arg, int flags) {
  if (NULL == dl_iterate_phdr) {
    return -1;
  }

  FILE* maps = NULL;

  // for linker/linker64 in Android version < 8.1 (API level 27)
  uintptr_t linker_base = 0;
  uintptr_t linker_load_bias = 0;
  if ((flags & XC_DL_WITH_LINKER) && xc_dl_util_get_api_level() < __ANDROID_API_O_MR1__) {
    linker_base = xc_dl_iterate_find_linker_base(&maps);
    if (0 != linker_base) {
      if (0 != xc_dl_iterate_do_callback(cb, cb_arg, linker_base,
                                         XC_DL_CONST_PATHNAME_LINKER,
                                         &linker_load_bias)) {

        return 0;
      }
    }
  }

  // for other ELF
  uintptr_t pkg[4] = {
      (uintptr_t) cb,
      (uintptr_t) cb_arg,
      (uintptr_t) &maps,
      linker_load_bias
  };
  if (NULL != xc_dl_iterate_linker_mutex) {
    pthread_mutex_lock(xc_dl_iterate_linker_mutex);
  }
  // 位于link.h中，可以查到当前进程所装载的所有符号，每查到一个就会调用你指定的回调函数.
  dl_iterate_phdr(xc_dl_iterate_by_linker_cb, pkg);
  if (NULL != xc_dl_iterate_linker_mutex) {
    pthread_mutex_unlock(xc_dl_iterate_linker_mutex);
  }

  if (NULL != maps)
    fclose(maps);
  return 0;
}

#if defined(__arm__) || defined(__i386__)

static int xc_dl_iterate_by_maps(xc_dl_iterate_cb_t cb, void* cb_arg) {
  FILE* maps = fopen("/proc/self/maps", "r"); // 当前加载到进程中的so内存隐射
  if (NULL == maps)
    return 0;

  char line[1024];
  while (fgets(line, sizeof(line), maps)) {
    // Try to find an ELF which loaded by linker. This is almost always correct in android 4.x.
    uintptr_t base;
    uintptr_t offset;
    // base-结束地址 r-xp offset
    if (2 != sscanf(line, "%"SCNxPTR"-%*"SCNxPTR" r-xp %"SCNxPTR" ", &base, &offset)) {
      continue;
    }
    if (0 != offset) { // 要求是偏移量为0的那一行
      continue;
    }
    if (0 != memcmp((void*) base, ELFMAG, SELFMAG)) {
      continue;
    }

    // get pathname
    char* pathname = strchr(line, '/'); // 索引到so路径处
    if (NULL == pathname) {
      break;
    }
    xc_dl_util_trim_ending(pathname);

    // callback
    if (0 != xc_dl_iterate_do_callback(cb, cb_arg, base, pathname, NULL)) {
      break;
    }
  }

  fclose(maps);
  return 0;
}

#endif

int xc_dl_iterate(xc_dl_iterate_cb_t cb, void* cb_arg, int flags) {
  int api_level = xc_dl_util_get_api_level();

  // get linker's __dl__ZL10g_dl_mutex for Android 5.0/5.1
  static bool linker_mutex_inited = false;
  if (__ANDROID_API_L__ == api_level || __ANDROID_API_L_MR1__ == api_level) {
    if (!linker_mutex_inited) {
      linker_mutex_inited = true;
      xc_dl_iterate_linker_mutex_init();
    }
  }

  // iterate by /proc/self/maps in Android 4.x (Android 4.x only supports arm32 and x86)
#if defined(__arm__) || defined(__i386__)
  if (api_level < __ANDROID_API_L__)
    return xc_dl_iterate_by_maps(cb, cb_arg);
#endif
  // iterate by dl_iterate_phdr()
  return xc_dl_iterate_by_linker(cb, cb_arg, flags);
}
