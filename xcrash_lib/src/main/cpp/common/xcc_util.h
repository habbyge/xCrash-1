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

#ifndef XCC_UTIL_H
#define XCC_UTIL_H 1

#include <stdint.h>
#include <sys/types.h>
#include <inttypes.h>
#include <signal.h>
#include <sys/syscall.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XCC_UTIL_TOMB_HEAD  "*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***\n"
#define XCC_UTIL_THREAD_SEP "--- --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---\n"
#define XCC_UTIL_THREAD_END "+++ +++ +++ +++ +++ +++ +++ +++ +++ +++ +++ +++ +++ +++ +++ +++\n"

#define XCC_UTIL_XCRASH_DUMPER_FILENAME "libxcrash_dumper.so"

#define XCC_UTIL_CRASH_TYPE_NATIVE "native"
#define XCC_UTIL_CRASH_TYPE_ANR    "anr"

#if defined(__arm__)
#define XCC_UTIL_ABI_STRING "arm"
#elif defined(__aarch64__)
#define XCC_UTIL_ABI_STRING "arm64"
#elif defined(__i386__)
#define XCC_UTIL_ABI_STRING "x86"
#elif defined(__x86_64__)
#define XCC_UTIL_ABI_STRING "x86_64"
#else
#define XCC_UTIL_ABI_STRING "unknown"
#endif

#if defined(__LP64__)
#define XCC_UTIL_FMT_ADDR "16"PRIxPTR
#else
#define XCC_UTIL_FMT_ADDR "8"PRIxPTR
#endif

#define XCC_UTIL_SYSCALL_GETDENTS SYS_getdents64

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"
typedef struct {
    ino64_t d_ino;
    off64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[1];
} xcc_util_dirent_t;
#pragma clang diagnostic pop

#define XCC_UTIL_MAX(a,b) ({         \
            __typeof__ (a) _a = (a); \
            __typeof__ (b) _b = (b); \
            _a > _b ? _a : _b; })

#define XCC_UTIL_MIN(a,b) ({         \
            __typeof__ (a) _a = (a); \
            __typeof__ (b) _b = (b); \
            _a < _b ? _a : _b; })

/**
 * __typeof__()、__typeof()、typeof()都是C的扩展，且意思是相同的，标准C不包括这样的运算符.
 * GUN C的扩展，它可以取得变量的类型，或者表达式的类型
 *
 * - EINTR:
 * 慢系统调用(slow system call): 此术语适用于那些可能永远阻塞的系统调用。永远阻塞的系统调用是指调用有可能永远
 * 无法返回，多数网络支持函数都属于这一类。如：若没有客户连接到服务器上，那么服务器的accept调用就没有返回的保证.
 * - EINTR错误的产生：当阻塞于某个慢系统调用的一个进程捕获某个信号且相应信号处理函数返回时，该系统调用可能返回一
 * 个EINTR错误。例如：在socket服务器端，设置了信号捕获机制，有子进程，当在父进程阻塞于慢系统调用时由父进程捕获到
 * 了一个有效信号时，内核会致使accept返回一个EINTR错误(被中断的系统调用).
 * 当碰到EINTR错误的时候，可以采取有一些可以重启的系统调用要进行重启，而对于有一些系统调用是不能够重启的。例如:
 * accept、read、write、select、和open之类的函数来说，是可以进行重启的。不过对于套接字编程中的connect函数我
 * 们是不能重启的，若connect函数返回一个EINTR错误的时候，我们不能再次调用它，否则将立即返回一个错误。针对connect
 * 不能重启的处理方法是，必须调用select来等待连接完成
 *
 * errno变量是Linux系统提供的一个全局错误码变量，system call会设置该变量的值.
 *
 * 通过上面对这个EINTR(是errno的一种)，这里举一反三，取其意.
 */
#define XCC_UTIL_TEMP_FAILURE_RETRY(exp) ({         \
            __typeof__(exp) _rc;                    \
            do {                                    \
                errno = 0;                          \
                _rc = (exp);                        \
            } while (_rc == -1 && errno == EINTR);  \
            _rc;                                    \
        })

#ifndef __LP64__
#define XCC_UTIL_LIBC     "/system/lib/libc.so"
#define XCC_UTIL_LIBC_Q   "/apex/com.android.runtime/lib/bionic/libc.so"
#define XCC_UTIL_LIBCPP   "/system/lib/libc++.so"
#define XCC_UTIL_LIBCPP_Q "/apex/com.android.runtime/lib/libc++.so"
#define XCC_UTIL_LIBART   "/system/lib/libart.so"
#define XCC_UTIL_LIBART_Q "/apex/com.android.runtime/lib/libart.so"
#define XCC_UTIL_LIBART_R "/apex/com.android.art/lib/libart.so"
#else
#define XCC_UTIL_LIBC     "/system/lib64/libc.so"
#define XCC_UTIL_LIBC_Q   "/apex/com.android.runtime/lib64/bionic/libc.so"
#define XCC_UTIL_LIBCPP   "/system/lib64/libc++.so"
#define XCC_UTIL_LIBCPP_Q "/apex/com.android.runtime/lib64/libc++.so"
#define XCC_UTIL_LIBART   "/system/lib64/libart.so"
#define XCC_UTIL_LIBART_Q "/apex/com.android.runtime/lib64/libart.so"
#define XCC_UTIL_LIBART_R "/apex/com.android.art/lib64/libart.so"
#endif

#define XCC_UTIL_LIBC_ABORT_MSG_PTR      "__abort_message_ptr"
#define XCC_UTIL_LIBC_SET_ABORT_MSG      "android_set_abort_message"
#define XCC_UTIL_LIBCPP_CERR             "_ZNSt3__14cerrE"
#define XCC_UTIL_LIBART_RUNTIME_INSTANCE "_ZN3art7Runtime9instance_E"

#define XCC_UTIL_LIBART_RUNTIME_DUMP \
        "_ZN3art7Runtime14DumpForSigQuitERNSt3__113basic_ostreamIcNS1_11char_traitsIcEEEE"

#define XCC_UTIL_LIBART_THREAD_CURRENT   "_ZN3art6Thread14CurrentFromGdbEv"

#define XCC_UTIL_LIBART_THREAD_DUMP \
        "_ZNK3art6Thread13DumpJavaStackERNSt3__113basic_ostreamIcNS1_11char_traitsIcEEEE"

#define XCC_UTIL_LIBART_THREAD_DUMP2 \
        "_ZNK3art6Thread13DumpJavaStackERNSt3__113basic_ostreamIcNS1_11char_traitsIcEEEEbb"

#define XCC_UTIL_LIBART_DBG_SUSPEND      "_ZN3art3Dbg9SuspendVMEv"
#define XCC_UTIL_LIBART_DBG_RESUME       "_ZN3art3Dbg8ResumeVMEv"

typedef void  (*xcc_util_libc_set_abort_message_t)(const char* msg);
typedef void  (*xcc_util_libart_runtime_dump_t)(void* runtime, void* ostream);
typedef void* (*xcc_util_libart_thread_current_t)(void);
typedef void  (*xcc_util_libart_thread_dump_t)(void* thread, void* ostream);

typedef void  (*xcc_util_libart_thread_dump2_t)(void* thread, void* ostream,
                                                int check_suspended,
                                                int dump_locks);

typedef void  (*xcc_util_libart_dbg_suspend_t)();
typedef void  (*xcc_util_libart_dbg_resume_t)();

const char* xcc_util_get_signame(const siginfo_t* si);
const char* xcc_util_get_sigcodename(const siginfo_t* si);
int xcc_util_signal_has_si_addr(const siginfo_t* si);
int xcc_util_signal_has_sender(const siginfo_t* si, pid_t caller_pid);

char* xcc_util_trim(char* start);
int xcc_util_atoi(const char* str, int* i);

int xcc_util_write(int fd, const char *buf, size_t len);
int xcc_util_write_str(int fd, const char* str);
int xcc_util_write_format(int fd, const char* format, ...);
int xcc_util_write_format_safe(int fd, const char* format, ...);

char* xcc_util_gets(char* s, size_t size, int fd);
int xcc_util_read_file_line(const char* path, char* buf, size_t len);

void xcc_util_get_process_name(pid_t pid, char* buf, size_t len);
void xcc_util_get_thread_name(pid_t tid, char* buf, size_t len);

int xcc_util_record_sub_section_from(int log_fd, const char* path, const char* title, size_t limit);

int xcc_util_is_root(void);

size_t xcc_util_get_dump_header(char* buf,
                                size_t buf_len,
                                const char* crash_type,
                                long time_zone,
                                uint64_t start_time,
                                uint64_t crash_time,
                                const char* app_id,
                                const char* app_version,
                                int api_level,
                                const char* os_version,
                                const char* kernel_version,
                                const char* abi_list,
                                const char* manufacturer,
                                const char* brand,
                                const char* model,
                                const char* build_fingerprint);

int xcc_util_record_logcat(int fd,
                           pid_t pid,
                           int api_level,
                           unsigned int logcat_system_lines,
                           unsigned int logcat_events_lines,
                           unsigned int logcat_main_lines);

int xcc_util_record_fds(int fd, pid_t pid);

int xcc_util_record_network_info(int fd, pid_t pid, int api_level);

#ifdef __cplusplus
}
#endif

#endif
