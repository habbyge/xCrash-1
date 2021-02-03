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

// Created on 2019-08-13.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <inttypes.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <android/log.h>
#include "xcc_errno.h"
#include "xcc_util.h"
#include "xcc_signal.h"
#include "xcc_meminfo.h"
#include "xcc_version.h"
#include "xc_trace.h"
#include "xc_common.h"
#include "xc_dl.h"
#include "xc_jni.h"
#include "xc_util.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-statement-expression"

#define XC_TRACE_CALLBACK_METHOD_NAME      "traceCallback"
#define XC_TRACE_CALLBACK_METHOD_SIGNATURE "(Ljava/lang/String;Ljava/lang/String;)V"

#define XC_TRACE_SIGNAL_CATCHER_TID_UNLOAD    (-2)
#define XC_TRACE_SIGNAL_CATCHER_TID_UNKNOWN   (-1)
#define XC_TRACE_SIGNAL_CATCHER_THREAD_NAME   "Signal Catcher"
#define XC_TRACE_SIGNAL_CATCHER_THREAD_SIGBLK 0x1000

static int xc_trace_is_lollipop = 0;
static pid_t xc_trace_signal_catcher_tid = XC_TRACE_SIGNAL_CATCHER_TID_UNLOAD;

// symbol address in libc++.so and libart.so
// libc++.so中_ZNSt3__14cerr符号地址
static void* xc_trace_libcpp_cerr = NULL; // c++的err函数地址
// libart.so中_ZN3art7Runtime9instance_E符号地址
static void** xc_trace_libart_runtime_instance = NULL;
// art虚拟机中与err有关的符号地址
static xcc_util_libart_runtime_dump_t xc_trace_libart_runtime_dump = NULL;
static xcc_util_libart_dbg_suspend_t xc_trace_libart_dbg_suspend = NULL;
static xcc_util_libart_dbg_resume_t xc_trace_libart_dbg_resume = NULL;

static int xc_trace_symbols_loaded = 0;
static int xc_trace_symbols_status = XCC_ERRNO_NOTFND;

// init parameters
static int xc_trace_rethrow;
static unsigned int xc_trace_logcat_system_lines;
static unsigned int xc_trace_logcat_events_lines;
static unsigned int xc_trace_logcat_main_lines;
static int xc_trace_dump_fds;
static int xc_trace_dump_network_info;

//callback
static jmethodID xc_trace_cb_method = NULL;
static int xc_trace_notifier = -1; // trace文件的描述符(fd)

static void xc_trace_load_signal_catcher_tid() {
  char buf[256];
  DIR* dir;
  struct dirent* ent;
  FILE* f;
  pid_t tid;
  uint64_t sigblk;

  xc_trace_signal_catcher_tid = XC_TRACE_SIGNAL_CATCHER_TID_UNKNOWN;

  snprintf(buf, sizeof(buf), "/proc/%d/task", xc_common_process_id);
  if (NULL == (dir = opendir(buf))) {
    return;
  }
  while (NULL != (ent = readdir(dir))) {
    // get and check thread id
    if (0 != xcc_util_atoi(ent->d_name, &tid))
      continue;
    if (tid < 0)
      continue;

    // check thread name
    xcc_util_get_thread_name(tid, buf, sizeof(buf));
    if (0 != strcmp(buf, XC_TRACE_SIGNAL_CATCHER_THREAD_NAME))
      continue;

    // check signal block masks
    sigblk = 0;
    snprintf(buf, sizeof(buf), "/proc/%d/status", tid);
    if (NULL == (f = fopen(buf, "r"))) {
      break;
    }
    while (fgets(buf, sizeof(buf), f)) {
      if (1 == sscanf(buf, "SigBlk: %"SCNx64, &sigblk)) {
        break;
      }
    }
    fclose(f);
    if (XC_TRACE_SIGNAL_CATCHER_THREAD_SIGBLK != sigblk)
      continue;

    //found it
    xc_trace_signal_catcher_tid = tid;
    break;
  }
  closedir(dir);
}

static void xc_trace_send_sigquit() {
  if (XC_TRACE_SIGNAL_CATCHER_TID_UNLOAD == xc_trace_signal_catcher_tid) {
    xc_trace_load_signal_catcher_tid();
  }

  if (xc_trace_signal_catcher_tid >= 0) {
    syscall(SYS_tgkill, xc_common_process_id, xc_trace_signal_catcher_tid, SIGQUIT);
  }
}

/**
 * 加载符号表
 * xc_dl_open() 和 xc_dl_sym() 是里面比较重要的两个函数实现。xc_dl_open 是寻找到 so 被 mmap
 * 所加载的虚拟地址，xc_dl_sym 是计算 so 中相应符号(函数)的虚拟地址。其主要是从 libc++.so 中查
 * 找符号 _ZNSt3__14cerrE，对的，就是cerr；从 libart.so 中查找符号 _ZN3art7Runtime9instance_E
 * 以及 _ZN3art7Runtime14DumpForSigQuitERNSt3__113basic_ostreamIcNS1_11char_traitsIcEEEE
 * 在进程虚拟空间中的地址。针对L还需要 _ZN3art3Dbg9SuspendVMEv 和 _ZN3art3Dbg8ResumeVMEv.
 *
 * xc_dl_create() 的具体实现在 xc_dl_find_map_start() 获取 so 的基地址、xc_dl_file_open()
 * 通过 mmap 加载 so、xc_dl_parse_elf() 解析so。这里的解析so，其实就是解析elf文件，这个比较复杂，
 * 需要对elf文件格式熟悉.
 */
static int xc_trace_load_symbols() { // TODO: ing......
  xc_dl_t* libcpp = NULL; // libc++.so
  xc_dl_t* libart = NULL; // libart.so

  // only once
  if (xc_trace_symbols_loaded) {
    return xc_trace_symbols_status;
  }
  xc_trace_symbols_loaded = 1;

  // 1. libc++.so
  // 寻找到 so 被 mmap 所加载的虚拟地址
  if (xc_common_api_level >= 29) {
    libcpp = xc_dl_open(XCC_UTIL_LIBCPP_Q, XC_DL_DYNSYM);
  }
  if (NULL == libcpp && NULL == (libcpp = xc_dl_open(XCC_UTIL_LIBCPP, XC_DL_DYNSYM))) {
    goto end;
  }
  // 计算 so 中相应符号(函数)的虚拟地址
  if (NULL == (xc_trace_libcpp_cerr = xc_dl_dynsym_object(
      libcpp, XCC_UTIL_LIBCPP_CERR))) {

    goto end;
  }

  // 2. libart.so
  if (xc_common_api_level >= 30) {
    libart = xc_dl_open(XCC_UTIL_LIBART_R, XC_DL_DYNSYM);
  }

  if (NULL == libart && xc_common_api_level >= 29)
    libart = xc_dl_open(XCC_UTIL_LIBART_Q, XC_DL_DYNSYM);
  if (NULL == libart && NULL == (libart = xc_dl_open(XCC_UTIL_LIBART, XC_DL_DYNSYM)))
    goto end;
  if (NULL == (xc_trace_libart_runtime_instance = (void**)
      xc_dl_dynsym_object(libart, XCC_UTIL_LIBART_RUNTIME_INSTANCE))) {
    goto end;
  }

  if (NULL == (xc_trace_libart_runtime_dump = (xcc_util_libart_runtime_dump_t)
      xc_dl_dynsym_func(libart, XCC_UTIL_LIBART_RUNTIME_DUMP))) {
    goto end;
  }

  if (xc_trace_is_lollipop) {
    if (NULL == (xc_trace_libart_dbg_suspend = (xcc_util_libart_dbg_suspend_t)
        xc_dl_dynsym_func(libart, XCC_UTIL_LIBART_DBG_SUSPEND))) {
      goto end;
    }

    if (NULL == (xc_trace_libart_dbg_resume = (xcc_util_libart_dbg_resume_t)
        xc_dl_dynsym_func(libart, XCC_UTIL_LIBART_DBG_RESUME))) {
      goto end;
    }
  }

  // OK
  xc_trace_symbols_status = 0;

  end:
  if (NULL != libcpp) {
    xc_dl_close(&libcpp);
  }
  if (NULL != libart) {
    xc_dl_close(&libart);
  }
  return xc_trace_symbols_status;
}

static int xc_trace_logs_filter(const struct dirent* entry) {
  size_t len;

  if (DT_REG != entry->d_type) {
    return 0;
  }

  len = strlen(entry->d_name);
  if (len < XC_COMMON_LOG_NAME_MIN_TRACE) {
    return 0;
  }

  if (0 != memcmp(entry->d_name,
                  XC_COMMON_LOG_PREFIX"_",
                  XC_COMMON_LOG_PREFIX_LEN + 1)) {

    return 0;
  }
  if (0 != memcmp(entry->d_name + (len - XC_COMMON_LOG_SUFFIX_TRACE_LEN),
                  XC_COMMON_LOG_SUFFIX_TRACE, XC_COMMON_LOG_SUFFIX_TRACE_LEN)) {
    return 0;
  }

  return 1;
}

static int xc_trace_logs_clean(void) {
  struct dirent** entry_list; // dirent不仅仅指向目录，还指向目录中的具体文件
  char pathname[1024];
  int n, i, r = 0;

  if (0 > (n = scandir(xc_common_log_dir, &entry_list,
                       xc_trace_logs_filter,
                       alphasort))) {

    return XCC_ERRNO_SYS;
  }
  for (i = 0; i < n; i++) {
    snprintf(pathname, sizeof(pathname), "%s/%s",
             xc_common_log_dir,
             entry_list[i]->d_name);

    // unlink() C语言的库函数<unistd.h>，删除参数pathname指定的文件，如果该文件名为
    // 最后连接点, 但有其他进程打开了此文件, 则在所有关于此文件的文件描述词皆关闭后才会
    // 删除，如果参数pathname为一符号连接, 则此连接会被删除。返回值：成功则返回0, 失败
    // 返回-1, 错误原因存于errno
    if (0 != unlink(pathname)) {
      r = XCC_ERRNO_SYS;
    }
  }
  free(entry_list);
  return r;
}

static int xc_trace_write_header(int fd, uint64_t trace_time) {
  int r;
  char buf[1024];

  xcc_util_get_dump_header(buf, sizeof(buf),
                           XCC_UTIL_CRASH_TYPE_ANR,
                           xc_common_time_zone,
                           xc_common_start_time,
                           trace_time,
                           xc_common_app_id,
                           xc_common_app_version,
                           xc_common_api_level,
                           xc_common_os_version,
                           xc_common_kernel_version,
                           xc_common_abi_list,
                           xc_common_manufacturer,
                           xc_common_brand,
                           xc_common_model,
                           xc_common_build_fingerprint);

  if (0 != (r = xcc_util_write_str(fd, buf))) {
    return r;
  }

  return xcc_util_write_format(fd, "pid: %d  >>> %s <<<\n\n",
                               xc_common_process_id, xc_common_process_name);
}

/**
 * 在子线程中执行: SIGQUIT信号发生后，等待处理函数(注意：非信号处理函数)
 */
static void* xc_trace_dumper(void* arg) {
  JNIEnv* env = NULL;
  uint64_t data;
  uint64_t trace_time;
  int fd;
  struct timeval tv;
  char pathname[1024];
  jstring j_pathname;

  (void) arg;

  pthread_detach(pthread_self()); // 设置当前子线程不让其父线程等待

  // 这个函数的作用是：绑定 JNIEnv 到当前线程上，为了让当前子线程获取env对象实例.
  // 很多时候，你的Native代码建立自己的线程（比如这里建立anr dump线程），并在合适的时候回调
  // Java代码，我们没有办法像上面那样直接获得JNIEnv(不能夸线程使用，线程安全的)，获取它的实
  // 例需要让你的线程获取该JNIEvn，调用: JavaVM::AttachCurrentThread()，使用完之后还需要
  // 调用 JavaVM::DetachCurrentThread()函数解绑线程，需要注意的是对于一个已经绑定到JavaVM
  // 上的线程调用AttachCurrentThread不会有任何影响。如果你的线程已经绑定到了JavaVM上，你还
  // 可以通过调用JavaVM::GetEnv获取JNIEnv，如果你的线程没有绑定，这个函数返回JNI_EDETACHED.
  JavaVMAttachArgs attach_args = {
    .version = XC_JNI_VERSION,
    .name    = "xcrash_trace_dp",
    .group   = NULL
  };
  if (JNI_OK != (*xc_common_vm)->AttachCurrentThread(xc_common_vm, &env, &attach_args)) {
    goto exit;
  }

  while (1) {
    // block here, waiting for sigquit信号
    XCC_UTIL_TEMP_FAILURE_RETRY(read(xc_trace_notifier, &data, sizeof(data)));
    // 收到eventid(xc_trace_notifier)，继续下面的执行......

    // check if process already crashed
    if (xc_common_native_crashed || xc_common_java_crashed) {
      break; // 被native crash 或 java crash捷足先登了，这里不处理anr(sigquit信号)了
    }

    // trace time
    if (0 != gettimeofday(&tv, NULL)) {
      break;
    }
    trace_time = (uint64_t) (tv.tv_sec) * 1000 * 1000 + (uint64_t) tv.tv_usec;

    // Keep only one current trace 只keep一个当前的trace，清理掉还保留的旧的trace日志
    if (0 != xc_trace_logs_clean()) {
      continue;
    }

    // create and open log file
    if ((fd = xc_common_open_trace_log(pathname, sizeof(pathname), trace_time)) < 0)
      continue;

    // write header info
    if (0 != xc_trace_write_header(fd, trace_time)) {
      goto end;
    }

    // write trace info from ART runtime
    if (0 != xcc_util_write_format(fd, XCC_UTIL_THREAD_SEP"Cmd line: %s\n",
                                   xc_common_process_name))
      goto end;
    if (0 != xcc_util_write_str(fd, "Mode: ART DumpForSigQuit\n")) {
      goto end;
    }

    // 上面是打开日志trace文件，并写入头部信息，这里关注的重点是其怎么 dump art 的 trace.
    if (0 != xc_trace_load_symbols()) { // TODO: 加载符号表 ing......
      if (0 != xcc_util_write_str(fd, "Failed to load symbols.\n")) {
        goto end;
      }
      goto skip;
    }

    // 关闭fd，并指向STDERR_FILENO，即把文件中的trace信息输出到 “标准错误输出”中，再即屏幕
    // 通过 dup2() 将标准的错误输出重定向到了自己的fd中，并关闭旧的fd，这时候向fd中写入的话，
    // 是直接写入到标准错误输出中(STDERR_FILENO)
    if (dup2(fd, STDERR_FILENO) < 0) {
      if (0 != xcc_util_write_str(fd, "Failed to duplicate FD.\n")) {
        goto end;
      }
      goto skip;
    }
    if (xc_trace_is_lollipop) { // 这个版本的Android系统，则suspend
      xc_trace_libart_dbg_suspend();
    }
    // 开始dump，就是
    // _ZN3art7Runtime14DumpForSigQuitERNSt3__113basic_ostreamIcNS1_11char_traitsIcEEEE
    // 也就是调用 dump 将对 SIGQUIT 的处理输出到cerr中。这里有一个细节，就是在dump节，其通过
    // dup2()函数将标准的错误输出重定向到了自己的fd中
    xc_trace_libart_runtime_dump(*xc_trace_libart_runtime_instance,
                                 xc_trace_libcpp_cerr);

    if (xc_trace_is_lollipop) { // 这个版本的Android系统，则resume
      xc_trace_libart_dbg_resume();
    }
    dup2(xc_common_fd_null, STDERR_FILENO);

    skip:
    if (0 != xcc_util_write_str(fd, "\n"XCC_UTIL_THREAD_END"\n")) {
      goto end;
    }

    // write other info
    if (0 != xcc_util_record_logcat(fd, xc_common_process_id,
                                    xc_common_api_level, xc_trace_logcat_system_lines,
                                    xc_trace_logcat_events_lines, xc_trace_logcat_main_lines)) {

      goto end;
    }
    if (xc_trace_dump_fds) {
      if (0 != xcc_util_record_fds(fd, xc_common_process_id)) {
        goto end; // 记录当前进程中正在(已经)打开的文件描述符
      }
    }
    if (xc_trace_dump_network_info) { // dump网络信息
      if (0 != xcc_util_record_network_info(fd, xc_common_process_id,
                                            xc_common_api_level)) {
        goto end;
      }
    }
    if (0 != xcc_meminfo_record(fd, xc_common_process_id)) { // 内存信息
      goto end;
    }

    end:
    // close log file
    xc_common_close_trace_log(fd);

    // rethrow SIGQUIT to ART Signal Catcher
    if (xc_trace_rethrow) {
      xc_trace_send_sigquit();
    }

    //JNI callback
    //Do we need to implement an emergency buffer for disk exhausted?
    if (NULL == xc_trace_cb_method)
      continue;
    if (NULL == (j_pathname = (*env)->NewStringUTF(env, pathname)))
      continue;

    (*env)->CallStaticVoidMethod(env, xc_common_cb_class,
                                 xc_trace_cb_method,
                                 j_pathname, NULL);

    XC_JNI_IGNORE_PENDING_EXCEPTION();
    (*env)->DeleteLocalRef(env, j_pathname);
  }

  // 使用完之后还需要调用 JavaVM::DetachCurrentThread()函数解绑线程
  (*xc_common_vm)->DetachCurrentThread(xc_common_vm);

  exit:
  xc_trace_notifier = -1;
  close(xc_trace_notifier);
  return NULL;
}

/**
 * SIGQUIT处理函数
 */
static void xc_trace_handler(int sig, siginfo_t* si, void* uc) {
  uint64_t data;

  (void) sig;
  (void) si;
  (void) uc;

  // 发生SIGQUIT异常信号，向eventid中写入数据，通知出去，目前dump线程正在阻塞等待这个eventid
  if (xc_trace_notifier >= 0) {
    data = 1;
    XCC_UTIL_TEMP_FAILURE_RETRY(write(xc_trace_notifier, &data, sizeof(data)));
  }
}

/**
 * 获取 Java 的 methodId
 */
static void xc_trace_init_callback(JNIEnv* env) {
  if (NULL == xc_common_cb_class) return;

  // 获取Java中的callback函数id
  xc_trace_cb_method = (*env)->GetStaticMethodID(env, xc_common_cb_class,
                                                 XC_TRACE_CALLBACK_METHOD_NAME,
                                                 XC_TRACE_CALLBACK_METHOD_SIGNATURE);

  XC_JNI_CHECK_NULL_AND_PENDING_EXCEPTION(xc_trace_cb_method, err);
  return;

  err:
  xc_trace_cb_method = NULL;
}

/**
 * 主要是用来获取ANR的trace.
 */
int xc_trace_init(JNIEnv* env,
                  int rethrow,
                  unsigned int logcat_system_lines,
                  unsigned int logcat_events_lines,
                  unsigned int logcat_main_lines,
                  int dump_fds,
                  int dump_network_info) {

  int r;
  pthread_t thd;

  // capture SIGQUIT only for ART
  // 只是针对 Android 5.0 以上，因为其主要是用来获取ANR的trace，<=21，
  // 使用监控 /data/anr 目录变更的方案
  if (xc_common_api_level < 21) {
    return 0;
  }

  //is Android Lollipop (5.x)?
  xc_trace_is_lollipop = ((21 == xc_common_api_level
                           || 22 == xc_common_api_level) ? 1 : 0);

  xc_trace_rethrow = rethrow;
  xc_trace_logcat_system_lines = logcat_system_lines;
  xc_trace_logcat_events_lines = logcat_events_lines;
  xc_trace_logcat_main_lines = logcat_main_lines;
  xc_trace_dump_fds = dump_fds;
  xc_trace_dump_network_info = dump_network_info;

  // init for JNI callback
  xc_trace_init_callback(env);

  // create event FD，eventfd是Linux的一个系统调用，创建一个文件描述符用于事件通知，
  // eventfd()创建一个eventfd对象，可以由用户空间应用程序实现事件等待/通知机制，或由
  // 内核通知用户空间应用程序事件，该对象包含了由内核维护的无符号64位整数计数器count 。
  // 使用参数arg1初始化此计数器，flags可以是以下值的 OR 运算结果，用以改变 eventfd 的行为:
  // 1. EFD_CLOEXEC (since Linux 2.6.27)
  //    文件被设置成 O_CLOEXEC，创建子进程 (fork) 时不继承父进程的文件描述符。
  // 2. EFD_NONBLOCK (since Linux 2.6.27)
  //    文件被设置成 O_NONBLOCK，执行 read / write 操作时，不会阻塞。
  // 3. EFD_SEMAPHORE (since Linux 2.6.30)
  //    提供类似信号量语义的read操作，简单说就是计数值count 递减1
  // - 操作方法:
  // 一切皆为文件是Linux内核设计的一种高度抽象，eventfd的实现也不例外，我们可以使用操作
  // 文件的方法操作eventfd.
  // read(): 读取count值后置0。如果设置EFD_SEMAPHORE，读到的值为1，同时count值递减1。
  // write(): 其实是执行add操作，累加count值。
  // epoll()/poll()/select(): 支持IO多路复用操作。
  // close(): 关闭文件描述符，eventfd对象引用计数减1，若减为0，则释放eventfd对象资源。
  // - 使用场景
  // 在 pipe 仅用于发出事件信号的所有情况下，都可以使用 eventfd 取而代之。
  if (0 > (xc_trace_notifier = eventfd(0, EFD_CLOEXEC)))
    return XCC_ERRNO_SYS;

  // register signal handler
  if (0 != (r = xcc_signal_trace_register(xc_trace_handler)))
    goto err2;

  // create thread for dump trace
  // 启动一个线程，并在线程响应函数中等待ANR的发生。这里的等待机制同样是用的eventfd
  if (0 != (r = pthread_create(&thd, NULL, xc_trace_dumper, NULL)))
    goto err1;

  return 0;

  err1:
  xcc_signal_trace_unregister();
  err2:
  close(xc_trace_notifier);
  xc_trace_notifier = -1;

  return r;
}

#pragma clang diagnostic pop
