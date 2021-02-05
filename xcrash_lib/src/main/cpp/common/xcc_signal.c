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

// 1.程序奔溃
// 在Unix-like系统中，所有的崩溃都是编程错误或者硬件错误相关的，系统遇到不可恢复的错误时会触发崩溃机制让程序退出，如
// 除零、段地址错误等。异常发生时，CPU 通过异常中断的方式，触发异常处理流程。不同的处理器，有不同的异常中断类型和中断
// 处理方式。
// Linux把这些中断处理，统一为信号，可以注册信号向量进行处理。
// 信号机制是进程之间相互传递消息的一种方法，信号全称为软中断信号。
//
// 2.信号机制
// 函数运行在用户态，当遇到系统调用、中断或是异常的情况时，程序会进入内核态。信号涉及到了这两种状态之间的转换。
// (1) 信号的接收
// 接收信号的任务是由内核代理的，当内核接收到信号后，会将其放到对应进程的信号队列中，同时向进程发送一个中断，使其陷入
// 内核态。注意，此时信号还只是在队列中，对进程来说暂时是不知道有信号到来的。
// (2) 信号的检测
// 进程陷入内核态后，有两种场景会对信号进行检测：
// 场景1：进程从内核态返回到用户态前进行信号检测
// 场景2：进程在内核态中，从睡眠状态被唤醒的时候进行信号检测
// 当发现有新信号时，便会进入下一步: 信号的处理.
// (3) 信号的处理
// 信号处理函数是运行在用户态的，调用处理函数前，内核会将当前内核栈的内容备份拷贝到用户栈上，并且修改指令寄存器（eip）
// 将其指向信号处理函数。
// 接下来进程返回到用户态中，执行相应的信号处理函数。
// 信号处理函数执行完成后，还需要返回内核态，检查是否还有其它信号未处理。如果所有信号都处理完成，就会将内核栈恢复（从
// 用户栈的备份拷贝回来），同时恢复指令寄存器（eip）将其指向中断前的运行位置，最后回到用户态继续执行进程。
// 至此，一个完整的信号处理流程便结束了，如果同时有多个信号到达，上面的处理流程会在第2步和第3步骤间重复进行。如果同时
// 有多个信号到达，上面的处理流程会在第(2)步和第(3)步骤间重复进行
//
// - 捕捉Native Crash
// 1.注册信号处理函数
// 第1步就是要用信号处理函数捕获到Native Crash(SIGSEGV, SIGBUS等)。在POSIX系统用sigaction()
// 2.设置额外栈空间
// 使用sigaltstack()，SIGSEGV 很有可能是栈溢出引起的，如果在默认的栈上运行很有可能会破坏程序运行的现场，无法获取到
// 正确的上下文。而且当栈满了（太多次递归，栈上太多对象），系统会在同一个已经满了的栈上调用 SIGSEGV 的信号处理函数，
// 又再一次引起同样的信号。
// 我们应该开辟一块新的空间作为运行信号处理函数的栈。可以使用 sigaltstack()在任意线程注册一个可选的栈，保留一下在紧
// 急情况下使用的空间。（系统会在危险情况下把栈指针指向这个地方，使得可以在一个新的栈上运行信号处理函数）.
// 3.兼容其他signal处理
// 某些信号可能在之前已经被安装过信号处理函数，而sigaction一个信号量只能注册一个处理函数，这意味着我们的处理函数会覆
// 盖其他人的处理信号，保存旧的处理函数，在处理完我们的信号处理函数后，在重新运行老的处理函数就能完成兼容。

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <signal.h>
#include <sys/syscall.h>
#include <android/log.h>
#include "xcc_signal.h"
#include "xcc_errno.h"
#include "xcc_libc_support.h"

#define XCC_SIGNAL_CRASH_STACK_SIZE (1024 * 128) // 128K

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"

typedef struct {
  int signum; // 信号字
  struct sigaction oldact; // 旧的信号处理器(包括了信号处理函数)
} xcc_signal_crash_info_t;
#pragma clang diagnostic pop

// #pragma 预处理指令，最初的目的是为了使得源代码在不同的编译器下兼容的，#pragma 在编译时进行计算。但它并不像如
// #ifdef...#endif 之类的宏，#pragma 的使用方式不会改变你的应用运行时的行为。一般用于:整理代码和防止编译器警告

/**
 * - 技术原理
 * 要想拦截 Native Crash，根本上是拦截C/C++层的Crash Signal(与Crash有关的信号字)
 * Naive崩溃捕获需要注册这些信号的处理函数(signal handler)，然后在信号处理函数中收集数据
 * 因为信号是以“中断”的方式出现的，可能中断任何CPU指令序列的执行，所以在信号处理函数中，只能调用“异步信号安全(
 * async-signal-safe)”的函数。例如 malloc()、calloc()、free()、snprintf()、gettimeofday() 等等都是不能
 * 使用的，C++ STL / boost 也是不能使用的。所以，在信号处理函数中我们只能不分配堆内存，需要使用堆内存只能在初
 * 始化时预分配。如果要使用不在异步信号安全白名单中的libc/bionic函数，只能直接调用 system call 或者自己实现。
 *
 * 进程崩溃前的极端情况：
 * 当崩溃捕获逻辑开始运行时，会面对很多糟糕的情况，比如：栈溢出、堆内存不可用、虚拟内存地址耗尽、FD 耗尽、Flash
 * 空间耗尽等。有时，这些极端情况的出现，本身就是导致进程崩溃的间接原因。
 * 1. 栈溢出
 * 我们需要预先用 sigaltstack() 为 signal handler 分配专门的栈内存空间，否则当遇到栈溢出时，signal handler
 * 将无法正常运行。
 * 2. 虚拟内存地址耗尽
 * 内存泄露很容易导致虚拟内存地址耗尽(特别是在32位环境中)，这意味着在signal handler中也不能使用类似mmap()的调用。
 * 3. FD 耗尽
 * FD泄露是常见的导致进程崩溃的间接原因。这意味着在signal handler中无法正常的使用依赖于FD的操作，比如无法open()
 * + read()读取/proc中的各种信息。为了不干扰APP的正常运行，我们仅仅预留了一个FD，用于在崩溃时可靠的创建出“崩溃信
 * 息记录文件”。
 * 4. Flash 空间耗尽
 * 在16G/32G存储空间的安卓设备中，这种情况经常发生。这意味着signal handler无法把崩溃信息记录到本地文件中。我们只
 * 能尝试在初始化时预先创建一些“占坑”文件，然后一直循环使用这些“占坑”文件来记录崩溃信息。如果“占坑”文件也创建失败，
 * 我们需要把最重要的一些崩溃信息（比如 backtrace）保存在内存中，然后立刻回调和发送这些信息。
 *
 * - xCrash架构与实现(http://www.itpub.net/2020/02/07/5193/)
 * 信号处理函数与子进程
 * 在信号处理函数（signal handler）代码执行的开始阶段，我们只能“忍辱偷生”：
 * 1. 遵守它的各种限制。
 * 2. 不使用堆内存。
 * 3. 自己实现需要的调用的“异步信号安全版本”，比如：snprintf()、gettimeofday()。
 * 4. 必要时直接调用 system call。
 * 但这并非长久之计，我们要尽快在信号处理函数中执行“逃逸”，即使用clone() + execl()创建新的子进程，然后在子进程
 * 中继续收集崩溃信息。这样做的目的是：
 * 1. 避开 async-signal-safe 的限制。
 * 2. 避开虚拟内存地址耗尽的问题。
 * 3. 避开 FD 耗尽的问题。
 * 4. 使用ptrace() suspend崩溃进程中所有的线程。与iOS不同，Linux/Android不支持suspend本进程内的线程。（如果
 *    不做suspend，则其他未崩溃的线程还在继续执行，还在继续写logcat，当我们收集logcat时，崩溃时间点附近的logcat
 *    可能早已被淹没。类似的，其他的业务log buffers也存在被淹没的问题。）
 * 5. 除了崩溃线程本身的registers、backtrace等，还能用ptrace()收集到进程中其他所有线程的registers、backtrace
 *    等信息，这对于某些崩溃问题的分析是有意义的。
 * 6. 更安全的读取内存数据。（ptrace读数据失败会返回错误码，但是在崩溃线程内直接读内存数据，如果内存地址非法，会导
 *    致段错误）
 * xCrash 整体分为两部分：运行于崩溃的APP进程内的部分，和独立进程的部分（我们称为 dumper）。
 * (2) Native 部分：
 * ① JNI Bridge。负责与 Java 层的交互。（传参与回调）
 * ② Signal handlers。负责信号捕获，以及启动独立进程 dumper。
 * ③ Fallback mode。负责当 dumper 捕获崩溃信息失败时，尝试在崩溃进行的 signal handler 中收集崩溃信息。
 *
 * Linux系统共定义了64种信号，分为两大类：可靠信号与不可靠信号，前32种信号为不可靠信号，后32种为可靠信号。
 * (http://gityuan.com/2015/12/20/signal/)，不可靠信号: 也称为非实时信号，不支持排队，信号可能会丢失,比如发送
 * 多次相同的信号, 进程只能收到一次. 信号值取值区间为1~31；可靠信号: 也称为实时信号，支持排队, 信号不会丢失, 发多
 * 少次, 就可以收到多少次. 信号值取值区间为32~64
 *
 * (https://blog.csdn.net/u010168781/article/details/84667052)
 * Native Crash处理原理:
 * 1、原理
 * 在堆中为信号处理函数分配一块区域，作为该函数的栈使用，当系统默认的栈空间用尽时，调用信号处理函数使用的栈是在堆中分
 * 配的空间，而不是系统默认的栈中，所以它仍旧可以继续工作，执行崩溃处理程序。
 * 崩溃处理使用的LSM（Linux security module)Linux安全模块中yama部分,（函数：prctl(PR_SET_PTRACER…）。Yama主
 * 要是对Ptrace函数调用进行访问控制。Ptrace是一个系统调用，它提供了一种方法来让‘父’进程可以观察和控制其它进程的执行，
 * 检查和改变其核心映像以及寄存器。主要用来实现断点调试和系统调用跟踪。利用ptrace函数，不仅可以劫持另一个进程的调用，
 * 修改系统函数调用和改变返回值，而且可以向另一个函数注入代码，修改eip，进入自己的逻辑。这个函数广泛用于调试和信号跟
 * 踪工具。所以说，对ptrace函数进行访问控制还是很有必要的。
 *
 * prctl(PR_SET_PTRACER涉及到LSM（Linux security module)Linux安全模块中yama部分。
 * Yama主要是对Ptrace函数调用进行访问控制，利用ptrace函数，不仅可以劫持另一个进程的调用，修改系统函数调用和改变返回
 * 值，而且可以向另一个函数注入代码，修改eip，进入自己的逻辑。这个函数广泛用于调试和信号跟踪工具。
 */
static xcc_signal_crash_info_t xcc_signal_crash_info[] = {
  // 调用abort()/kill()/tkill()/tgkill()自杀，或被其他进程通过kill()/tkill()/tgkill()他杀
  {.signum = SIGABRT},  // abort发出的信号(用户态进程发出的)
  {.signum = SIGBUS},   // 非法内存访问，错误的物理设备地址访问(kernel发出的信号)
  {.signum = SIGFPE},   // 浮点异常，除数为零(kernel发出的信号)
  {.signum = SIGILL},   // 非法指令，无法识别的CPU指令(kernel发出的信号)
  {.signum = SIGSEGV},  // 无效内存访问(段错误)，错误的虚拟内存地址访问(kernel发出的信号)
  {.signum = SIGTRAP},  // 断点或陷阱指令
  {.signum = SIGSYS},   // 系统调用异常，无法识别的系统调用(system call)(kernel发出的信号)
  {.signum = SIGSTKFLT} // 栈溢出
};

/**
 * 注册Crash信号字处理函数
 */
int xcc_signal_crash_register(void (*handler) (int, siginfo_t*, void*)) {
  stack_t ss;

  // 为SIGSEGV信号处理程序设置一个替代堆栈。当发生无效内存访问等段错误时，也能够处理SIGSEGV。
  if (NULL == (ss.ss_sp = calloc(1, XCC_SIGNAL_CRASH_STACK_SIZE))) {
    return XCC_ERRNO_NOMEM;
  }

  ss.ss_size = XCC_SIGNAL_CRASH_STACK_SIZE;
  ss.ss_flags = 0;

  // 该函数设计内存方面的知识(http://www.groad.net/bbs/forum.php?mod=viewthread&tid=7336):
  // 一般情况下，信号处理函数被调用时，内核会在进程的栈上为其创建一个栈帧。但是这里就会有一个问题，如果栈的增长到达
  // 了栈的资源限制值(RLIMIT_STACK，使用ulimit命令可以查看，一般为8M)，或是栈已经长得太大(没有 RLIMIT_STACK
  // 的限制)，以致到达了映射内存(mapped memory)边界，那么此时信号处理函数就没法得到栈帧的分配。
  // 在一个进程的栈增长超过到最大的允许值时，内核会向该进程发送一个SIGSEGV信号(段错误)。如果我们在该进程里已经设
  // 置了一个捕捉 SIGSEGV 信号的处理函数，，那么此时由于进程的栈已经耗尽，因此该信号得不到处理，因此进程就会被结
  // 束掉(这也就是 SIGSEGV 信号的默认处理方式)。
  // 假如说，我们一定需要在这种极端的情况下处理SIGSEGV信号(例如：C/C++层的Crash处理)，那么还是有办法的，也就是
  // 使用 sigaltstack() 函数来实现，可用下面的步骤：
  // 1. 分配一块内存区，当然是从堆中分配，这块内存区就称为“可替换信号栈”(alternate signal stack)，顾名思义，
  //    我们就是希望将信号处理函数的栈挪到堆中，而不和进程共用一块栈区。
  // 2. 使用 sigaltstack() 系统调用，通知内核 “可替换信号栈” 已经建立。
  // 3. 接着建立信号处理函数，此时需要对 sigaction() 函数的 sa_flags 成员设立 SA_ONSTACK 标志，该标志告诉内
  //    核信号处理函数的栈帧就在 “可替换信号栈” 上建立的。
  // 回到sigaltstack()函数，该函数的第1个参数sigstack是一个stack_t结构的指针，该结构存储了一个“可替换信号栈”
  // 的位置及属性信息。第2个参数old_sigstack也是一个stack_t类型指针，它用来返回上一次建立的“可替换信号栈”的信
  // 息(如果有的话)。
  if (0 != sigaltstack(&ss, NULL)) {
    // 用于替换信号处理函数栈，有的说法是设置紧急函数栈。其原因是一般情况下，信号处理函数被调用时，内核会在进程
    // 的栈上为其创建一个栈帧。但是这里就会有一个问题，如果栈的增长到达了栈的资源限制值 (RLIMIT_STACK，使用
    // ulimit 命令可以查看，一般为 8M)，或是栈已经长得太大(没有 RLIMIT_STACK 的限制)，以致到达了映射内存(
    // mapped memory)边界，那么此时信号处理函数就没法得到栈帧的分配。
    return XCC_ERRNO_SYS;
  }

  struct sigaction act;
  memset(&act, 0, sizeof(act));
  // 信号集(sigset_t)用来描述信号的集合，每个信号占用1位(64位)。Linux所支持的所有信号可以全部或部分的出现在信
  // 号集中，主要与信号阻塞相关函数配合使用。调用该函数后，set指向的信号集中将包含Linux支持的64种信号，相当于64
  // bit都置1，即将所有信号加入至信号集
  sigfillset(&act.sa_mask);
  act.sa_sigaction = handler;
  // 参数 sa_flags 可以指定一些选项，如：SA_SIGINFO、SA_ONSTACK、SA_RESTART、SA_RESTORER。
  // 如果设置了 SA_SIGINFO，则表示使用 _sa_sigaction信号处理程序 (默认是_sa_handler)，通过参数
  // info 能够得到一些产生信号的信息。比如struct siginfo中有一个成员 si_code，当信号是 SIGBUS 时，
  // 如果 si_code 为 BUS_ADRALN，则表示“无效的地址对齐”。
  // SA_RESTORER 与 sa_restorer 配对使用，貌似也是为了返回旧的信号处理程序，但现在应该是已经弃用了。
  // SA_ONSTACK 表示使用一个替代栈
  // SA_RESTART 表示重启系统调用
  act.sa_flags = SA_RESTART | SA_SIGINFO | SA_ONSTACK; // 信号处理函数在堆上运行，而不是在栈上

  size_t i;
  for (i = 0; i < sizeof(xcc_signal_crash_info) / sizeof(xcc_signal_crash_info[0]); i++) {
    // 信号处理-sigaction()函数：
    // 该函数与signal()函数一样，用于设置与信号sig关联的动作，而oact如果不是空指针的话，就用它来保存原先对该信
    // 号的动作的位置，act则用于设置指定信号的动作。sigaction结构体定义在signal.h中，但是它至少包括以下成员：
    // void(*)(int)sa_handler：处理函数指针，相当于signal函数的func参数。
    // sigset_t sa_mask: 指定一个信号集，在调用sa_handler所指向的信号处理函数之前，该信号集将被加入到进程的
    //                   信号屏蔽字中。信号屏蔽字是指当前被阻塞的一组信号，它们不能被当前进程接收到
    // int sa_flags：信号处理修改器;
    if (0 != sigaction(xcc_signal_crash_info[i].signum, &act, &(xcc_signal_crash_info[i].oldact))) {
      return XCC_ERRNO_SYS;
    }
  }

  return 0;
}

/**
 * 注销Crash信号字处理函数，即：还原旧的信号处理函数
 */
int xcc_signal_crash_unregister() {
  int r = 0;
  size_t i;
  for (i = 0; i < sizeof(xcc_signal_crash_info) / sizeof(xcc_signal_crash_info[0]); i++) {
    if (0 != sigaction(xcc_signal_crash_info[i].signum, &(xcc_signal_crash_info[i].oldact), NULL)) {
      r = XCC_ERRNO_SYS;
    }
  }
  return r;
}

int xcc_signal_crash_ignore() {
  struct sigaction act;
  xcc_libc_support_memset(&act, 0, sizeof(act));
  sigemptyset(&act.sa_mask);
  act.sa_handler = SIG_DFL;
  act.sa_flags = SA_RESTART;

  int r = 0;
  size_t i;
  for (i = 0; i < sizeof(xcc_signal_crash_info) / sizeof(xcc_signal_crash_info[0]); i++) {
    if (0 != sigaction(xcc_signal_crash_info[i].signum, &act, NULL)) {
      r = XCC_ERRNO_SYS;
    }
  }
  return r;
}

int xcc_signal_crash_queue(siginfo_t* si) {
  if (SIGABRT == si->si_signo || SI_FROMUSER(si)) {
    // 该系统调用函数位于: glibc-syscalls.h 中
    if (0 != syscall(SYS_rt_tgsigqueueinfo, getpid(), gettid(), si->si_signo, si)) {
      return XCC_ERRNO_SYS;
    }
  }
  return 0;
}

static sigset_t xcc_signal_trace_oldset;
static struct sigaction xcc_signal_trace_oldact;

/**
 * 低版本(api level < 21)Anr监控方案: 监听 /data/anr 目录的变化。
 * 高版本(api level >= 21)方案: app已经访问不到 /data/anr 了, xCrash是不是有提供了其他的实现方案呢？实际上
 * 它上捕获了 SIGQUIT 信号，这个是 Android App 发生 ANR 时由 ActivityMangerService 向 App 发送的信号.
 */
int xcc_signal_trace_register(void (*handler) (int, siginfo_t*, void*)) {
  int r;
  sigset_t set;
  struct sigaction act;

  // un-block the SIGQUIT mask for current thread, hope this is the main thread
  // 用于将参数set信号集初始化并清空
  sigemptyset(&set);
  // 用来将参数SIGQUIT信号加入至参数set信号集里
  sigaddset(&set, SIGQUIT); // 增加一个信号到信号集
  // 在Linux的多线程中使用信号机制，与在进程中使用信号机制有着根本的区别，可以说是完全不同。在进程
  // 环境中，对信号的处理是，先注册信号处理函数，当信号异步发生时，调用处理函数来处理信号。它完全是
  // 异步的（我们完全不知到信号会在进程的那个执行点到来！）。然而信号处理函数的实现，有着许多的限制,
  // 比如有一些函数不能在信号处理函数中调用；再比如一些函数read、recv等调用时会被异步的信号给中断
  // (interrupt)，因此我们必须对在这些函数在调用时因为信号而中断的情况进行处理（判断函数返回时
  // enno 是否等于 EINTR）。但是在多线程中处理信号的原则却完全不同，它的基本原则是：将对信号的异
  // 步处理，转换成同步处理，也就是说用一个线程专门的来“同步等待”信号的到来，而其它的线程可以完全
  // 不被该信号中断/打断(interrupt)。这样就在相当程度上简化了在多线程环境中对信号的处理。而且可以
  // 保证其它的线程不受信号的影响。这样我们对信号就可以完全预测，因为它不再是异步的，而是同步的（我
  // 们完全知道信号会在哪个线程中的哪个执行点到来而被处理！）。而同步的编程模式总是比异步的编程模式
  // 简单。其实多线程相比于多进程的其中一个优点就是：多线程可以将进程中异步的东西转换成同步的来处理。
  //
  // 1.sigwait() 监听信号集set中所包含的信号，并将其存在signo中.
  // sigwait()函数暂停调用线程的执行，直到信号集中指定的信号之一被传递为止。在多线程代码中，总是使
  // 用sigwait或者sigwaitinfo或者sigtimedwait等函数来处理信号。而不是signal或者sigaction等
  // 函数。因为在一个线程中调用signal或者sigaction等函数会改变所有线程中的信号处理函数。而不是仅
  // 仅改变调用signal/sigaction的那个线程的信号处理函数。
  // 注意：调用sigwait同步等待的信号必须在调用线程中被屏蔽，并且通常应该在所有的线程中被屏蔽（这样
  // 可以保证信号绝不会被送到除了调用sigwait的任何其它线程），这是通过利用信号掩码的继承关系来达到
  // 的。
  // 2、pthread_sigmask函数：
  // 每个线程均有自己的信号屏蔽集（信号掩码），可以使用pthread_sigmask函数来屏蔽某个线程对某些信
  // 号的响应处理，仅留下需要处理该信号的线程来处理指定的信号。实现方式是：利用线程信号屏蔽集的继承
  // 关系（在主进程中对sigmask进行设置后，主进程创建出来的线程将继承主进程的掩码）
  // SIG_BLOCK:   结果集是当前集合参数集的并集
  // SIG_UNBLOCK: 结果集是当前集合参数集的差集
  // SIG_SETMASK: 结果集是由参数集指向的集
  if (0 != (r = pthread_sigmask(SIG_UNBLOCK, &set, &xcc_signal_trace_oldset))) {
    return r;
  }

  //register new signal handler for SIGQUIT
  memset(&act, 0, sizeof(act));
  sigfillset(&act.sa_mask);
  act.sa_sigaction = handler;
  act.sa_flags = SA_RESTART | SA_SIGINFO;
  if (0 != sigaction(SIGQUIT, &act, &xcc_signal_trace_oldact)) { // 注册之
    pthread_sigmask(SIG_SETMASK, &xcc_signal_trace_oldset, NULL);
    return XCC_ERRNO_SYS;
  }

  return 0;
}

void xcc_signal_trace_unregister(void) {
  pthread_sigmask(SIG_SETMASK, &xcc_signal_trace_oldset, NULL);
  sigaction(SIGQUIT, &xcc_signal_trace_oldact, NULL);
}
