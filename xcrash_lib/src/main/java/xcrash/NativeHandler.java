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
package xcrash;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Build;
import android.text.TextUtils;

import java.io.File;
import java.util.Map;

/**
 * native异常处理器
 * 在捕获Native异常中，原理上面基本是采用Linux的信号机制。
 *
 * 不错的Native Crash实例分析：https://caikelun.io/
 * - Native Crash问题，有如下特点：
 * 1. 从 tombstone 看不出问题的根本原因
 * 2. 崩溃点本身都不在业务逻辑可控的范围内
 * 3. 大多数发生在会导致线程 block 的调用的后一条指令处
 * 4. 都发生在动态下载的so库中。（注意so库都在files目录中）
 * 5. 设备机型和操作系统版本分布无明显特征
 * 6. 99%以上发生在非root的设备上。（现在 root 手机的用户越来越少了）
 *
 * - Native Crash 捕获的通用方案:
 * 无论是安卓系统的 debuggerd，还是 xCrash，或者 Breakpad，在捕获 native 崩溃时，都会经历以下几个阶段：
 * 1. 崩溃进程的 signal handler 被唤起执行
 * 2. clone() 子进程。
 * 3. 在子进程中 ptrace() attach 到崩溃进程的各个线程
 * 4. 读取崩溃进程中各个线程的寄存器、内存、ELF 等信息
 * 5. 将信息直接写入 dump 文件；或者进一步分析提取 backtrace 等信息写入 dump 文件
 * 在子进程 attach 到崩溃进程的所有线程之前，崩溃进程仍然还在执行。如果考虑安卓 app 的多进程情况，那么在整个崩溃捕获
 * 期间，app 的其他进程也都可能在执行中，崩溃捕获的机制也是由代码实现的，它们需要被一步一步的执行。我们可以想象：当案
 * 件（崩溃）发生时，警察（崩溃捕获机制）赶到案发现场是需要一定的时间的，这段时间就是 “视觉的盲区”。
 * 对于我们前面描述的崩溃问题，在进程崩溃之后，但在 xCrash 开始执行并记录崩溃信息之前，一定还发生了一些我们所不知道的
 * 事情，案发现场的某些细节被篡改了！
 *
 * - backtrace 不完整的常见原因
 * 有时候分析native crash堆栈时，经常会出现日志不全的问题，究其原因：
 * 1. 崩溃时 stack 内存被大量误写。如果崩溃点附近的逻辑正在处理的外部输入随机性很大，情况就更加糟糕，往往会看到大量离
 * 散的不完整 backtrace
 * 2. 调用路径上的某些 ELF 文件的 unwind table 不完整。比如某些系统的 odex/oat，还有系统的 WebView Chromium，都
 * 属于此类
 * 3. 调用路径上的某些 ELF 文件本身损坏了，或被移除了。另外，如果崩溃点本身位于损坏的ELF中，有时收到的信号会是SIGBUS
 * 4. 执行的指令位于 SharedMemory 中，此时读取到的 ELF 内容可能是不可靠的，为了避免误导，一般都会选择主动终止 unwind
 *
 * - 对于程序的崩溃问题，无论是面对 Linux 的 coredump 还是 Android 的 tombstone，我们最终都需要进行俗称为 “验尸”
 * 的过程。有时候，我们会遇到一些堪称完美的 “犯罪现场”。
 *
 * - 一般 Native Crash 快照包括：
 * 1. Signal机制触发的Core dump：包括信号字、错误码、发生crash的16进制地址
 * 2. 寄存器快照: r0/r1...、pc、sp、lr等，Arm汇编基础知识：
 * (1) 处理器寄存器被指定为R0、R1等
 * (2) MOVE指令的源位于左侧，目标位于右侧
 * (3) 伪处理程序中的栈从高地址增长到低地址。因此，push会导致栈指针的递减。pop会导致栈指针的增量
 * (4) 寄存器 sp(stack pointer) 用于指向栈
 * (5) 寄存器 fp(frame pointer) 用作帧指针。帧指针充当被调用函数和调用函数之间的锚
 * (6) 当调用一个函数时，该函数首先将 fp 的当前值保存在栈上。然后，它将 sp 寄存器的值保存在 fp 寄存器中。然后递减
 *     sp 寄存器来为本地变量分配空间 -- 这个过程其实完成了函数栈帧的切换，并预分配了被子函数的栈帧空间.
 * (7) fp 寄存器用于访问本地变量和参数，局部变量位于帧指针(fp)的负偏移量处，传递给函数的参数位于帧指针(fp)的正偏移量
 * (8) 当函数返回时，fp寄存器被复制到sp寄存器中，这将释放用于局部变量的栈帧，函数调用者的fp寄存器的值由pop从堆栈中恢
 *     复 -- 这个过程是父函数栈帧的恢复
 *
 * rx(x=0~9)代表整数寄存器
 * dx(0~31)是浮点指针寄存器
 * fp(或者r11): 寄存器 fp(frame pointer) 用作帧指针，帧指针充当被调用函数和调用函数之间的锚
 * ip(或者r12):
 * sp(或者r13): 寄存器 sp(stack pointer) 用于指向栈顶
 *
 * 3. backtrace: 序号越小就越靠近调用末端，pc指向的偏移地址(16进制)可还原出行号、对应汇编地址
 * 4. stack: 显示调用关系，由编译期决定的分配释放的内存空间,
 */
@SuppressLint("StaticFieldLeak")
class NativeHandler {
    private long anrTimeoutMs = 15 * 1000;

    private Context ctx;
    private boolean crashRethrow;
    private ICrashCallback crashCallback;
    private boolean anrEnable;
    private boolean anrCheckProcessState;
    private ICrashCallback anrCallback;

    private boolean initNativeLibOk = false;

    private static final NativeHandler instance = new NativeHandler();

    private NativeHandler() {
    }

    static NativeHandler getInstance() {
        return instance;
    }

    /**
     * 加载so动态库
     * 初始化C/C++库，用于捕获Native异常。
     */
    int initialize(Context ctx,
                   ILibLoader libLoader,
                   String appId,
                   String appVersion,
                   String logDir,
                   boolean crashEnable,
                   boolean crashRethrow,
                   int crashLogcatSystemLines,
                   int crashLogcatEventsLines,
                   int crashLogcatMainLines,
                   boolean crashDumpElfHash,
                   boolean crashDumpMap,
                   boolean crashDumpFds,
                   boolean crashDumpNetworkInfo,
                   boolean crashDumpAllThreads,
                   int crashDumpAllThreadsCountMax,
                   String[] crashDumpAllThreadsAllowList,
                   ICrashCallback crashCallback,
                   boolean anrEnable,
                   boolean anrRethrow,
                   boolean anrCheckProcessState,
                   int anrLogcatSystemLines,
                   int anrLogcatEventsLines,
                   int anrLogcatMainLines,
                   boolean anrDumpFds,
                   boolean anrDumpNetworkInfo,
                   ICrashCallback anrCallback) {

        // load lib 加载libxcrash.so
        if (libLoader == null) {
            try {
                System.loadLibrary("xcrash");
            } catch (Throwable e) {
                XCrash.getLogger().e(Util.TAG, "NativeHandler System.loadLibrary failed", e);
                return Errno.LOAD_LIBRARY_FAILED;
            }
        } else {
            try { // 指定路径下面加载
                libLoader.loadLibrary("xcrash");
            } catch (Throwable e) {
                XCrash.getLogger().e(Util.TAG, "NativeHandler ILibLoader.loadLibrary failed", e);
                return Errno.LOAD_LIBRARY_FAILED;
            }
        }

        this.ctx = ctx;
        this.crashRethrow = crashRethrow;
        this.crashCallback = crashCallback;
        this.anrEnable = anrEnable;
        this.anrCheckProcessState = anrCheckProcessState;
        this.anrCallback = anrCallback;
        //setting rethrow to "false" is NOT recommended
        this.anrTimeoutMs = anrRethrow ? 15 * 1000 : 30 * 1000;

        // init native lib
        try {
            int r = nativeInit(
                Build.VERSION.SDK_INT,
                Build.VERSION.RELEASE,
                Util.getAbiList(),
                Build.MANUFACTURER,
                Build.BRAND,
                Build.MODEL,
                Build.FINGERPRINT,
                appId,
                appVersion,
                ctx.getApplicationInfo().nativeLibraryDir,
                logDir,
                crashEnable,
                crashRethrow,
                crashLogcatSystemLines,
                crashLogcatEventsLines,
                crashLogcatMainLines,
                crashDumpElfHash,
                crashDumpMap,
                crashDumpFds,
                crashDumpNetworkInfo,
                crashDumpAllThreads,
                crashDumpAllThreadsCountMax,
                crashDumpAllThreadsAllowList,
                anrEnable,
                anrRethrow,
                anrLogcatSystemLines,
                anrLogcatEventsLines,
                anrLogcatMainLines,
                anrDumpFds,
                anrDumpNetworkInfo);

            if (r != 0) {
                XCrash.getLogger().e(Util.TAG, "NativeHandler init failed");
                return Errno.INIT_LIBRARY_FAILED;
            }
            initNativeLibOk = true;
            return 0; //OK
        } catch (Throwable e) {
            XCrash.getLogger().e(Util.TAG, "NativeHandler init failed", e);
            return Errno.INIT_LIBRARY_FAILED;
        }
    }

    void notifyJavaCrashed() {
        if (initNativeLibOk && anrEnable) {
            NativeHandler.nativeNotifyJavaCrashed();
        }
    }

    void testNativeCrash(boolean runInNewThread) {
        if (initNativeLibOk) {
            NativeHandler.nativeTestCrash(runInNewThread ? 1 : 0);
        }
    }

    private static String getStacktraceByThreadName(boolean isMainThread, String threadName) {
        try {
            for (Map.Entry<Thread, StackTraceElement[]> entry : Thread.getAllStackTraces().entrySet()) {
                Thread thd = entry.getKey();
                if ((isMainThread && thd.getName().equals("main")) ||
                        (!isMainThread && thd.getName().contains(threadName))) {

                    StringBuilder sb = new StringBuilder();
                    for (StackTraceElement element : entry.getValue()) {
                        sb.append("    at ").append(element.toString()).append("\n");
                    }
                    return sb.toString();
                }
            }
        } catch (Exception e) {
            XCrash.getLogger().e(Util.TAG, "NativeHandler getStacktraceByThreadName failed", e);
        }
        return null;
    }

    // do NOT obfuscate this method，被jni层调用
    private static void crashCallback(String logPath, String emergency,
                                      boolean dumpJavaStacktrace,
                                      boolean isMainThread, String threadName) {

        if (!TextUtils.isEmpty(logPath)) {

            //append java stacktrace
            if (dumpJavaStacktrace) {
                String stacktrace = getStacktraceByThreadName(isMainThread, threadName);
                if (!TextUtils.isEmpty(stacktrace)) {
                    TombstoneManager.appendSection(logPath, "java stacktrace", stacktrace);
                }
            }

            //append memory info
            TombstoneManager.appendSection(logPath, "memory info", Util.getProcessMemoryInfo());

            //append background / foreground
            TombstoneManager.appendSection(logPath, "foreground",
                    ActivityMonitor.getInstance().isApplicationForeground() ? "yes" : "no");
        }

        ICrashCallback callback = NativeHandler.getInstance().crashCallback;
        if (callback != null) {
            try {
                callback.onCrash(logPath, emergency);
            } catch (Exception e) {
                XCrash.getLogger().w(Util.TAG, "NativeHandler native crash callback.onCrash failed", e);
            }
        }

        if (!NativeHandler.getInstance().crashRethrow) {
            ActivityMonitor.getInstance().finishAllActivities();
        }
    }

    // do NOT obfuscate this method，这个函数在JNI层被调用，需要keep
    private static void traceCallback(String logPath, String emergency) {
        if (TextUtils.isEmpty(logPath)) {
            return;
        }

        //append memory info
        TombstoneManager.appendSection(logPath, "memory info", Util.getProcessMemoryInfo());

        //append background / foreground
        TombstoneManager.appendSection(logPath, "foreground",
                ActivityMonitor.getInstance().isApplicationForeground() ? "yes" : "no");

        //check process ANR state
        if (NativeHandler.getInstance().anrCheckProcessState) {
            if (!Util.checkProcessAnrState(NativeHandler.getInstance().ctx,
                    NativeHandler.getInstance().anrTimeoutMs)) {

                FileManager.getInstance().recycleLogFile(new File(logPath));
                return; //not an ANR
            }
        }

        //delete extra ANR log files
        if (!FileManager.getInstance().maintainAnr()) {
            return;
        }

        //rename trace log file to ANR log file
        String anrLogPath = logPath.substring(0, logPath.length() -
                Util.traceLogSuffix.length()) + Util.anrLogSuffix;

        File traceFile = new File(logPath);
        File anrFile = new File(anrLogPath);
        if (!traceFile.renameTo(anrFile)) {
            FileManager.getInstance().recycleLogFile(traceFile);
            return;
        }

        ICrashCallback callback = NativeHandler.getInstance().anrCallback;
        if (callback != null) {
            try {
                callback.onCrash(anrLogPath, emergency);
            } catch (Exception e) {
                XCrash.getLogger().w(Util.TAG, "NativeHandler ANR callback.onCrash failed", e);
            }
        }
    }

    private static native int nativeInit(
            int apiLevel,
            String osVersion,
            String abiList,
            String manufacturer,
            String brand,
            String model,
            String buildFingerprint,
            String appId,
            String appVersion,
            String appLibDir,
            String logDir,
            boolean crashEnable,
            boolean crashRethrow,
            int crashLogcatSystemLines,
            int crashLogcatEventsLines,
            int crashLogcatMainLines,
            boolean crashDumpElfHash,
            boolean crashDumpMap,
            boolean crashDumpFds,
            boolean crashDumpNetworkInfo,
            boolean crashDumpAllThreads,
            int crashDumpAllThreadsCountMax,
            String[] crashDumpAllThreadsAllowList,
            boolean traceEnable,
            boolean traceRethrow,
            int traceLogcatSystemLines,
            int traceLogcatEventsLines,
            int traceLogcatMainLines,
            boolean traceDumpFds,
            boolean traceDumpNetworkInfo);

    /**
     * 通知natvie异常信息
     */
    private static native void nativeNotifyJavaCrashed();

    private static native void nativeTestCrash(int runInNewThread);
}
