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

import android.app.Application;
import android.content.Context;
import android.os.Build;
import android.text.TextUtils;

/**
 * 在Android平台，Native Crash一直是crash里的大头。Native Crash具有上下文不全、出错信息模糊、难以捕捉等特点，
 * 比Java Crash更难修复。所以一个合格的异常捕获组件也要能达到以下目的:
 * - 支持在Crash时进行更多扩展操作
 *   - 打印logcat和应用日志
 *   - 上报crash次数
 *   - 对不同的crash做不同的恢复措施
 * - 可以针对业务不断改进和适应
 *
 * - 信号机制
 * 1.程序奔溃
 * 在Unix-like系统中，所有的崩溃都是编程错误或者硬件错误相关的，系统遇到不可恢复的错误时会触发崩溃机制让程序退出，
 * 如除零、段地址错误等。异常发生时，CPU通过异常中断的方式，触发异常处理流程。不同的处理器，有不同的异常中断类型和
 * 中断处理方式。linux把这些中断处理，统一为信号量，可以注册信号量向量进行处理。
 * 信号机制是进程之间相互传递消息的一种方法，信号全称为软中断信号。
 * 2.信号机制
 * 函数运行在用户态，当遇到系统调用、中断或是异常的情况时，程序会进入内核态。信号涉及到了这两种状态之间的转换。
 * (1) 信号的接收
 * 接收信号的任务是由内核代理的，当内核接收到信号后，会将其放到对应进程的信号队列中，同时向进程发送一个中断，使其陷
 * 入内核态。注意，此时信号还只是在队列中，对进程来说暂时是不知道有信号到来的。
 * (2) 信号的检测
 * 进程陷入内核态后，有两种场景会对信号进行检测：
 * 进程从内核态返回到用户态前进行信号检测
 * 进程在内核态中，从睡眠状态被唤醒的时候进行信号检测
 * 当发现有新信号时，便会进入下一步，信号的处理。
 * (3) 信号的处理
 * 信号处理函数是运行在用户态的，调用处理函数前，内核会将当前内核栈的内容备份拷贝到用户栈上，并且修改指令寄存器（eip）
 * 将其指向信号处理函数。接下来进程返回到用户态中，执行相应的信号处理函数。信号处理函数执行完成后，还需要返回内核态，
 * 检查是否还有其它信号未处理。如果所有信号都处理完成，就会将内核栈恢复（从用户栈的备份拷贝回来），同时恢复指令寄存器
 * （eip）将其指向中断前的运行位置，最后回到用户态继续执行进程。
 * 至此，一个完整的信号处理流程便结束了，如果同时有多个信号到达，上面的处理流程会在第2步和第3步骤间重复进行。
 * (4) 常见信号量类型
 *
 * 分析: https://juejin.im/post/6844904077428686862
 * xCrash is a crash reporting library for Android APP
 * xCrash提供捕获异常的配置和初始化的功能
 * 该sdk的入口类
 * xCrash是爱奇艺开源的在android平台上面捕获异常的开源库。xCrash能为安卓APP提供捕获Java崩溃异常，native崩溃
 * 异常和ANR异常。能在 App 进程崩溃或 ANR 时，在你指定的目录中生成一个 tombstone 文件（格式与安卓系统的
 * tombstone 文件类似）。Tombstone文件默认将被写入到 Context#getFilesDir() + “/tombstones” 目录。（通常
 * 在：/data/data/PACKAGE_NAME/files/tombstones）
 * xCrash分为两个module，是xcrash_lib，xcrash_sample。xcrash_lib是核心库，xcrash_sample是提供的测试工程.
 * 进程分为crash进程(app) 和 dump进程.
 */
public final class XCrash {
    private static boolean initialized = false; // xcrash 初始化标志
    private static String appId = null; // app应用的appId
    private static String appVersion = null; // app应用版本的版本信息
    private static String logDir = null; // 日志输出的文件夹路径
    private static ILogger logger = new DefaultLogger(); // xcrash默认的日志输出接口

    private XCrash() {
    }

    /**
     * 该sdk第1个需要执行的入口函数，初始化xCrash
     * Initialize xCrash with default parameters.
     *
     * <p>Note: This is a synchronous operation.
     *
     * @param ctx The context of the application object of the current process.
     * @return Return zero if successful, non-zero otherwise. The error code is
     *         defined in: {@link xcrash.Errno}.
     */
    public static int init(Context ctx) {
        return init(ctx, null);
    }

    /**
     * Initialize xCrash with custom parameters.
     * xCrash初始化接口，主要对配置信息保存，以及执行日志文件管理
     *
     * - 异常日志格式分析
     * 通过xCrash_sample工程可以对Android常见的异常进行测试。下面对日志文件结构进行简单的分析，以便应用发生异常时，
     * 通过日志来分析原因。以下日志文件，为采用默认配置输出的异常日志。日志文件的组成是：
     * tombstone_应用启动时间*1000_app版本_app进程名_java异常后缀，例如：
     * tombstone_00001571190344276000_1.2.3-beta456-patch789__xcrash.sample.java.xcrash
     *
     * - Java异常输出日志
     * 日志分为:
     * 1. 头部信息（为应用的基本信息）
     * 2. java stacktrace
     * 3. logcat日志输出部分，包括main,system,event
     * 4. app应用进程打开的文件描述符
     * 5. 内存信息
     * 6. app应用进程信息
     * 7. 异常回调填充信息
     *
     * - Native异常输出日志
     * 日志分为：
     * 1. 头部信息（为应用的基本信息）
     * 2. 异常信号部分。（哪个异常信号导致异常，信号参见Linux信号）
     * 3. backtrace // 表示发生错误的堆栈
     * 4. so库的编译信息，build id
     * 5. 堆栈信息
     * 6. 内存信息
     * 7. 内存映射(mmap)
     * 8. Logcat日志输出部分，包括main,system,event
     * 9. app应用进程打开的文件描述符
     * 10. 内存信息
     * 11. app应用进程信息
     * 12. 异常回调填充信息
     *
     * Native Crash分析：
     * 1. Native Crash的分析工具：
     *（1）addr2line
     * 作用：把出错backtrace 解析出来文件和行数
     * 格式：arm-linux_androideabi-addr2line -C -f -e sysbols/system/lib/xxx.so 0004097c
     * 参数：arm-linux_androideabi-addr2line ndk里面工具,可以使用locate搜索出来
     * xxx.so:位于sysbols目录下，需要具有符号表，版本需要一致
     * 0004097c：需要和backtrace里面的地址一下
     *（2）objdump
     * arm-linux_androideabi-objdump -dl xxx.so > xxx.txt
     * 把库的汇编文件放在指定xxx.txt，搜索backtrace地址，通过汇编看是否有问题*
     *（3）Coredump
     * 1.arm-linux_androideabi-gdb app_process(sysbols/system/bin目录下) -c xxx.core(data/core目录下)
     * 2.set solib-absolute-prefix symbols //加载symblos目录
     * 3.set solib-search-path system/lib //加载sysblos文件的lib目录
     * 4.symbol-file libcamera.so //加载具体的库，都是带有符号表的目录
     *
     *（4）gdb基本命令
     * bt  // check backtrace
     * f 2 // 进入第n帧，bt之后会看到第几帧
     * p this // 打印this值
     * p *this 打印地址值
     * x/12x  0x111 // 打印111地址附件的12个寄存器值 第一个x为命令  12代表个数 最后一个代表格式
     * info threads   // 列出所有线程
     * info registers // 列出所有寄存器值
     * t  2  //选择第二个线程
     * 2. 分析步骤
     * (1)找到上述DEBUG内容位置,关键字am_crash DEBUG : pid
     * (2)查看进程是否有错误，搜索pid  tid看线程log
     * (3)查看是否有系统性能问题
     * (4)检查下1中的backtrace中的问题库，是否在最近有修改，或者有个类似的问题，可以加快时间
     * (5)使用addr2line工具，看下出问题的代码，看是否找出原因
     * (6)objdump汇编文件得到之后，根据寄存器的推是不是寄存器问题
     * (7)gdb工具，加载库之后，使用f bt 之类的命令查看线程信息  backtrace 寄存器值 内存值
     * (8)根据代码和上述结果分析
     *
     * - anr异常输出日志
     * 1. 头部信息（为应用的基本信息）
     * 2. 异常信号部分。（哪个异常信号导致异常，信号参见Linux信号）
     * 3. backtrace
     * 4. 主线程信息
     * 5. 内存映射
     * 6. Logcat日志输出部分，包括main,system,event
     * 7. app应用进程打开的文件描述符
     * 8. 内存信息
     * 9. app应用进程信息
     * 10. 异常回调填充信息
     *
     * Note: This is a synchronous operation. 这是一个异步初始化操作
     *
     * @param ctx The context of the application object of the current process.
     * @param params An initialization parameter set.
     * @return Return zero if successful, non-zero otherwise. The error code is
     *         defined in: {@link xcrash.Errno}.
     */
    public static synchronized int init(Context ctx, InitParameters params) {
        // 判断是否已初始化过，如果初始化过，不允许初始化两次
        if (XCrash.initialized) {
            return Errno.OK;
        }
        XCrash.initialized = true;

        if (ctx == null) {
            return Errno.CONTEXT_IS_NULL;
        }

        // make sure to get the instance of android.app.Application
        Context appContext = ctx.getApplicationContext();
        if (appContext != null) {
            ctx = appContext;
        }

        // use default parameters
        if (params == null) {
            params = new InitParameters();
        }

        // set logger
        if (params.logger != null) {
            XCrash.logger = params.logger;
        }

        // save app id
        String packageName = ctx.getPackageName();
        XCrash.appId = packageName;
        if (TextUtils.isEmpty(XCrash.appId)) {
            XCrash.appId = "unknown";
        }

        // save app version
        if (TextUtils.isEmpty(params.appVersion)) {
            params.appVersion = Util.getAppVersion(ctx);
        }
        XCrash.appVersion = params.appVersion;

        // save log dir
        if (TextUtils.isEmpty(params.logDir)) {
            params.logDir = ctx.getFilesDir() + "/tombstones";
        }
        XCrash.logDir = params.logDir;

        // get PID and process name
        int pid = android.os.Process.myPid();
        String processName = null;
        if (params.enableJavaCrashHandler || params.enableAnrHandler) {
            processName = Util.getProcessName(pid);

            // capture only the ANR of the main process
            if (params.enableAnrHandler) {
                if (TextUtils.isEmpty(processName) || !processName.equals(packageName)) {
                    params.enableAnrHandler = false;
                }
            }
        }

        // init file manager，日志文件的管理器  异常日志文件数量，超过数量，删除最早的。
        // 其中异常日志的占位文件，在native异常或者android 5.0以后anr异常会使用到
        // 在捕获到native异常的时候，如果存在占位文件，则使用占位文件。不存在才会创建新的文件
        FileManager.getInstance().initialize(
            params.logDir, // 异常日志文件路径
            params.javaLogCountMax, // java异常日志文件数量
            params.nativeLogCountMax,
            params.anrLogCountMax,
            params.placeholderCountMax, // 异常日志的占位文件，可配置
            params.placeholderSizeKb, // 异常日志占位文件的大小
            params.logFileMaintainDelayMs); // xCrash初始化后，延迟xx毫秒，进行日志文件管理

        if (params.enableJavaCrashHandler ||
                params.enableNativeCrashHandler ||
                params.enableAnrHandler) {

            if (ctx instanceof Application) {
                ActivityMonitor.getInstance().initialize((Application) ctx);
            }
        }

        // init java crash handler, 是否捕获java异常日志
        if (params.enableJavaCrashHandler) {
            JavaCrashHandler.getInstance().initialize(
                pid,
                processName,
                appId,
                params.appVersion,
                params.logDir,
                params.javaRethrow,
                params.javaLogcatSystemLines,
                params.javaLogcatEventsLines,
                params.javaLogcatMainLines,
                params.javaDumpFds,
                params.javaDumpNetworkInfo,
                params.javaDumpAllThreads,
                params.javaDumpAllThreadsCountMax,
                params.javaDumpAllThreadsAllowList,
                params.javaCallback);
        }

        // init ANR handler (API level < 21)，更通用的方案(无版本限制)采用微信Matrix
        if (params.enableAnrHandler && Build.VERSION.SDK_INT < 21) {
            AnrHandler.getInstance().initialize(
                ctx, // context上下文
                pid, // 进程pid
                processName, // 进程名
                appId,
                params.appVersion, // app应用版本
                params.logDir, // 日志输出文件夹(目录)

                // 以下为可配置参数
                params.anrCheckProcessState,
                params.anrLogcatSystemLines,
                params.anrLogcatEventsLines,
                params.anrLogcatMainLines,
                params.anrDumpFds,
                params.anrDumpNetworkInfo,
                params.anrCallback);
        }

        // init native crash handler / ANR handler (API level >= 21)
        int r = Errno.OK;
        if (params.enableNativeCrashHandler ||
                (params.enableAnrHandler && Build.VERSION.SDK_INT >= 21)) {

            r = NativeHandler.getInstance().initialize(
                ctx,
                params.libLoader, // so库加载路径
                appId,
                params.appVersion,
                params.logDir, // 日志输出路径
                params.enableNativeCrashHandler,
                params.nativeRethrow,
                params.nativeLogcatSystemLines,
                params.nativeLogcatEventsLines,
                params.nativeLogcatMainLines,
                params.nativeDumpElfHash,
                params.nativeDumpMap,
                params.nativeDumpFds,
                params.nativeDumpNetworkInfo,
                params.nativeDumpAllThreads,
                params.nativeDumpAllThreadsCountMax,
                params.nativeDumpAllThreadsAllowList,
                params.nativeCallback,

                // 以下配置与ANR相关
                params.enableAnrHandler && Build.VERSION.SDK_INT >= 21,
                params.anrRethrow,
                params.anrCheckProcessState,
                params.anrLogcatSystemLines,
                params.anrLogcatEventsLines,
                params.anrLogcatMainLines,
                params.anrDumpFds,
                params.anrDumpNetworkInfo,
                params.anrCallback);
        }

        // maintain tombstone and placeholder files in a background thread with some delay
        // 执行日志文件管理：在后台线程中维护逻辑: 删除文件和占位符文件
        FileManager.getInstance().maintain();

        return r;
    }

    /**
     * An initialization parameter set. xCrash初始化配置参数
     * xCrash配置参数分为四个部分：1.通用输出配置；2.java异常输出配置；3.native异常输出配置；4.ANR异常输出配置。
     */
    public static class InitParameters {

        // common，通用输出配置
        // APP应用版本信息
        String     appVersion             = null;
        // 用于存放异常日志的文件夹
        String     logDir                 = null;
        // 初始化xCrash后延迟xx毫秒，进行日志文件维护任务（为清理多余的过期日志文件）
        int        logFileMaintainDelayMs = 5000;
        // xCrash库的日志输出接口
        ILogger    logger                 = null;
        // xCrash库需要加载的so文件路径
        ILibLoader libLoader              = null;

        /**
         * Set App version. You can use this method to set an internal test/gray version number.
         * (Default: {@link android.content.pm.PackageInfo#versionName})
         *
         * @param appVersion App version string.
         * @return The InitParameters object.
         */
        public InitParameters setAppVersion(String appVersion) {
            this.appVersion = appVersion;
            return this;
        }

        /**
         * Set the directory to save crash log files.
         * (Default: {@link android.content.Context#getFilesDir()} + "/tombstones")
         *
         * @param dir Absolute path to the directory.
         * @return The InitParameters object.
         */
        @SuppressWarnings("WeakerAccess")
        public InitParameters setLogDir(String dir) {
            this.logDir = dir;
            return this;
        }

        /**
         * Set delay in milliseconds before the log file maintain task is to be executed.(Default: 5000)
         *
         * @param logFileMaintainDelayMs Delay in milliseconds before the log file
         *                               maintain task is to be executed.
         * @return The InitParameters object.
         */
        public InitParameters setLogFileMaintainDelayMs(int logFileMaintainDelayMs) {
            this.logFileMaintainDelayMs = (logFileMaintainDelayMs < 0 ? 0 : logFileMaintainDelayMs);
            return this;
        }

        /**
         * Set a logger implementation for xCrash to log message and exception.
         *
         * @param logger An instance of {@link xcrash.ILogger}.
         * @return The InitParameters object.
         */
        public InitParameters setLogger(ILogger logger) {
            this.logger = logger;
            return this;
        }

        /**
         * Set a libLoader implementation for xCrash to load native library.
         *
         * @param libLoader An instance of {@link xcrash.ILibLoader}.
         * @return The InitParameters object.
         */
        public InitParameters setLibLoader(ILibLoader libLoader) {
            this.libLoader = libLoader;
            return this;
        }

        // placeholder
        int placeholderCountMax = 0;
        int placeholderSizeKb   = 128;

        /**
         * Set the maximum number of placeholder files in the log directory. (Default: 0)
         *
         * <p>Note: Set this value to 0 means disable the placeholder feature.
         *
         * @param countMax The maximum number of placeholder files.
         * @return The InitParameters object.
         */
        public InitParameters setPlaceholderCountMax(int countMax) {
            this.placeholderCountMax = (countMax < 0 ? 0 : countMax);
            return this;
        }

        /**
         * Set the KB of each placeholder files in the log directory. (Default: 128)
         *
         * @param sizeKb The KB of each placeholder files.
         * @return The InitParameters object.
         */
        public InitParameters setPlaceholderSizeKb(int sizeKb) {
            this.placeholderSizeKb = (sizeKb < 0 ? 0 : sizeKb);
            return this;
        }

        // java crash，Java异常输出配置
        // 是否使能Java异常处理器
        boolean        enableJavaCrashHandler      = true;
        // 是否继续抛出原始Java异常行为
        boolean        javaRethrow                 = true;
        // java异常文件数量
        int            javaLogCountMax             = 10;
        // 执行命令 logcat -b system 输出的日志行数
        int            javaLogcatSystemLines       = 50;
        // 执行命令 logcat -b event 输出的日志行数
        int            javaLogcatEventsLines       = 50;
        // logcat -b main 输出的日志行数
        int            javaLogcatMainLines         = 200;
        // 是否输出app应用进程的文件描述符
        boolean        javaDumpFds                 = true;
        boolean        javaDumpNetworkInfo         = true;
        // 是否输出所有线程的日志信息
        boolean        javaDumpAllThreads          = true;
        // 输出日志最多的线程数
        int            javaDumpAllThreadsCountMax  = 0;
        // 输出线程日志的线程白名单
        String[]       javaDumpAllThreadsAllowList = null;
        // 发生java异常crash的回调
        ICrashCallback javaCallback                = null;

        /**
         * Enable the Java exception capture feature. (Default: enable)
         *
         * @return The InitParameters object.
         */
        public InitParameters enableJavaCrashHandler() {
            this.enableJavaCrashHandler = true;
            return this;
        }

        /**
         * Disable the Java exception capture feature. (Default: enable)
         *
         * @return The InitParameters object.
         */
        public InitParameters disableJavaCrashHandler() {
            this.enableJavaCrashHandler = false;
            return this;
        }

        /**
         * Set whether xCrash should rethrow the Java exception to system
         * after it has been handled. (Default: true)
         *
         * @param rethrow If <code>true</code>, the Java exception will be rethrown to Android System.
         * @return The InitParameters object.
         */
        public InitParameters setJavaRethrow(boolean rethrow) {
            this.javaRethrow = rethrow;
            return this;
        }

        /**
         * Set the maximum number of Java crash log files to save in the log directory. (Default: 10)
         *
         * @param countMax The maximum number of Java crash log files.
         * @return The InitParameters object.
         */
        public InitParameters setJavaLogCountMax(int countMax) {
            this.javaLogCountMax = (countMax < 1 ? 1 : countMax);
            return this;
        }

        /**
         * Set the maximum number of rows to get from "logcat -b system" when
         * a Java exception occurred. (Default: 50)
         *
         * @param logcatSystemLines The maximum number of rows.
         * @return The InitParameters object.
         */
        public InitParameters setJavaLogcatSystemLines(int logcatSystemLines) {
            this.javaLogcatSystemLines = logcatSystemLines;
            return this;
        }

        /**
         * Set the maximum number of rows to get from "logcat -b events" when
         * a Java exception occurred. (Default: 50)
         *
         * @param logcatEventsLines The maximum number of rows.
         * @return The InitParameters object.
         */
        public InitParameters setJavaLogcatEventsLines(int logcatEventsLines) {
            this.javaLogcatEventsLines = logcatEventsLines;
            return this;
        }

        /**
         * Set the maximum number of rows to get from "logcat -b main" when
         * a Java exception occurred. (Default: 200)
         *
         * @param logcatMainLines The maximum number of rows.
         * @return The InitParameters object.
         */
        public InitParameters setJavaLogcatMainLines(int logcatMainLines) {
            this.javaLogcatMainLines = logcatMainLines;
            return this;
        }

        /**
         * Set if dumping FD list when a java crash occurred. (Default: enable)
         *
         * @param flag True or false.
         * @return The InitParameters object.
         */
        public InitParameters setJavaDumpFds(boolean flag) {
            this.javaDumpFds = flag;
            return this;
        }

        /**
         * Set if dumping network info when a java crash occurred. (Default: enable)
         *
         * @param flag True or false.
         * @return The InitParameters object.
         */
        public InitParameters setJavaDumpNetworkInfo(boolean flag) {
            this.javaDumpNetworkInfo = flag;
            return this;
        }

        /**
         * Set if dumping threads info(stacktrace)for all threads(not just the thread that has crashed)
         * when a Java exception occurred. (Default: enable)
         *
         * @param flag True or false.
         * @return The InitParameters object.
         */
        @SuppressWarnings("WeakerAccess")
        public InitParameters setJavaDumpAllThreads(boolean flag) {
            this.javaDumpAllThreads = flag;
            return this;
        }

        /**
         * Set the maximum number of other threads to dump when a Java exception occurred.
         * "0" means no limit. (Default: 0)
         *
         * <p>Note: This option is only useful when "JavaDumpAllThreads"
         * is enabled by calling {@link InitParameters#setJavaDumpAllThreads(boolean)}.
         *
         * @param countMax The maximum number of other threads to dump.
         * @return The InitParameters object.
         */
        public InitParameters setJavaDumpAllThreadsCountMax(int countMax) {
            this.javaDumpAllThreadsCountMax = (countMax < 0 ? 0 : countMax);
            return this;
        }

        /**
         * Set a thread name (regular expression) allowlist to filter which
         * threads need to be dumped when a Java exception occurred.
         * "null" means no filtering. (Default: null)
         *
         * <p>Note: This option is only useful when "JavaDumpAllThreads"
         * is enabled by calling {@link InitParameters#setJavaDumpAllThreads(boolean)}.
         *
         * @param allowList A thread name (regular expression) allowlist.
         * @return The InitParameters object.
         */
        public InitParameters setJavaDumpAllThreadsAllowList(String[] allowList) {
            this.javaDumpAllThreadsAllowList = allowList;
            return this;
        }

        /**
         * Set a callback to be executed when a Java exception occurred.
         * (If not set, nothing will be happened.)
         *
         * @param callback An instance of {@link xcrash.ICrashCallback}.
         * @return The InitParameters object.
         */
        public InitParameters setJavaCallback(ICrashCallback callback) {
            this.javaCallback = callback;
            return this;
        }

        // native crash, Native异常输出配置
        // 是否输出native异常标志
        boolean        enableNativeCrashHandler      = true;
        // 是否继续向外抛出异常
        boolean        nativeRethrow                 = true;
        // native异常文件的最大数量
        int            nativeLogCountMax             = 10;
        // 执行命令 logcat -b system 输出的日志行数
        int            nativeLogcatSystemLines       = 50;
        // 执行命令 logcat -b evnet输出的日志行数
        int            nativeLogcatEventsLines       = 50;
        // logcat -b main 输出的日志行数
        int            nativeLogcatMainLines         = 200;
        // 是否输出产生native异常的so库文件的hash值
        boolean        nativeDumpElfHash             = true;
        // 是否输出产生native异常so文件的内存映射
        boolean        nativeDumpMap                 = true;
        // 是否输出文件描述符
        boolean        nativeDumpFds                 = true;
        boolean        nativeDumpNetworkInfo         = true;
        // 是否输出所有线程的日志信息，默认为true，如果为false只输出crahs线程的信息
        boolean        nativeDumpAllThreads          = true;
        // 输出日志最多的线程数
        int            nativeDumpAllThreadsCountMax  = 0;
        // 输出线程日志的线程白名单
        String[]       nativeDumpAllThreadsAllowList = null;
        // 发生java异常crash的回调
        ICrashCallback nativeCallback                = null;

        /**
         * Enable the native crash capture feature. (Default: enable)
         *
         * @return The InitParameters object.
         */
        public InitParameters enableNativeCrashHandler() {
            this.enableNativeCrashHandler = true;
            return this;
        }

        /**
         * Disable the native crash capture feature. (Default: enable)
         *
         * @return The InitParameters object.
         */
        public InitParameters disableNativeCrashHandler() {
            this.enableNativeCrashHandler = false;
            return this;
        }

        /**
         * Set whether xCrash should rethrow the crash native signal to system
         * after it has been handled. (Default: true)
         *
         * @param rethrow If <code>true</code>, the native signal will be rethrown to Android System.
         * @return The InitParameters object.
         */
        public InitParameters setNativeRethrow(boolean rethrow) {
            this.nativeRethrow = rethrow;
            return this;
        }

        /**
         * Set the maximum number of native crash log files to save in the log directory.(Default: 10)
         *
         * @param countMax The maximum number of native crash log files.
         * @return The InitParameters object.
         */
        public InitParameters setNativeLogCountMax(int countMax) {
            this.nativeLogCountMax = (countMax < 1 ? 1 : countMax);
            return this;
        }

        /**
         * Set the maximum number of rows to get from "logcat -b system"
         * when a native crash occurred. (Default: 50)
         *
         * @param logcatSystemLines The maximum number of rows.
         * @return The InitParameters object.
         */
        public InitParameters setNativeLogcatSystemLines(int logcatSystemLines) {
            this.nativeLogcatSystemLines = logcatSystemLines;
            return this;
        }

        /**
         * Set the maximum number of rows to get from "logcat -b events"
         * when a native crash occurred. (Default: 50)
         *
         * @param logcatEventsLines The maximum number of rows.
         * @return The InitParameters object.
         */
        public InitParameters setNativeLogcatEventsLines(int logcatEventsLines) {
            this.nativeLogcatEventsLines = logcatEventsLines;
            return this;
        }

        /**
         * Set the maximum number of rows to get from "logcat -b main"
         * when a native crash occurred. (Default: 200)
         *
         * @param logcatMainLines The maximum number of rows.
         * @return The InitParameters object.
         */
        public InitParameters setNativeLogcatMainLines(int logcatMainLines) {
            this.nativeLogcatMainLines = logcatMainLines;
            return this;
        }

        /**
         * Set if dumping ELF file's MD5 hash in Build-Id section
         * when a native crash occurred. (Default: enable)
         *
         * @param flag True or false.
         * @return The InitParameters object.
         */
        public InitParameters setNativeDumpElfHash(boolean flag) {
            this.nativeDumpElfHash = flag;
            return this;
        }

        /**
         * Set if dumping memory map when a native crash occurred. (Default: enable)
         *
         * @param flag True or false.
         * @return The InitParameters object.
         */
        public InitParameters setNativeDumpMap(boolean flag) {
            this.nativeDumpMap = flag;
            return this;
        }

        /**
         * Set if dumping FD list when a native crash occurred. (Default: enable)
         *
         * @param flag True or false.
         * @return The InitParameters object.
         */
        public InitParameters setNativeDumpFds(boolean flag) {
            this.nativeDumpFds = flag;
            return this;
        }

        /**
         * Set if dumping network info when a native crash occurred. (Default: enable)
         *
         * @param flag True or false.
         * @return The InitParameters object.
         */
        public InitParameters setNativeDumpNetwork(boolean flag) {
            this.nativeDumpNetworkInfo = flag;
            return this;
        }

        /**
         * Set if dumping threads info (registers, backtrace and stack)
         * for all threads (not just the thread that has crashed)
         * when a native crash occurred. (Default: enable)
         *
         * @param flag True or false.
         * @return The InitParameters object.
         */
        @SuppressWarnings("WeakerAccess")
        public InitParameters setNativeDumpAllThreads(boolean flag) {
            this.nativeDumpAllThreads = flag;
            return this;
        }

        /**
         * Set the maximum number of other threads to dump when a native crash occurred.
         * "0" means no limit. (Default: 0)
         *
         * <p>Note: This option is only useful when "NativeDumpAllThreads"
         * is enabled by calling {@link InitParameters#setNativeDumpAllThreads(boolean)}.
         *
         * @param countMax The maximum number of other threads to dump.
         * @return The InitParameters object.
         */
        public InitParameters setNativeDumpAllThreadsCountMax(int countMax) {
            this.nativeDumpAllThreadsCountMax = (countMax < 0 ? 0 : countMax);
            return this;
        }

        /**
         * Set a thread name (regular expression) allowlist to filter which threads
         * need to be dumped when a native crash occurred.
         * "null" means no filtering. (Default: null)
         *
         * <p>Note: This option is only useful when "NativeDumpAllThreads" is enabled
         * by calling {@link InitParameters#setNativeDumpAllThreads(boolean)}.
         *
         * <p>Warning: The regular expression used here only supports POSIX ERE
         * (Extended Regular Expression).
         * Android bionic's regular expression is different from Linux libc's regular expression.
         * See:https://android.googlesource.com/platform/bionic/+/refs/heads/master/libc/include/regex.h
         *
         * @param allowList A thread name (regular expression) allowlist.
         * @return The InitParameters object.
         */
        public InitParameters setNativeDumpAllThreadsAllowList(String[] allowList) {
            this.nativeDumpAllThreadsAllowList = allowList;
            return this;
        }

        /**
         * Set a callback to be executed when a native crash occurred. (If not set,
         * nothing will be happened.)
         *
         * @param callback An instance of {@link xcrash.ICrashCallback}.
         * @return The InitParameters object.
         */
        public InitParameters setNativeCallback(ICrashCallback callback) {
            this.nativeCallback = callback;
            return this;
        }

        // anr相关的自定义参数
        // anr异常处理器，默认为true,如果为false不捕获anr异常
        boolean        enableAnrHandler     = true;
        // 是否抛出原始anr异常。默认为true
        boolean        anrRethrow           = true;
        // 是否设置anr的状态标志给进程状态（具体参见源码中的注释）
        boolean        anrCheckProcessState = true;
        // anr日志最大保留文件数量
        int            anrLogCountMax       = 10;
        // 执行命令 logcat -b system 输出的日志行数
        // -b <buffer> 指定要查看的日志缓冲区，该选项用于指定要操作的日志缓冲区，可以是system,events,radio,main.
        // 它们分别对应/dev/log文件夹下的system,events,radio,main日志文件。系统默认的是system和main。该选项可以
        // 出现多次，以指定多个日志缓冲区，比如：adb logcat -b system -b main -b events -b radio -s robin:i
        int            anrLogcatSystemLines = 50;
        // 执行命令 logcat -b event 输出的日志行数
        int            anrLogcatEventsLines = 50;
        // 执行命令 logcat -b main 输出的日志行数
        int            anrLogcatMainLines   = 200;
        // 是否输出app进程的下打开的文件描述符
        boolean        anrDumpFds           = true;
        boolean        anrDumpNetworkInfo   = true;
        // 发生anr异常的应用回调
        ICrashCallback anrCallback          = null;

        /**
         * Enable the ANR capture feature. (Default: enable)
         *
         * @return The InitParameters object.
         */
        public InitParameters enableAnrCrashHandler() {
            this.enableAnrHandler = true;
            return this;
        }

        /**
         * Disable the ANR capture feature. (Default: enable)
         *
         * @return The InitParameters object.
         */
        public InitParameters disableAnrCrashHandler() {
            this.enableAnrHandler = false;
            return this;
        }

        /**
         * Set whether xCrash should rethrow the ANR native signal to system
         * after it has been handled. (Default: true)
         *
         * <p>Note: This option is only valid if Android API level greater than or equal to 21.
         *
         * <p>Warning: It is highly recommended NOT to modify the default value (true) in most
         * cases unless you know that you are doing.
         *
         * @param rethrow If <code>true</code>, the native signal will be rethrown to Android System.
         * @return The InitParameters object.
         */
        public InitParameters setAnrRethrow(boolean rethrow) {
            this.anrRethrow = rethrow;
            return this;
        }

        /**
         * Set whether the process error state (from "ActivityManager#getProcessesInErrorState()")
         * is a necessary condition for ANR.  (Default: true)
         *
         * <p>Note: On some Android TV box devices, the ANR is not reflected by process error state.
         * In this case, set this option to false.
         *
         * @param checkProcessState If <code>true</code>, process state error will be a necessary
         *                          condition for ANR.
         * @return The InitParameters object.
         */
        public InitParameters setAnrCheckProcessState(boolean checkProcessState) {
            this.anrCheckProcessState = checkProcessState;
            return this;
        }

        /**
         * Set the maximum number of ANR log files to save in the log directory. (Default: 10)
         *
         * @param countMax The maximum number of ANR log files.
         * @return The InitParameters object.
         */
        public InitParameters setAnrLogCountMax(int countMax) {
            this.anrLogCountMax = (countMax < 1 ? 1 : countMax);
            return this;
        }

        /**
         * Set the maximum number of rows to get from "logcat -b system" when an ANR occurred.
         * (Default: 50)
         *
         * @param logcatSystemLines The maximum number of rows.
         * @return The InitParameters object.
         */
        public InitParameters setAnrLogcatSystemLines(int logcatSystemLines) {
            this.anrLogcatSystemLines = logcatSystemLines;
            return this;
        }

        /**
         * Set the maximum number of rows to get from "logcat -b events" when an ANR occurred.
         * (Default: 50)
         *
         * @param logcatEventsLines The maximum number of rows.
         * @return The InitParameters object.
         */
        public InitParameters setAnrLogcatEventsLines(int logcatEventsLines) {
            this.anrLogcatEventsLines = logcatEventsLines;
            return this;
        }

        /**
         * Set the maximum number of rows to get from "logcat -b main" when an ANR occurred.
         * (Default: 200)
         *
         * @param logcatMainLines The maximum number of rows.
         * @return The InitParameters object.
         */
        public InitParameters setAnrLogcatMainLines(int logcatMainLines) {
            this.anrLogcatMainLines = logcatMainLines;
            return this;
        }

        /**
         * Set if dumping FD list when an ANR occurred. (Default: enable)
         *
         * @param flag True or false.
         * @return The InitParameters object.
         */
        public InitParameters setAnrDumpFds(boolean flag) {
            this.anrDumpFds = flag;
            return this;
        }

        /**
         * Set if dumping network info when an ANR occurred. (Default: enable)
         *
         * @param flag True or false.
         * @return The InitParameters object.
         */
        public InitParameters setAnrDumpNetwork(boolean flag) {
            this.anrDumpNetworkInfo = flag;
            return this;
        }

        /**
         * Set a callback to be executed when an ANR occurred. (If not set, nothing will be happened.)
         *
         * @param callback An instance of {@link xcrash.ICrashCallback}.
         * @return The InitParameters object.
         */
        public InitParameters setAnrCallback(ICrashCallback callback) {
            this.anrCallback = callback;
            return this;
        }
    }

    static String getAppId() {
        return appId;
    }

    static String getAppVersion() {
        return appVersion;
    }

    static String getLogDir() {
        return logDir;
    }

    static ILogger getLogger() {
        return logger;
    }

    /**
     * Force a java exception.
     *
     * <p>Warning: This method is for testing purposes only. Don't call it
     * in a release version of your APP.
     *
     * @param runInNewThread Whether it is triggered in the current thread.
     * @throws RuntimeException This exception will terminate current process.
     */
    public static void testJavaCrash(boolean runInNewThread) throws RuntimeException {
        if (runInNewThread) {
            Thread thread = new Thread() {
                @Override
                public void run() {
                    throw new RuntimeException("test java exception");
                }
            };
            thread.setName("xcrash_test_java_thread");
            thread.start();
        } else {
            throw new RuntimeException("test java exception");
        }
    }

    /**
     * Force a native crash.
     *
     * <p>Warning: This method is for testing purposes only. Don't call it
     * in a release version of your APP.
     *
     * @param runInNewThread Whether it is triggered in the current thread.
     */
    public static void testNativeCrash(boolean runInNewThread) {
        NativeHandler.getInstance().testNativeCrash(runInNewThread);
    }
}
