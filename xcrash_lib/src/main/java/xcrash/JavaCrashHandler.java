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

import java.io.File;
import java.io.PrintWriter;
import java.io.RandomAccessFile;
import java.io.StringWriter;
import java.lang.Thread.UncaughtExceptionHandler;
import java.util.ArrayList;
import java.util.Date;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

import android.annotation.SuppressLint;
import android.text.TextUtils;
import android.os.Process;

/**
 * java异常处理器
 * UncaughtExceptionHandler是java系统提供用来处理未捕获全局异常。
 */
@SuppressLint("StaticFieldLeak")
class JavaCrashHandler implements UncaughtExceptionHandler {
    private static final String TAG = "JavaCrashHandler";

    private final Date startTime = new Date();

    private int pid;
    private String processName;
    private String appId;
    private String appVersion;
    private boolean rethrow;
    private String logDir;
    private int logcatSystemLines;
    private int logcatEventsLines;
    private int logcatMainLines;
    private boolean dumpFds;
    private boolean dumpNetworkInfo;
    private boolean dumpAllThreads;
    private int dumpAllThreadsCountMax;
    private String[] dumpAllThreadsAllowList;
    private ICrashCallback callback;
    private UncaughtExceptionHandler defaultHandler = null;

    private JavaCrashHandler() {
    }

    private static final JavaCrashHandler instance = new JavaCrashHandler();

    static JavaCrashHandler getInstance() {
        return instance;
    }

    /**
     * 初始化的功能有:
     * 1. 保存APP应用信息。包括进程ID，进程名，应用版本。
     * 2. Java异常输出配置，包括输出日志路径，是否抛出异常，配置输出内容
     *
     * @param rethrow 决定拦截异常后，是否继续抛出异常？
     */
    void initialize(int pid, String processName, String appId, String appVersion,
                    String logDir, boolean rethrow, int logcatSystemLines,
                    int logcatEventsLines, int logcatMainLines, boolean dumpFds,
                    boolean dumpNetworkInfo, boolean dumpAllThreads,
                    int dumpAllThreadsCountMax, String[] dumpAllThreadsAllowList,
                    ICrashCallback callback) {

        this.pid = pid;
        this.processName = (TextUtils.isEmpty(processName) ? "unknown" : processName);
        this.appId = appId;
        this.appVersion = appVersion;
        this.rethrow = rethrow;
        this.logDir = logDir;
        this.logcatSystemLines = logcatSystemLines;
        this.logcatEventsLines = logcatEventsLines;
        this.logcatMainLines = logcatMainLines;
        this.dumpFds = dumpFds;
        this.dumpNetworkInfo = dumpNetworkInfo;
        this.dumpAllThreads = dumpAllThreads;
        this.dumpAllThreadsCountMax = dumpAllThreadsCountMax;
        this.dumpAllThreadsAllowList = dumpAllThreadsAllowList;
        this.callback = callback;
        this.defaultHandler = Thread.getDefaultUncaughtExceptionHandler();

        try {
            Thread.setDefaultUncaughtExceptionHandler(this);
        } catch (Exception e) {
            XCrash.getLogger().e(TAG, "JavaCrashHandler setDefaultUncaughtExceptionHandler failed", e);
        }
    }

    @Override
    public void uncaughtException(Thread thread, Throwable throwable) {
        if (defaultHandler != null) {
            // xcrash不处理异常，采用默认的异常处理机制
            Thread.setDefaultUncaughtExceptionHandler(defaultHandler);
        }

        try {
            handleException(thread, throwable);
        } catch (Exception e) {
            XCrash.getLogger().e(TAG, "JavaCrashHandler handleException failed", e);
        }

        if (this.rethrow) {
            // java默认异常处理，抛出异常
            if (defaultHandler != null) {
                defaultHandler.uncaughtException(thread, throwable);
            }
        } else {
            // 关闭进程
            ActivityMonitor.getInstance().finishAllActivities();
            Process.killProcess(this.pid);
            System.exit(10);
        }
    }

    private void handleException(Thread thread, Throwable throwable) {
        Date crashTime = new Date();

        // 1. 通知native，anr异常处理器，java异常发生，其他异常处理器停止工作
        // notify the java crash
        NativeHandler.getInstance().notifyJavaCrashed();
        AnrHandler.getInstance().notifyJavaCrashed();

        // 2. 创建异常日志文件
        // create log file
        File logFile = null;
        try {
            // 异常日志文件的命名规则
            String logPath = String.format(Locale.US, "%s/%s_%020d_%s__%s%s",
                    logDir, Util.logPrefix, startTime.getTime() * 1000,
                    appVersion, processName, Util.javaLogSuffix);

            logFile = FileManager.getInstance().createLogFile(logPath);
        } catch (Exception e) {
            XCrash.getLogger().e(TAG, "JavaCrashHandler createLogFile failed", e);
        }

        // 获取java 异常输出
        // get emergency
        String emergency = null;
        try {
            // 应用基本信息，和java异常堆栈
            emergency = getEmergency(crashTime, thread, throwable);
        } catch (Exception e) {
            XCrash.getLogger().e(TAG, "JavaCrashHandler getEmergency failed", e);
        }

        // 3.异常日志写入文件
        // write info to log file
        if (logFile != null) {
            // 3.1 写入emergency，java异常信息
            // 3.2 logcat 写入异常文件中 logcat -b main; logcat -b event; logcat -b system
            // 3.3 输出APP应用进程的文件描述符信息
            // 3.4 输出内存信息
            // 3.5 输出其他线程信息

            RandomAccessFile raf = null;
            try {
                raf = new RandomAccessFile(logFile, "rws");

                //write emergency info
                if (emergency != null) {
                    raf.write(emergency.getBytes("UTF-8"));
                }

                // If we wrote the emergency info successfully, we don't need to
                // return it from callback again.
                emergency = null;

                // write logcat
                if (logcatMainLines > 0 || logcatSystemLines > 0 || logcatEventsLines > 0) {
                    raf.write(Util.getLogcat(logcatMainLines, logcatSystemLines,
                            logcatEventsLines).getBytes("UTF-8"));
                }

                //write fds
                if (dumpFds) {
                    raf.write(Util.getFds().getBytes("UTF-8"));
                }

                //write network info
                if (dumpNetworkInfo) {
                    raf.write(Util.getNetworkInfo().getBytes("UTF-8"));
                }

                //write memory info
                raf.write(Util.getMemoryInfo().getBytes("UTF-8"));

                //write background / foreground
                raf.write(("foreground:\n" + (ActivityMonitor.getInstance().isApplicationForeground()
                        ? "yes" : "no") + "\n\n").getBytes("UTF-8"));

                //write other threads info
                if (dumpAllThreads) {
                    raf.write(getOtherThreadsInfo(thread).getBytes("UTF-8"));
                }
            } catch (Exception e) {
                XCrash.getLogger().e(TAG, "JavaCrashHandler write log file failed", e);
            } finally {
                if (raf != null) {
                    try {
                        raf.close();
                    } catch (Exception ignored) {
                    }
                }
            }
        }

        //callback
        if (callback != null) {
            try {
                callback.onCrash(logFile == null ? null : logFile.getAbsolutePath(), emergency);
            } catch (Exception ignored) {
            }
        }
    }

    private String getEmergency(Date crashTime, Thread thread, Throwable throwable) {
        //stack stace
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        throwable.printStackTrace(pw);
        String stacktrace = sw.toString();

        return Util.getLogHeader(startTime, crashTime, Util.javaCrashType, appId, appVersion)
                + "pid: " + pid
                + ", tid: " + Process.myTid()
                + ", name: " + thread.getName()
                + "  >>> " + processName + " <<<\n"
                + "\n"
                + "java stacktrace:\n"
                + stacktrace
                + "\n";
    }

    private String getOtherThreadsInfo(Thread crashedThread) {
        int thdMatchedRegex = 0;
        int thdIgnoredByLimit = 0;
        int thdDumped = 0;

        //build allowlist regex list
        ArrayList<Pattern> allowList = null;
        if (dumpAllThreadsAllowList != null) {
            allowList = new ArrayList<Pattern>();
            for (String s : dumpAllThreadsAllowList) {
                try {
                    allowList.add(Pattern.compile(s));
                } catch (Exception e) {
                    XCrash.getLogger().w(TAG, "JavaCrashHandler pattern compile failed", e);
                }
            }
        }

        StringBuilder sb = new StringBuilder();
        Map<Thread, StackTraceElement[]> map = Thread.getAllStackTraces();
        for (Map.Entry<Thread, StackTraceElement[]> entry : map.entrySet()) {

            Thread thd = entry.getKey();
            StackTraceElement[] stacktrace = entry.getValue();

            //skip the crashed thread
            if (thd.getName().equals(crashedThread.getName())) continue;

            //check regex for thread name
            if (allowList != null && !matchThreadName(allowList, thd.getName())) continue;
            thdMatchedRegex++;

            //check dump count limit
            if (dumpAllThreadsCountMax > 0 && thdDumped >= dumpAllThreadsCountMax) {
                thdIgnoredByLimit++;
                continue;
            }

            sb.append(Util.sepOtherThreads + "\n");
            sb.append("pid: ").append(pid).append(", tid: ").append(thd.getId())
                    .append(", name: ").append(thd.getName())
                    .append("  >>> ").append(processName).append(" <<<\n");

            sb.append("\n");
            sb.append("java stacktrace:\n");
            for (StackTraceElement element : stacktrace) {
                sb.append("    at ").append(element.toString()).append("\n");
            }
            sb.append("\n");

            thdDumped++;
        }

        if (map.size() > 1) {
            if (thdDumped == 0) {
                sb.append(Util.sepOtherThreads + "\n");
            }

            sb.append("total JVM threads (exclude the crashed thread): ")
                    .append(map.size() - 1)
                    .append("\n");

            if (allowList != null) {
                sb.append("JVM threads matched allowlist: ").append(thdMatchedRegex).append("\n");
            }
            if (dumpAllThreadsCountMax > 0) {
                sb.append("JVM threads ignored by max count limit: ")
                        .append(thdIgnoredByLimit)
                        .append("\n");
            }
            sb.append("dumped JVM threads:").append(thdDumped).append("\n");
            sb.append(Util.sepOtherThreadsEnding + "\n");
        }

        return sb.toString();
    }

    private boolean matchThreadName(ArrayList<Pattern> allowList, String threadName) {
        for (Pattern pat : allowList) {
            if (pat.matcher(threadName).matches()) {
                return true;
            }
        }
        return false;
    }
}
