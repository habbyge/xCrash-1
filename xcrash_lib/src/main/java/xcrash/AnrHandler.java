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

// Created on 2019-09-03.
package xcrash;

import android.content.Context;
import android.os.Build;
import android.os.FileObserver;
import android.text.TextUtils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.RandomAccessFile;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static android.os.FileObserver.CLOSE_WRITE;

/**
 * ANR（Application Not Responding）异常捕获处理器
 *
 * - ANR异常产生的类型（本质就是四大组件超时）：
 * 1. KeyDispatchTimeout，UI主线程对于输入事件，即InputDispatch事件超过5s没有处理产生ANR。
 * 2. BroadcastTimeout，在广播接收器BroadcastReceiver的onReceive在一定的时间内没有执行完程序就会发生ANR异常，
 *    如果广播接收器所在的进程是前台进程，超时时间为10S；如果广播接收器所在的进程是后台进程，超时时间为60S。
 * 3. ServiceTimeout，前台Service的各个生命周期函数包括（onCreate,onStart,onBind）在20S内没有处理完成，发生
 *    ANR异常。后台的Service的各个生命周期函数包括（onCreate,onStart,onBind）在200S内没有处理完成，发生ANR异常。
 * 4. ContentProviderTimeout。ContentProvider 在10S内没有处理完成发生ANR。
 *
 * - ANR异常产生的原因
 * 1. 在主UI线程执行耗时的操作，常见的耗时操作有IO操作：网络访问，大量数据的读写等
 * 2. 多线程死锁，造成主线程被阻塞
 * 3. service binder的连接达到上线无法和和System Server通信
 * 4. System Server中WatchDog出现ANR
 * 5. 系统资源已耗尽（管道、CPU、IO等）
 *
 * - ANR异常处理
 * Android系统发生ANR异常是，Logcat会输出一条日志，通过日志可以确定，Android发生ANR异常时，会将日志写入
 * /data/anr/traces.txt。因此可以猜想到应用程序可以监控/data/anr/文件是否有写入，即可判断是否发生ANR异常。如何
 * 监控文件夹，Android提供了一个类“FileObserver”，可以监控文件。但是通过这种方式监控是否发生ANR异常，对Android
 * 的版本有要求，API版本必须<21。xCrash对应API版本<21的也是采用此种方式，腾讯提供的Buly也是采用该种方式。
 * xCrash在api>=21时，采用捕获SIGQUIT信号的方案，来处理anr；
 *
 * 微信的Matrix采用 "旁路方案" 的方式，另辟蹊径来监控是否发生ANR，Matrix适用所有Android版本，具体方案是：借助
 * VSYNC帧类：Choreographer，在其返回的每一个渲染帧的callback函数中，关闭和开始一个5s的超时异步事件，如果在5s内
 * 渲染帧的callback没有返回(即没有退出该异步事件和继续重启下一次)，则认为发生或可能发生了anr事件，并通过编译期全量
 * 的向方法(函数)执行前和执行后，插入统计函数的方式，来计算函数耗时，找到慢(evil)函数，这个满方法调用栈的排序，即可
 * 找到导致该anr的原因.
 *
 * xCrash和Matrix在ANR异常的方案，我更偏向于Matrix的方案.
 */
@SuppressWarnings("StaticFieldLeak")
class AnrHandler {
    private final Date startTime = new Date();

    private final Pattern patPidTime = Pattern.compile("^-----\\spid\\s(\\d+)\\sat\\s(.*)\\s-----$");
    private final Pattern patProcessName = Pattern.compile("^Cmd\\sline:\\s+(.*)$");

    private final long anrTimeoutMs = 15 * 1000; // anr超时默认值是15s

    private Context ctx;
    private int pid;
    private String processName;
    private String appId;
    private String appVersion;
    private String logDir;
    private boolean checkProcessState;
    private int logcatSystemLines;
    private int logcatEventsLines;
    private int logcatMainLines;
    private boolean dumpFds;
    private boolean dumpNetworkInfo;
    private ICrashCallback callback;
    private long lastTime = 0;
    private FileObserver fileObserver = null;

    private static final AnrHandler instance = new AnrHandler();

    private AnrHandler() {
    }

    static AnrHandler getInstance() {
        return instance;
    }

    @SuppressWarnings("deprecation")
    void initialize(Context ctx, int pid, String processName, String appId,
                    String appVersion, String logDir, boolean checkProcessState,
                    int logcatSystemLines, int logcatEventsLines, int logcatMainLines,
                    boolean dumpFds, boolean dumpNetworkInfo, ICrashCallback callback) {

        // check API level，该ANR异常监控方案只支持api < 21的场景，更通用的方案可以采用微信的Matrix
        if (Build.VERSION.SDK_INT >= 21) {
            return;
        }

        this.ctx = ctx;
        this.pid = pid;
        this.processName = (TextUtils.isEmpty(processName) ? "unknown" : processName);
        this.appId = appId;
        this.appVersion = appVersion;
        this.logDir = logDir;
        this.checkProcessState = checkProcessState;
        this.logcatSystemLines = logcatSystemLines;
        this.logcatEventsLines = logcatEventsLines;
        this.logcatMainLines = logcatMainLines;
        this.dumpFds = dumpFds;
        this.dumpNetworkInfo = dumpNetworkInfo;
        this.callback = callback;

        // 核心：利用FileObserver监控路径"/data/anr/"，监听文件被写入.
        // Android的FileObserver是抽象类，是基于Linux的inotify的特性来实现的，主要用来监控文件系统，
        // 根据文件的特定事件发出事件。
        fileObserver = new FileObserver("/data/anr/", CLOSE_WRITE) {

            @Override
            public void onEvent(int event, String path) {
                try {
                    if (path != null) {
                        String filepath = "/data/anr/" + path;
                        if (filepath.contains("trace")) {
                            handleAnr(filepath);
                        }
                    }
                } catch (Exception e) {
                    XCrash.getLogger().e(Util.TAG, "AnrHandler fileObserver onEvent failed", e);
                }
            }
        };

        try {
            fileObserver.startWatching();
        } catch (Exception e) {
            fileObserver = null;
            XCrash.getLogger().e(Util.TAG, "AnrHandler fileObserver startWatching failed", e);
        }
    }

    /**
     * Java层发生了Crash，这里是Java层通知ANR，让ANR不用继续监控了，进程嗝屁了
     */
    void notifyJavaCrashed() {
        if (fileObserver != null) {
            try {
                fileObserver.stopWatching();
            } catch (Exception e) {
                XCrash.getLogger().e(Util.TAG, "AnrHandler fileObserver stopWatching failed", e);
            } finally {
                fileObserver = null;
            }
        }
    }

    private void handleAnr(String filepath) {
        Date anrTime = new Date();

        // check ANR time interval
        if (anrTime.getTime() - lastTime < anrTimeoutMs) {
            return;
        }

        // check process error state，检查进程状态是否未响应
        // 该函数的主要功能有：
        // 1. 过滤掉其他应用的异常
        // 2. 过滤掉本应用非ANR异常
        // 3. 通过这个函数可以保证anrHandler处理的是当前应用的ANR异常
        if (this.checkProcessState) {
            if (!Util.checkProcessAnrState(this.ctx, anrTimeoutMs)) {
                return;
            }
        }

        // get trace
        // 读取anr文件/data/anr/trace*.txt。返回文件内容
        String trace = getTrace(filepath, anrTime.getTime());
        if (TextUtils.isEmpty(trace)) {
            return;
        }

        // captured ANR
        lastTime = anrTime.getTime();

        // delete extra ANR log files
        // 删除其他的anr异常日志文件
        if (!FileManager.getInstance().maintainAnr()) {
            return;
        }

        // get emergency，获取 tombstone 的文件头
        String emergency = null;
        try {
            emergency = getEmergency(anrTime, trace);
        } catch (Exception e) {
            XCrash.getLogger().e(Util.TAG, "AnrHandler getEmergency failed", e);
        }

        //create log file，创建anr异常日志保存文件
        File logFile = null;
        try {
            String logPath = String.format(Locale.US, "%s/%s_%020d_%s__%s%s", logDir, Util.logPrefix,
                    anrTime.getTime() * 1000, appVersion, processName, Util.anrLogSuffix);
            logFile = FileManager.getInstance().createLogFile(logPath);
        } catch (Exception e) {
            XCrash.getLogger().e(Util.TAG, "AnrHandler createLogFile failed", e);
        }

        // write info to log file，根据配置将日志文件头、traces、logcat日志保存在文件中
        if (logFile != null) {
            RandomAccessFile raf = null;
            try {
                raf = new RandomAccessFile(logFile, "rws");

                // write emergency info
                if (emergency != null) {
                    raf.write(emergency.getBytes("UTF-8"));
                }

                // If we wrote the emergency info successfully,
                // we don't need to return it from callback again.
                emergency = null;

                //write logcat
                if (logcatMainLines > 0 || logcatSystemLines > 0 || logcatEventsLines > 0) {
                    raf.write(Util.getLogcat(logcatMainLines, logcatSystemLines, logcatEventsLines)
                            .getBytes("UTF-8"));
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
            } catch (Exception e) {
                XCrash.getLogger().e(Util.TAG, "AnrHandler write log file failed", e);
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

    private String getEmergency(Date anrTime, String trace) {
        return Util.getLogHeader(startTime, anrTime, Util.anrCrashType, appId, appVersion)
            + "pid: " + pid + "  >>> " + processName + " <<<\n"
            + "\n"
            + Util.sepOtherThreads
            + "\n"
            + trace
            + "\n"
            + Util.sepOtherThreadsEnding
            + "\n\n";
    }

    private String getTrace(String filepath, long anrTime) {

        // "\n\n----- pid %d at %04d-%02d-%02d %02d:%02d:%02d -----\n"
        // "Cmd line: %s\n"
        // "......"
        // "----- end %d -----\n"

        BufferedReader br = null;
        String line;
        Matcher matcher;
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US);
        StringBuilder sb = new StringBuilder();
        boolean found = false;

        try {
            br = new BufferedReader(new FileReader(filepath));
            while ((line = br.readLine()) != null) {
                if (!found && line.startsWith("----- pid ")) {

                    //check current line for PID and log time
                    matcher = patPidTime.matcher(line);
                    if (!matcher.find() || matcher.groupCount() != 2) {
                        continue;
                    }
                    String sPid = matcher.group(1);
                    String sLogTime = matcher.group(2);
                    if (sPid == null || sLogTime == null) {
                        continue;
                    }
                    if (pid != Integer.parseInt(sPid)) {
                        continue; //check PID
                    }
                    Date dLogTime = dateFormat.parse(sLogTime);
                    if (dLogTime == null) {
                        continue;
                    }
                    long logTime = dLogTime.getTime();
                    if (Math.abs(logTime - anrTime) > anrTimeoutMs) {
                        continue; //check log time
                    }

                    //check next line for process name
                    line = br.readLine();
                    if (line == null) {
                        break;
                    }
                    matcher = patProcessName.matcher(line);
                    if (!matcher.find() || matcher.groupCount() != 1) {
                        continue;
                    }
                    String pName = matcher.group(1);
                    if (pName == null || !(pName.equals(this.processName))) {
                        continue; //check process name
                    }

                    found = true;

                    sb.append(line).append('\n');
                    sb.append("Mode: Watching /data/anr/*\n");

                    continue;
                }

                if (found) {
                    if (line.startsWith("----- end ")) {
                        break;
                    } else {
                        sb.append(line).append('\n');
                    }
                }
            }
            return sb.toString();
        } catch (Exception ignored) {
            return null;
        } finally {
            if (br != null) {
                try {
                    br.close();
                } catch (Exception ignored) {
                }
            }
        }
    }
}
