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

#ifndef XC_JNI_H
#define XC_JNI_H 1

#include <stdint.h>
#include <sys/types.h>
#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Jni层异常处理
 * 为了处理以Java代码实现的方法执行中抛出的异常，或者是以Native代码编写的方法抛出的Java异常，JNI提供了Java异常机制
 * 的钩子程序。该机制与C/C++中常规函数实现的标准错误处理无关。JNI提供一个函数集来在Native代码中检查、分析和处理Java
 * 异常.
 * (1) 如果一个异常已经抛出，下面的函数返回JNI_TRUE，否则返回JNI_FALSE:
 * jboolean ExceptionCheck();
 * 如：当异常发生时，清理并抛出自定义异常
 * if (env->ExceptionCheck()) {
 *   env->ExceptionClear();// 清除异常
 *   env->ThrowNew(env->FindClass("java/lang/Exception"),"xx异常");
 * }
 * (2) ExceptionOccurred()获取正在被抛出异常的一个Native引用。Native代码或者Java代码必须处理该异常：
 * jthrowable ExceptionOccurred();
 * (3) ExceptionDescribe()打印有关刚刚被抛出到标准错误输出中的异常信息。该信息包括一个栈追踪信息：
 * void ExceptionDescribe();
 * (4) ExceptionClear()清理一个刚刚抛出的异常：
 * void ExceptionClear();
 * (5) Throw()抛出一个已经创建的异常。如果异常成功抛出，返回0；否则返回一个负值：
 * jint Throw(jthrowable obj);
 * // 可以这样使用：手动抛出异常，然后在本机或Java代码中处理
 * jthrowable mException = NULL;
 * mException = env->ExceptionOccurred();
 * if (mException != NULL) {
 *   env->Throw(mException);
 *   // 或抛出自定义异常
 *   env->ThrowNew(env->FindClass("java/lang/Exception"), "xxx异常");
 *   // 最后别忘了清除异常，不然还是会导致VM崩溃
 *   env->ExceptionClear();
 *   return -1;
 * }
 * (6) ThrowNew()基于clazz创建一个异常，它应该是继承自Throwable，并且异常文本是由msg(按照UTF-8)指定。如果异常
 * 的构造以及抛出成功，返回0；否则返回一个负值。
 * jint ThrowNew(jclass clazz, const char* msg);
 * // 如：在可能出错的地方抛出自定义异常,然后在本机代码或者Java代码中处理
 * env->ThrowNew(env->FindClass("java/lang/Exception"), "xxx异常");
 * (7)FatalError()会生成致命错误信号。一个致命错误是特指无法恢复的情况。VM在调用该函数之后将会关闭：
 * void FatalError(const char* msg);
 */
#define XC_JNI_IGNORE_PENDING_EXCEPTION()                 \
  do {                                                    \
    if ((*env)->ExceptionCheck(env)) {                    \
      (*env)->ExceptionClear(env);                        \
    }                                                     \
  } while(0)

#define XC_JNI_CHECK_PENDING_EXCEPTION(label)             \
  do {                                                    \
    if ((*env)->ExceptionCheck(env)) {                    \
      (*env)->ExceptionClear(env);                        \
      goto label;                                         \
    }                                                     \
  } while(0)

#define XC_JNI_CHECK_NULL_AND_PENDING_EXCEPTION(v, label) \
  do {                                                    \
    XC_JNI_CHECK_PENDING_EXCEPTION(label);                \
    if (NULL == (v)) {                                    \
      goto label;                                         \
    }                                                     \
  } while(0)

#define XC_JNI_VERSION    JNI_VERSION_1_6
#define XC_JNI_CLASS_NAME "xcrash/NativeHandler" // java类的类全路径名

#ifdef __cplusplus
}
#endif

#endif
