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

// 这里解释啥是LZMA？
// LZMA（Lempel-Ziv-Markov chain-Algorithm）是Igor Pavlov为7-Zip发明的压缩算法
// LZMA2算法是LZMA算法的升级版，修正了一些问题
// .lzma、.7z和.xz分别是三种文件格式的后缀名，它们对应三种不同的文件结构。文件结构相当于容器，
// 把LZMA算法压缩后的数据包装起来，然后添加上魔术字、校验码、压缩元信息、文件夹结构等信息。
// .xz和.lzma一样，只能压缩一个文件。它们需要和打包工具tar一起使用才能把多个文件压缩成一个文件。
// 而.7z这种更复杂的文件结构可以包含多个文件或文件夹的压缩数据。由于.xz的压缩元信息存储在头部，
// 而压缩数据存储在元信息后面，所以.xz格式可以支持流式解压缩。 相反，.7z把压缩元信息存储在尾部，
// 而压缩数据在元信息的前面，所以.7z不适合流式解压缩。
// .lzma是历史遗留的老文件格式，它正在被.xz格式取代。。lzma文件对LZMA压缩数据进行简单的封装，
// 加上13个字节的头部信息。.xz作为.lzma的替代，它的文件结构更复杂，包含的元信息更多。.xz文件可
// 以由多个Stream和Stream Padding组成，但通常只有一个Stream。
// 7zip那个压缩器定义的压缩格式，支持一系列压缩算法，LZMA只是其中一种。

#pragma once

#define XC_DL_DYNSYM 0x01
#define XC_DL_SYMTAB 0x02
#define XC_DL_ALL    (XC_DL_DYNSYM | XC_DL_SYMTAB)

typedef struct xc_dl xc_dl_t;

xc_dl_t* xc_dl_open(const char* pathname, int flags);
void xc_dl_close(xc_dl_t** self);

void*xc_dl_dynsym_func(xc_dl_t* self, const char* sym_name);
void*xc_dl_dynsym_object(xc_dl_t* self, const char* sym_name);

void* xc_dl_symtab_func(xc_dl_t *self, const char* sym_name);
void* xc_dl_symtab_object(xc_dl_t* self, const char* sym_name);
