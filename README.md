**extract.erofs**
===========
## 简介
**使用[erofs-utils](https://github.com/hsiangkao/erofs-utils)实现的提取erofs镜像的工具**  
**提取包含：**
- fs_config
- files_context

## Introduction
**A tool for extracting erofs images implemented using [erofs-utils](https://github.com/hsiangkao/erofs-utils)**  
**Extract contains:**
- fs_config
- files_context

## Infomation of tool
**fs_config:**`vendor/bin/cnd 1000 1000 0755 capabilities=0x1000001400`  
**files_context:** `/vendor/bin/hw/android\.hardware\.bluetooth@1\.0-service-qti u:object_r:hal_bluetooth_default_exec:s0`

```
usage: [options]
  -h, --help          Display this help and exit
  -i, --image=[FILE]  Image file
  -p                  Print all entrys
  --print=X           Print the target of path X
  -x                  Extract all items
  --extract=X         Extract the target of path X
  -f, --overwrite     [default: skip] overwrite files that already exist
  -T#                 [1-X] Use # threads, -T0: X/2
  --only-cfg          Only extract fs_config and file_contexts
  -o, --outdir=X      Output dir
  -V, --version       Print the version info
  erofs-utils:        x.x-gxxxxxxxx
  extract.erofs:      x.x.x
  extract author:     skkk

```
## 编译指南/Compile Guide
#### 安装环境/Install Environment
```shell
automake autoconf libtool gcc pkgconf libuuid-devel make
```
#### 编译/Compile
```shell
. autogen.sh
. configure
make
make install
```  

## 贡献者/Contributors
- 感谢[lateautumn233](https://github.com/lateautumn233)提供的[erofs-utils](https://github.com/lateautumn233/erofs-utils)编译方法
- Thanks to [lateautumn233](https://github.com/lateautumn233) for the [erofs-utils](https://github.com/lateautumn233/erofs-utils) compilation method.
