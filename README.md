**extract.erofs**
===========
**使用[erofs-utils](https://github.com/hsiangkao/erofs-utils)实现的提取erofs镜像的工具**  
**提取包含：**
- fs_config
- files_context

**A tool for extracting erofs images implemented using [erofs-utils](https://github.com/hsiangkao/erofs-utils)**  
**Extract contains:**
- fs_config
- files_context

**fs_config:**`vendor/bin/cnd 1000 1000 0755 capabilities=0x1000001400`  
**files_context:** `/vendor/bin/hw/android\.hardware\.bluetooth@1\.0-service-qti u:object_r:hal_bluetooth_default_exec:s0`

```
usage: [options]
  -h, --help              Display this help and exit
  -i, --image=[FILE]      Image file
  -p                      Print all entrys
  -P, --print=X           Print the target of path X
  -x                      Extract all items
  -X, --extract=X         Extract the target of path X
  -c, --config=[FILE]     Target of config
  -r                      When using config, recurse directories
  -f, --overwrite         [default: skip] overwrite files that already exist
  -T#                     [1-X] Use # threads, -T0: X/2
  --only-cfg              Only extract fs_config|file_contexts|fs_options
  -o, --outdir=X          Output dir
  -V, --version           Print the version info
  erofs-utils:            x.x-gxxxxxxxx
  extract.erofs:          x.x.x
  Available compressors:  lz4, lz4hc, lzma, deflate
  extract author:         skkk

```

**Contributors**
- 感谢[lateautumn233](https://github.com/lateautumn233)提供的[erofs-utils](https://github.com/lateautumn233/erofs-utils)编译方法
- Thanks to [lateautumn233](https://github.com/lateautumn233) for the [erofs-utils](https://github.com/lateautumn233/erofs-utils) compilation method.
