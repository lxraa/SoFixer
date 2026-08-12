# SoFixer
用于修复从内存中 dump 下来的So文件。
## Build
`-DSO_64` 是编译期切换整套 `Elf_*` 类型的开关，32/64 位是两份不同的 cmake 配置，
**必须各用各的 build 目录**——共用一个的话，最后一次 `cmake` 跑的是哪个，你就只能修哪个，
另一个 arch 会静默沿用目录里那个过期的二进制。

```shell
mkdir build   && cd build   && cmake -DSO_64=ON  .. && make   # 修 64 位 so
cd .. && mkdir build32 && cd build32 && cmake -DSO_64=OFF .. && make   # 修 32 位 so
```

## 测试
`tests/` 覆盖 PT_GNU_EH_FRAME → section header 的重建。测试直接跑 `build/SoFixer64.exe`，
用 `tests/elf_fixture.py` 现造最小 ELF，并伪造 dump 里会被篡改/损坏的那几个字段。

```shell
python -m pytest tests -v
```

## 使用方法
* 從so中dump內存， ida腳本
```$cpp
import idaapi
start_address = 0x0000007DB078B000
end_address = 0x0000007DB08DE000
data_length = end_address - start_address
fp = open('E:\path.so', 'wb')

cur = 0
towrite = 0x100000
while cur < data_length:
    if data_length - cur < 0x100000:
        towrite = data_length - cur
    data = idaapi.dbg_read_memory(start_address + cur, towrite)
    fp.write(data)
    cur = cur + towrite

fp.close()
```
* 执行修复
```$cpp
sofixer  -s soruce.so -o fix.so -m 0x0 -d 
-s 待修復的so路徑
-o 修復後的so路徑
-m 內存dump的基地址(16位) 0xABC
-d 輸出debug信息
```

## 原理
原理参考下面的文章  
TK so修复参考[http://bbs.pediy.com/thread-191649.htm]
* 修复shdr
* 修复phdr
* 修复重定位

## 已知问题
在解析重定位表的时候有几个地方写错了，暂时懒得改，估计够用了，等出现新的修复so的
理论的时候再一并更新吧
