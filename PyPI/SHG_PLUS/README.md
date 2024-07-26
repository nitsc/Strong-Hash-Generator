---
# 使用说明
## 环境要求
如果你的Python环境版本高于2.5，并且已经配备了`hashlib`模块，请按照以下步骤操作。
### 已安装依赖
如果你已经安装了以下依赖库：
- `bcrypt`
- `cryptography`
- `argon2-cffi`
- `blake3`
- `pycryptodome`
那么你可以直接导入`SHG_PLUS`模块：
```python
import SHG_PLUS
```
#### 调用`cycle_strong_hash`函数
使用以下方式调用`cycle_strong_hash`函数进行哈希处理：
```python
cycle_strong_hash(data, iterations, length)
```
其中：
- `data`：需要哈希的字符串。
- `iterations`：迭代次数。
- `length`：动态盐的长度。
如果你想修改 AES动态密钥 和 PBKDF2动态密钥，请在`SHG_PLUS`模块中找到`pbkdf2_hash()`和`generate_key()`，并找到 `length` 修改为你想要的值。
函数将返回一个元组，包含加密后的哈希值和计算耗时。
### 安装依赖
如果你尚未安装所需的依赖库，可以使用以下命令进行安装：
```shell
pip install bcrypt cryptography argon2-cffi blake3 pycryptodome
```
或者，你也可以通过以下链接下载安装依赖的脚本：
[安装依赖脚本](https://github.com/nitsc/Strong-Hash-Generator/PyPI/install_dependencies.py)
下载后，运行以下命令：
```shell
python install_dependencies.py
```
确保你的环境中已经安装了`pip`。
```


## 程序介绍

### Super Strong Hash Generator with Salt and bcrypt

**概述：**
这个Python程序是一个强大的哈希生成器，它结合了多种哈希算法和加密技术，以生成强而安全的哈希值。

**功能特点：**

**PLUS 版本** 提供了以下功能：
- 使用了 10 层哈希算法：
  1. SHA3-256
  2. SHA3-512
  3. SHA3-384
  4. SHA2-256
  5. SHA2-512
  6. SHA2-384
  7. BLAKE3
  8. BLAKE2b
  9. BLAKE2s
  10. RIPEMD-256 
- 每层哈希算法都使用了很长的盐值（salt），以确保哈希值的唯一性和安全性。
- 使用了多种密码哈希算法：
  1. bcrypt
  2. PBKDF2
  3. Argon2
  4. HMAC-SHA256
  5. AES 中的 CBC 模式
- 1024 次迭代
- 动态密钥

这个程序可以用于生成强而安全的哈希值，适用于需要高安全性的场景，如密码存储、数据完整性验证等。
请注意，使用此程序生成的哈希值应该存储在安全的地方，并且不要在公开场合泄露。

