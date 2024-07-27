---

## 程序介绍

### Super Strong Hash Generator with Salt and bcrypt

**概述：**
这个Python程序是一个强大的哈希生成器，它结合了多种哈希算法和加密技术，以生成强而安全的哈希值。
`hash_security_test.py` 用于检测生成的哈希值的安全性。

**安装方法：**
```shell
pip install -i https://test.pypi.org/simple/ example-pkg-SHG
```

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

**Mini 版本** 提供了以下功能：
- 使用了 3 层哈希算法：
 1. SHA2-256
 2. BLAKE2b
 3. BLAKE2s
- 每层哈希算法都使用了很长的盐值（salt），以确保哈希值的唯一性和安全性。
- 使用了多种密码哈希算法：
  1. bcrypt
  2. PBKDF2
  3. Argon2
  4. HMAC-SHA256
  5. AES 中的 CBC 模式
- 512 次迭代
- 动态密钥


**使用方法：**
1. **运行 `安装依赖项.py` ：**安装程序所需的依赖项。

2. **运行程序：** 执行程序后，将提示用户输入需要加密的数据。

3. **输入数据：** 用户可以输入任意字符串进行哈希计算。

4. **获取结果：** 程序将输出经过多层哈希处理后的安全哈希值。

这个程序可以用于生成强而安全的哈希值，适用于需要高安全性的场景，如密码存储、数据完整性验证等。
请注意，使用此程序生成的哈希值应该存储在安全的地方，并且不要在公开场合泄露。


