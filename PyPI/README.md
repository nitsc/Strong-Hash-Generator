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
