# 导入必要的库
import os
import hmac
import time
import blake3
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from base64 import urlsafe_b64encode
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Hash import RIPEMD



# 生成盐（Salt）
def generate_salt(length=64):
    return os.urandom(length)

# 使用盐和 SHA2-256 计算哈希值
def salted_sha2256_hash(data, salt):
    sha2256 = hashlib.sha256()
    sha2256.update(salt + data.encode('utf-8'))
    return sha2256.hexdigest()

# 使用盐和 SHA2-512 计算哈希值
def salted_sha2512_hash(data, salt):
    sha2512 = hashlib.sha512()
    sha2512.update(salt + data.encode('utf-8'))
    return sha2512.hexdigest()

# 使用盐和 SHA3-256 计算哈希值
def salted_sha3256_hash(data, salt):
    sha3256 = hashlib.sha3_256()
    sha3256.update(salt + data.encode('utf-8'))
    return sha3256.hexdigest()

# 使用盐和 SHA3-512 计算哈希值
def salted_sha3512_hash(data, salt):
    sha3512 = hashlib.sha3_512()
    sha3512.update(salt + data.encode('utf-8'))
    return sha3512.hexdigest()

# 使用盐和 SHA2-384 计算哈希值
def salted_sha2384_hash(data, salt):
    sha2384 = hashlib.sha384()
    sha2384.update(salt + data.encode('utf-8'))
    return sha2384.hexdigest()

# 使用盐和 SHA3-384 计算哈希值
def salted_sha3384_hash(data, salt):
    sha3384 = hashlib.sha3_384()
    sha3384.update(salt + data.encode('utf-8'))
    return sha3384.hexdigest()

# 使用盐和 BLAKE3 计算哈希值
def salted_blake3_hash(data, salt):
    return blake3.blake3(salt + data.encode('utf-8')).hexdigest()

# 使用盐和 BLAKE2b 计算哈希值
def salted_blake2b_hash(data, salt):
    blake2b = hashlib.blake2b()
    blake2b.update(salt + data.encode('utf-8'))
    return blake2b.hexdigest()

# 使用盐和 BLAKE2s 计算哈希值
def salted_blake2s_hash(data, salt):
    blake2s = hashlib.blake2s()
    blake2s.update(salt + data.encode('utf-8'))
    return blake2s.hexdigest()

# 使用盐和 PIPEMD 计算哈希值
def salted_pipemd256_hash(data):
    hasher = RIPEMD.new()
    hasher.update(data.encode('utf-8'))
    return hasher.hexdigest()




# 通过 Argon2 计算哈希值
def argon2_hash(data):
    ph = PasswordHasher()
    hashed = ph.hash(data)
    return hashed

# 使用 PBKDF2 进行密钥衍生
def pbkdf2_hash(data, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=128,
        salt=salt,
        iterations=4096,
        backend=default_backend()
    )
    key = kdf.derive(data.encode('utf-8'))
    return urlsafe_b64encode(key).decode('utf-8')

# 生成随机密钥
def generate_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# 加密数据
def encrypt(data: bytes, key: bytes):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(data) + encryptor.finalize()

# 生成 HMAC
def create_hmac(data: bytes, key: bytes):
    return hmac.new(key, data, hashlib.sha256).digest()



# 综合使用 10层算法 和 AES加密算法 等进行哈希计算
def strong_hash(data, salt):
    # 先计算盐化后的 SHA2-256 哈希值
    sha2256_value = salted_sha2256_hash(data, salt)
    
    # 使用 SHA2-256 的结果计算盐化后的 SHA2-512 哈希值
    sha2512_value = salted_sha2512_hash(sha2256_value, salt)
    
    # 使用 SHA3-256 的结果计算盐化后的 SHA3-512 哈希值
    sha3512_value = salted_sha3512_hash(sha2512_value, salt)
    
    # 使用 SHA3-512 的结果计算盐化后的 SHA2-384 哈希值
    sha2384_value = salted_sha2384_hash(sha3512_value, salt)
    
    # 使用 SHA2-384 的结果计算盐化后的 SHA3-384 哈希值
    sha3384_value = salted_sha3384_hash(sha2384_value, salt)
    
    # 使用 SHA3-384 的结果计算盐化后的 BLAKE3 哈希值
    blake3_value = salted_blake3_hash(sha3384_value, salt)
    
    # 使用 BLAKE3 的结果计算盐化后的 BLAKE2b 哈希值
    blake2b_value = salted_blake2b_hash(blake3_value, salt)
    
    # 使用 BLAKE2b 的结果计算 BLAKE2s 哈希值
    blake2s_value = salted_blake2s_hash(blake2b_value, salt)
    
    # 使用 BLAKE2s 的结果计算盐化后的 PIPEMD 哈希值
    pipemd256_value = salted_pipemd256_hash(blake2s_value)
    
    # 使用 AES 加密算法的 CFB 模式加密 PIPEMD 哈希值
    password = sha3512_value
    key = generate_key(password, salt)
    encrypted_hash = encrypt(pipemd256_value.encode(), key)
    
    # 使用 HMAC-SHA256 计算加密后的哈希值的 HMAC 值
    hmac_value = create_hmac(encrypted_hash, key)
    
    # 使用 HMAC-SHA256 的结果计算盐化后的 Argon2 哈希值
    global then_value
    then_value = urlsafe_b64encode(hmac_value).decode()
    argon2_hash_value = argon2_hash(then_value)
    
    # 使用 Argon2 的结果计算盐化后的 PBKDF2 哈希值
    final_hash_value = pbkdf2_hash(argon2_hash_value, salt)
    return final_hash_value

    
# 循环计算 哈希值
def cycle_strong_hash(data, iterations=1000):
    salt = generate_salt()  # 生成盐
    
    # 循环多次哈希计算
    for _ in range(iterations):
        end_hash_value = strong_hash(data, salt)
    return end_hash_value  # 返回最终的哈希值

# 主函数
def main():
    # 介绍
    print("Super Strong Hash Generator Plus ")
    print("\nEnter '!@exit' to quit.")
    
    # 循环
    while True:
        d = input("Enter the data to hash: ")
        d = d.strip()
        if d == '!@exit' or d == '！@exit':
            break
        else:
            try:
                # 调用 cycle_strong_hash 函数计算哈希值
                start_time = time.time()  # 记录开始时间
                super_hash_value = cycle_strong_hash(d, iterations=1024)
                end_time = time.time()  # 记录结束时间
                print("Super Strong Hash:", super_hash_value)
                print("Time taken to compute hash:", end_time - start_time, "seconds")
            except Exception as e:
                # 错误处理
                print("Error:", str(e))

# 运行主函数
if __name__ == "__main__": 
    main()
