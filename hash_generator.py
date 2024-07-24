import hashlib
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from base64 import urlsafe_b64encode
from argon2 import PasswordHasher


# 生成盐（Salt）
def generate_salt(length=128):
    return os.urandom(length)

# 使用 SHA-256 哈希值
def sha256_hash(data):
    sha256 = hashlib.sha256()
    sha256.update(data.encode('utf-8'))
    return sha256.hexdigest()

# 使用 BLAKE2b 哈希值
def blake2b_hash(data):
    blake2b = hashlib.blake2b()
    blake2b.update(data.encode('utf-8'))
    return blake2b.hexdigest()

# 使用 BLAKE2s 哈希值
def blake2s_hash(data):
    blake2s = hashlib.blake2s()
    blake2s.update(data.encode('utf-8'))
    return blake2s.hexdigest()

# 使用盐和 SHA-256 计算哈希值
def salted_sha256_hash(data, salt):
    sha256 = hashlib.sha256()
    sha256.update(salt + data.encode('utf-8'))
    return sha256.hexdigest()

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

# 综合使用 SHA-256、BLAKE2b 和 BLAKE2s 进行哈希计算
def strong_hash(data, salt):
    # 先计算盐化后的 SHA-256 哈希值
    sha256_value = salted_sha256_hash(data, salt)
    
    # 使用 SHA-256 的结果计算 BLAKE2b 哈希值
    blake2b_value = salted_blake2b_hash(sha256_value, salt)
    
    # 使用 BLAKE2b 的结果计算 BLAKE2s 哈希值
    blake2s_value = salted_blake2s_hash(blake2b_value, salt)
    
    # 使用 BLAKE2s 的结果计算盐化后的 SHA-256 哈希值
    final_hash_value = salted_sha256_hash(blake2s_value, salt)
    
    return final_hash_value

# 通过 Argon2 计算哈希值
def argon2_hash(data):
    ph = PasswordHasher()
    hashed = ph.hash(data)
    return hashed

# 使用 PBKDF2 进行密钥衍生
def pbkdf2_hash(data, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=512,
        salt=salt,
        iterations=65536,  # 增加迭代次数
        backend=default_backend()
    )
    key = kdf.derive(data.encode('utf-8'))
    return urlsafe_b64encode(key).decode('utf-8')

# 循环多次哈希值并结合盐和 Argon2
def enhanced_strong_hash(data, iterations=65536):
    salt = generate_salt()  # 生成盐
    # 首先计算 Argon2 哈希值
    argon2_hash_value = argon2_hash(data)
    
    for _ in range(iterations):
        # 结合 Argon2 哈希值进行多层哈希计算
        argon2_hash_value = strong_hash(argon2_hash_value, salt)
    
    # 最后使用 PBKDF2 进行密钥衍生
    final_hash_value = pbkdf2_hash(argon2_hash_value, salt)
    
    return final_hash_value

# 主函数
def main():
    print("Super Strong Hash Generator with SHA-256, BLAKE2b, BLAKE2s, Salt, bcrypt, Argon2, and PBKDF2")
    print("\nEnter '!@exit' to quit.")
    
    while True:
        d = input("Enter the data to hash: ")
        d = d.strip()
        if d == '!@exit' or d == '！@exit':
            break
        else:
            try:
                hash_value = enhanced_strong_hash(d, iterations=65536)
                print("Super Strong Hash:", hash_value)
            except Exception as e:
                print("Error:", str(e))

# 运行主函数
if __name__ == "__main__": 
    main()
