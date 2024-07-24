import hashlib
import bcrypt
import os

# 生成盐（salt）
def generate_salt(length=16):
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

# 通过 bcrypt 计算哈希值
def bcrypt_hash(data):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(data.encode('utf-8'), salt)
    return hashed.decode('utf-8'), salt

# 循环多次哈希值并结合盐和 bcrypt
def enhanced_strong_hash(data, iterations=10):
    salt = generate_salt()  # 生成盐
    # 首先计算 bcrypt 哈希值
    bcrypt_hash_value, bcrypt_salt = bcrypt_hash(data)
    
    for _ in range(iterations):
        # 结合 bcrypt 哈希值进行多层哈希计算
        bcrypt_hash_value = strong_hash(bcrypt_hash_value, salt)
    
    return bcrypt_hash_value

# 主函数
def main():
    print("Super Strong Hash Generator with Salt and bcrypt")
    print("\nEnter '!@exit' to quit.")
    
    while True:
        d = input("Enter the data to hash: ")
        d = d.strip()
        if d == '!@exit' or d == '！@exit':
            break
        else:
            try:
                hash_value = enhanced_strong_hash(d, iterations=10)
                print("Enhanced Strong Hash:", hash_value)
            except Exception as e:
                print("Error:", str(e))

# 运行主函数
if __name__ == "__main__": 
    main()
