import hashlib
import secrets
import base64
import math
from hashlib import sha256
from collections import defaultdict

def calculate_entropy(hash_bytes):
    """计算哈希值的熵（随机性）"""
    frequency = [0] * 256
    for byte in hash_bytes:
        frequency[byte] += 1
    entropy = 0.0
    length = len(hash_bytes)
    for freq in frequency:
        if freq > 0:
            p = freq / length
            entropy -= p * math.log2(p)
    return entropy

def test_collision_resistance(hash_func, length=64, attempts=10000):
    """测试哈希函数的抗碰撞性"""
    seen_hashes = set()
    for _ in range(attempts):
        random_data = secrets.token_bytes(length)
        hash_value = hash_func(random_data).hexdigest()
        if hash_value in seen_hashes:
            return False
        seen_hashes.add(hash_value)
    return True

def test_rainbow_table_resistance(hash_func, length=64, attempts=1000, chain_length=100):
    """测试哈希函数的抗彩虹表能力"""
    hash_table = defaultdict(lambda: None)
    for _ in range(attempts):
        initial_data = secrets.token_bytes(length)
        data = initial_data
        for _ in range(chain_length):
            hash_value = hash_func(data).digest()
            data = hash_value
        # Check if the end hash value was previously encountered
        if hash_table[hash_value] is not None:
            if hash_table[hash_value] == initial_data:
                return False
        hash_table[hash_value] = initial_data
    return True

def hash_security_test():
    while True:
        user_input = input("请输入要测试的哈希值（Base64编码格式）：")
        try:
            hash_bytes = base64.urlsafe_b64decode(user_input + '==')
        except ValueError:
            print("输入的哈希值无效。")
            continue

        # 计算哈希值的熵
        entropy = calculate_entropy(hash_bytes)
        print(f"哈希值的熵：{entropy:.2f}")

        # 测试抗碰撞性（这里以SHA-256为例，可以替换为其他哈希函数）
        def sha256_hash(data):
            return hashlib.sha256(data)

        collision_resistant = test_collision_resistance(sha256_hash)
        if collision_resistant:
            print("哈希函数具有良好的抗碰撞性。")
        else:
            print("哈希函数可能存在碰撞风险。")

        # 测试抗彩虹表能力
        rainbow_table_resistant = test_rainbow_table_resistance(sha256_hash)
        if rainbow_table_resistant:
            print("哈希函数对彩虹表攻击具有良好的抗性。")
        else:
            print("哈希函数可能容易受到彩虹表攻击。")

if __name__ == "__main__":
    hash_security_test()
