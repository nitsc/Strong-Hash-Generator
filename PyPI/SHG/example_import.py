# 导入必要的函数
import SHG

# 定义主函数
def main():
    # date，将要加密的信息
    data = "jweremy"
    # iterations，算法迭代的次数
    iterations = 1
    # length，动态的长度
    length = 16384
    # AES 动态密钥 和 PBKDF2 动态密钥 长度可在 SHG_PLUS 中修改，不过要注意长度符合 AES 和 PBKDF2 的要求
    # 获取返回的元组
    result = SHG_PLUS.cycle_strong_hash(data, iterations,length)
    # 将元组字符串化以执行操作
    result = str(result)
    # 将字符串中的括号替换为空字符串
    result = result.replace("(", "")
    result = result.replace(")", "")
    # 将字符串划分处理
    result_parts = result.split(",")
    # 获取哈希值和计算耗时
    hash_value = result_parts[0]
    calculated_time = result_parts[1]
    # 打印哈希值和计算耗时
    print(f"Hash result: {hash_value}")
    print(f"Time taken for {iterations} iteration(s): {calculated_time} seconds")

# 调用主函数
if __name__ == "__main__":
    main()
