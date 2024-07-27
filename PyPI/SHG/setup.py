import setuptools #导入setuptools打包工具
 
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()
 
setuptools.setup(
    name="SHG", # 用自己的名替换其中的YOUR_USERNAME_
    version="2.0.1",    #包版本号，便于维护版本
    author="Zhou Nitsc(Dean of NITSC)",    #作者，可以写自己的姓名
    author_email="dministrator1234567890dddaz@outlook.com",    #作者联系方式，可写自己的邮箱地址
    description="这个Python程序是一个强大的哈希生成器，它结合了10种著名先进哈希算法和5种加密技术，以生成强而安全的哈希值。",#包的简述
    long_description=long_description,    #包的详细介绍，一般在README.md文件内
    long_description_content_type="text/markdown",
    url="https://github.com/nitsc/Strong-Hash-Generator",    #自己项目地址，比如github的项目地址
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',    #对python的最低版本要求
)