import os,subprocess

def up_pip():
    bat_folder = 'bat'
    if not os.path.exists(bat_folder):
        os.makedirs(bat_folder)
    
    bat_file_path = os.path.join(bat_folder, 'up.bat')
    with open(bat_file_path, 'w') as bat_file:
        bat_file.write("pip install --upgrade pip")
    subprocess.run([bat_file_path], shell=True)
    
def install_package(package_name):
    bat_folder = 'bat'
    if not os.path.exists(bat_folder):
        os.makedirs(bat_folder)
    bat_file_path = os.path.join(bat_folder, 'install.bat')
    with open(bat_file_path, 'w') as bat_file:
        bat_file.write(f'pip install {package_name}')
    subprocess.run([bat_file_path], shell=True)
    
def list():
    bat_folder = 'bat'
    if not os.path.exists(bat_folder):
        os.makedirs(bat_folder)
    bat_file_path = os.path.join(bat_folder, 'plist.bat')
    with open(bat_file_path, 'w') as bat_file:
        bat_file.write("pip list")
    subprocess.run([bat_file_path], shell=True)

def install_dependency():
    up_pip()
    install_package("bcrypt")
    list()
    print("安装依赖库成功！接下来您就可以正常使用 超强的哈希值生成器 啦")
    
if __name__ == "__main__":
    install_dependency()