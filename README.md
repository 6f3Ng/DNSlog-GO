简介
---
DNSLog-GO 是一款golang编写的监控 DNS 解析记录的工具，自带多用户WEB界面

演示截图:

![avatar](https://github.com/lanyi1998/DNSlog-GO/raw/master/images/demo.png)

安装
---

详细图文教程:https://mp.weixin.qq.com/s/m_UXJa0imfOi721bkBpwFg

# 1.获取发行版

这里 https://github.com/lanyi1998/DNSlog-GO/releases 下载最新发行版,并解压

# 2.域名与公网 IP 准备

```
搭建并使用 DNSLog，你需要拥有两个域名，一个域名作为 NS 服务器域名(例:a.com)，一个用于记录域名(例: b.com)。还需要有一个公网 IP 地址(如：1.1.1.1)
    
注意：b.com 的域名提供商需要支持自定义 NS 记录, a.com 则无要求。
    
在 a.com 中设置两条 A 记录：
    
ns1.a.com  A 记录指向  1.1.1.1        
ns2.a.com  A 记录指向  1.1.1.1
修改 b.com 的 NS 记录为 1 中设定的两个域名

本步骤中，需要在域名提供商提供的页面进行设置，部分域名提供商只允许修改 NS 记录为已经认证过的 NS 地址。所以需要找一个支持修改 NS 记录为自己 NS 的域名提供商。
    
注意: NS 记录修改之后部分地区需要 24-48 小时会生效
```

# 3.修改配置文件 config.ini

```
[HTTP]
Port = 8080  //http web监听端口
Token = admin1,admin2 //多个用户token，用,分割。可以团队成员一起使用了
ConsoleDisable = false //是否关闭web页面
    
[DNS]
Domain = demo.com //dnslog的域名
```

# 4.启动对应系统的客户端，注意服务端重启以后，必须清空一下浏览器中的localStorage,否则会获取不到数据

---

API Python Demo

```python
import requests
import random
import json


class DnsLog():
    domain = ""
    token = ""
    Webserver = ""

    def __init__(self, Webserver, token):
        self.Webserver = Webserver  # dnslog的http监听地址，格式为 ip:端口
        self.token = token  # token
        # 检测DNSLog服务器是否正常
        try:
            res = requests.post("http://" + Webserver + "/api/verifyToken", json={"token": token}).json()
            self.domain = res.Msg
        except:
            exit("DnsLog 服务器连接失败")
        if res["Msg"] == "false":
            exit("DnsLog token 验证失败")

    # 生成随机子域名
    def randomSubDomain(self, length=5):
        subDomain = ''.join(random.sample('zyxwvutsrqponmlkjihgfedcba', length)) + '.' + self.domain
        return subDomain

    # 验证子域名是否存在
    def checkDomain(self, domain):
        res = requests.post("http://" + self.Webserver + "/api/verifyDns", json={"Query": domain},
                            headers={"token": self.token}).json()
        if res["Msg"] == "false":
            return False
        else:
            return True


url = "http://192.168.41.2:8090/"

dns = DnsLog("1111:8888", "admin")

subDomain = dns.randomSubDomain()

payload = {
    "b": {
        "@type": "java.net.Inet4Address",
        "val": subDomain
    }
}

requests.post(url, json=payload)

if dns.checkDomain(subDomain):
    print("存在FastJosn")
```


## Stargazers over time

[![Stargazers over time](https://starchart.cc/lanyi1998/DNSlog-GO.svg)](https://starchart.cc/lanyi1998/DNSlog-GO)