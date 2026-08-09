from pathlib import Path

import netaddr
from curl_cffi import Session
from dns.resolver import Resolver

s = Session()
# 获取国内IP段
r = s.get("https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/cn.list")
cn_cidr = netaddr.IPSet(r.text.splitlines())
# 获得cloudflare的所有可用ip地址
# 官网数据
r = s.get("https://api.cloudflare.com/client/v4/ips")
r = r.json()["result"]
cf = netaddr.IPSet(r["ipv4_cidrs"] + r["ipv6_cidrs"])
# 国内节点
r = s.get("https://api.cloudflare.com/client/v4/ips?networks=jdcloud")
r = r.json()["result"]
cf_cn = netaddr.IPSet(r["ipv4_cidrs"] + r["ipv6_cidrs"])
# print(ipset1)
# 三方数据
r = s.get(
    "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/cloudflare.list"
)
cf_alt = netaddr.IPSet(r.text.splitlines())
# print(ipset3)
# 用于匹配
# cf_match = cf - cf_cn
# 用于扫描IP
cf_scan = cf_alt - cn_cidr
# with (
#     open("cf4.txt", "w", encoding="utf-8") as f4,
#     open("cf6.txt", "w", encoding="utf-8") as f6,
# ):
#     for i in cf.iter_cidrs():
#         if i.version == 4:
#             f4.write(str(i) + "\n")
#         else:
#             f6.write(str(i) + "\n")
res = set()
for i in cf_scan.iter_cidrs():
    if i.version == 4:
        if i.prefixlen > 24:
            res.add(i.supernet(24)[0].network)
        else:
            for j in i.subnet(24):
                res.add(j.network)
    else:
        if i.prefixlen > 48:
            res.add(i.supernet(48)[0].network)
        else:
            for j in i.subnet(48):
                res.add(j.network)

# print(res)
with open("cloudflare.txt", "w", encoding="utf-8") as f:
    for i in res:
        f.write(str(i) + "\n")
print(f"Total {len(res)} IPs written to cloudflare.txt")

# 获得cloudfront的所有可用ip地址
# 官网数据
r = s.get("https://ip-ranges.amazonaws.com/ip-ranges.json")
r = r.json()
cft = netaddr.IPSet()
for i in r["prefixes"]:
    if i["service"] == "CLOUDFRONT" and i["region"] == "GLOBAL":
        cft.add(i["ip_prefix"])
for i in r["ipv6_prefixes"]:
    if i["service"] == "CLOUDFRONT" and i["region"] == "GLOBAL":
        cft.add(i["ipv6_prefix"])
# print(ipset1)
# 三方数据
r = s.get(
    "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/cloudfront.list"
)
cft_alt = netaddr.IPSet(r.text.splitlines())
# print(ipset3)
# 用于匹配
# cft_match = cft - cn_cidr
# 用于扫描IP
cft_scan = cft_alt - cn_cidr
# print(r)
# with (
#     open("cft4.txt", "w", encoding="utf-8") as f4,
#     open("cft6.txt", "w", encoding="utf-8") as f6,
# ):
#     for i in cft_match.iter_cidrs():
#         if i.version == 4:
#             f4.write(str(i) + "\n")
#         else:
#             f6.write(str(i) + "\n")
res = set()
for i in cft_scan.iter_cidrs():
    if i.version == 4:
        if i.prefixlen > 24:
            res.add(i.supernet(24)[0].network)
        else:
            for j in i.subnet(24):
                res.add(j.network)
    else:
        if i.prefixlen > 48:
            res.add(i.supernet(48)[0].network)
        else:
            for j in i.subnet(48):
                res.add(j.network)

# print(res)
with open("cloudfront.txt", "w", encoding="utf-8") as f:
    for i in res:
        f.write(str(i) + "\n")
print(f"Total {len(res)} IPs written to cloudfront.txt")

r = s.get("https://api.fastly.com/public-ip-list")
r = r.json()
fast = netaddr.IPSet(r["addresses"] + r["ipv6_addresses"])
# 将ip地址转换为netaddr的ip对象
fast = netaddr.IPSet(fast)
# print(ipset1)
# 三方数据
r = s.get(
    "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/fastly.list"
)
fast_alt = netaddr.IPSet(r.text.splitlines())
# print(ipset3)
# 交集
# fastly_match = fast - cn_cidr
fastly_scan = fast_alt - cn_cidr
# print(r)
# with (
#     open("fastly4.txt", "w", encoding="utf-8") as f4,
#     open("fastly6.txt", "w", encoding="utf-8") as f6,
# ):
#     for i in fastly_match.iter_cidrs():
#         if i.version == 4:
#             f4.write(str(i) + "\n")
#         else:
#             f6.write(str(i) + "\n")
# 分割IP地址
res = set()
for i in fastly_scan.iter_cidrs():
    if i.version == 4:
        if i.prefixlen > 22:
            res.add(i.supernet(22)[0][256 + 229])
        else:
            for j in i.subnet(22):
                res.add(j[256 + 229])
    else:
        if i.prefixlen > 48:
            res.add(i.supernet(48)[0][0x485])
        else:
            for j in i.subnet(48):
                res.add(j[0x485])
with open("fastly.txt", "w", encoding="utf-8") as f:
    for i in res:
        f.write(str(i) + "\n")
print(f"Total {len(res)} IPs written to fastly.txt")


def parse(r):
    """解析google官方数据"""
    data = r.json()
    ipset = netaddr.IPSet()
    for prefix in data.get("prefixes", []):
        if "ipv4Prefix" in prefix:
            ipset.add(prefix["ipv4Prefix"])
        elif "ipv6Prefix" in prefix:
            ipset.add(prefix["ipv6Prefix"])
    return ipset


r = s.get(
    "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/google.list"
)
google_alt = netaddr.IPSet(r.text.splitlines())
# print(f"Google alt IPs: {len(google_alt)}")
# google官方数据
google = s.get("https://www.gstatic.com/ipranges/goog.json")
google = parse(google)
gcloud = s.get("https://www.gstatic.com/ipranges/cloud.json")
gcloud = parse(gcloud)
gdns = s.get("https://www.gstatic.com/ipranges/publicdns.json")
gdns = parse(gdns)
gbot = s.get(
    "https://developers.google.cn/static/crawling/ipranges/common-crawlers.json"
)
gbot = parse(gbot)
gbot1 = s.get(
    "https://developers.google.cn/static/crawling/ipranges/special-crawlers.json"
)
gbot1 = parse(gbot1)
gbot2 = s.get(
    "https://developers.google.cn/static/crawling/ipranges/user-triggered-fetchers.json"
)
gbot2 = parse(gbot2)
gbot3 = s.get(
    "https://developers.google.cn/static/crawling/ipranges/user-triggered-fetchers-google.json"
)
gbot3 = parse(gbot3)
gbot4 = s.get(
    "https://developers.google.cn/static/crawling/ipranges/user-triggered-agents.json"
)
gbot4 = parse(gbot4)
# 获得SPF记录
r = Resolver()
spf = netaddr.IPSet()
ans = r.resolve("_spf.google.com", "TXT")
if ans is None or ans.rrset is None:
    print("No TXT record found for _spf.google.com")
else:
    text = ans.rrset.to_text()
    print(f"SPF record for _spf.google.com: {text}")
    for record in text.split(" "):
        if record.startswith("ip4:"):
            spf.add(record[4:])
        elif record.startswith("ip6:"):
            spf.add(record[4:])
    print(spf)
gws = (
    google_alt
    & google - gcloud - gdns - gbot - gbot1 - gbot2 - gbot3 - gbot4 - spf - cn_cidr
)
with Path("google.txt").open("w") as f:
    for ip in gws.iter_cidrs():
        f.write(str(ip) + "\n")
