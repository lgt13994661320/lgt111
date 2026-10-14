#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
根据 题目.json 生成符合要求的 答案.json。
依据 FOFA 查询语法进行自然语言到 FOFA Query 的转换。

支持的语法（部分示例）：
  ip="..."            - IP 地址 / CIDR / 范围
  host="..."          - 主机名 / 域名
  domain="..."        - 主域名
  port="..."          - 端口
  protocol="..."      - 应用层协议
  base_protocol="..." - 传输层协议
  country="CN"        - 国家代码
  region="..."        - 行政区（英文）
  city="..."          - 城市
  asn="AS4134"        - 自治系统号
  org="..."           - 组织
  cloud_name="..."    - 云厂商
  is_cloud="true"     - 是否云资产
  is_domain="true"    - 是否绑定域名
  is_ipv6="true"      - 是否 IPv6
  is_honeypot="false" - 是否蜜罐
  is_fraud="false"    - 是否欺诈
  title="..."         - 网页标题
  body="..."          - 网页正文
  header="..."        - HTTP 响应头
  banner="..."        - 协议 banner
  js_name="..."       - JS 文件名
  status_code="..."   - HTTP 状态码
  server="..."        - 服务器中间件
  os="..."            - 操作系统
  app="..."           - 应用指纹
  product="..."       - 产品
  product_category="..." - 产品门类
  version="..."       - 版本
  cert="..."          - 证书全文
  cert.subject="..."  - 证书主题
  cert.issuer="..."   - 证书颁发者
  cert.subject.org="..." - 证书持有者组织
  cert.serial_number="..." - 证书序列号
  cert.is_valid="true" - 证书有效
  cert.is_expired="false" - 证书未过期
  cert.domain="..."   - 证书关联域名
  fid="..."           - FOFA ID
  jarm="..."          - JARM 指纹
  ja3s="..."          - JA3S 指纹
  icon_hash="..."     - 网站图标哈希
  cname="..."         - CNAME
  after="YYYY-MM-DD"  - 收录时间之后
  before="YYYY-MM-DD" - 收录时间之前

逻辑运算符：
  =        等于（精确匹配）
  ==       完全等于
  !=       不等于
  *=       模糊匹配（个人版及以上）
  &&       AND
  ||       OR
  ()       优先级
"""

import json
import re
import shutil
from pathlib import Path

# 固定答案：无法直接转换为 FOFA 搜索语句的题目
FIXED = "该需求不能直接转换为FOFA搜索语句"

# 各题目的 FOFA 查询语句（按题号顺序）
ANSWERS = {
    "M001-S009": 'ip="20.247.40.92"',
    "M002-S004": 'ip="124.255.254.0/24"',
    "M003-S002": 'domain="zendesk.com"',
    "M004-S003": 'host="www.amazon.com"',
    "M005-S004": 'domain*="vpn"',
    "M006-S002": 'country="GB"',
    "M007-S007": 'country="KR" && region="Gangwon"',
    "M008-S009": 'country="DE" && region="Bavaria" && city="Munich"',
    "M009-S008": 'asn="AS4134"',
    "M010-S009": 'country="NL" && cloud_name="Amazon AWS"',
    "M011-S005": 'region="Hebei" && cloud_name="Huawei Cloud"',
    "M012-S009": 'port="3000"',
    "M013-S003": '(title="Jenkins" || body="jenkins") && country!="CN" && after="2026-08-01"',
    "M014-S002": 'protocol="dns" && country="CN"',
    "M015-S001": FIXED,
    "M016-S006": 'protocol="ssh" && port="22022"',
    "M017-S001": 'base_protocol="tcp"',
    "M018-S006": 'protocol="snmp"',
    "M019-S010": 'protocol="memcached" && country="US"',
    "M020-S005": 'protocol="ftp" && base_protocol="tcp"',
    "M021-S010": 'protocol="ssh" && banner="OpenSSH_10.4"',
    "M022-S007": 'country="JP" && app="Hikvision"',
    "M023-S002": 'domain="163.com" && host="?.?.163.com"',
    "M024-S005": 'version="10.0.0"',
    "M025-S010": FIXED,
    "M026-S002": 'body="NoSuchUpload"',
    "M027-S008": 'header="Content-Security-Policy-Report-Only"',
    "M028-S011": 'status_code="308"',
    "M029-S010": 'banner="SSH-2.0-OpenSSH_6.1"',
    "M030-S003": 'header="Set-Cookie: PHPSESSID"',
    "M031-S009": 'js_name="jquery.min.js"',
    "M032-S010": 'country="NL" && city="Amsterdam" && port="554" && banner="200 OK"',
    "M033-S003": 'cert.issuer="GlobalSign" && cert.is_valid="true"',
    "M034-S007": 'cert.subject="apple.com" && domain!="apple.com"',
    "M035-S010": 'cert="TrustAsia"',
    "M036-S007": 'cert.subject.org="Alibaba"',
    "M037-S008": 'domain="sohu.com" && banner!="" && banner!="apache"',
    "M038-S009": 'cert="adobe.com"',
    "M039-S001": 'cert.subject="qq.com"',
    "M040-S011": 'cert="godaddy" && domain!="godaddy.com"',
    "M041-S001": 'cert="google.com" && is_honeypot="false" && is_fraud="false"',
    "M042-S003": 'cert.subject*="example.com" || cert*="example.com"',
    "M043-S004": 'protocol="tls1.0" && cert.is_valid="true"',
    "M044-S007": 'jarm="21d21d00021d21d00021d21d21d21dce319294781f0e12867fd06896a000ea" && status_code="307" && header="Content-Length: 0"',
    "M045-S001": 'os="linux"',
    "M046-S013": 'country="CN" && is_domain="false"',
    "M047-S011": FIXED,
    "M048-S001": 'country="CA" && cert.subject!=domain',
    "M049-S010": 'country="TR" && ja3s="f4febc55ea12b31ae17cfb7e614afda8"',
    "M050-S004": 'org*="Inc"',
    "M051-S001": 'country="US" && org="OVH SAS" && port="2087" && title="WHM 登录"',
    "M052-S002": 'host*=".io" && app="WordPress"',
    "M053-S009": 'city="Xiamen" && port="80" && status_code="200"',
    "M054-S009": 'country="GB" && org="DigitalOcean" && body="/api/show"',
    "M055-S003": 'country="CN" && header="Set-Cookie" && body="/admin"',
    "M056-S008": 'domain="baidu.com" && ((title="Login" || title="admin" || title="Dashboard" || title="管理") || header="Set-Cookie")',
    "M057-S012": 'ip="13.0.0.0/8" && status_code="200" && (body="Welcome" || body="Sign in" || body="Dashboard")',
    "M058-S012": 'country="DE" && (host="amazonaws.com" || domain="amazonaws.com" || cname="amazonaws.com" || cert="amazonaws.com" || cert.domain="amazonaws.com")',
    "M059-S006": 'port="143" && cert.serial_number="1" && (cert="TAK" || cert="ATAK" || cert="WinTAK" || cert="Squad" || cert="CoT")',
    "M060-S010": 'ip="113.247.228.0/24" && (port="80" || port="443" || port="8080" || port="8443")',
    "M061-S005": '(title="Sign in" || title="Login") && port="80" && is_ipv6="false"',
    "M062-S010": 'country="NZ" && (port="80" || port="443") && is_cloud="true"',
    "M063-S001": '((banner="IIS" && banner*="1.") || header="IIS")',
    "M064-S004": 'country="JP" && is_domain="true" && port="443" && status_code="200" && cert.is_valid="true" && ((title="大学" || title="学部" || title="研究") || (body="入学案内" || body="学生"))',
    "M065-S004": 'domain="baidu.com" && ((title="系统" || title="平台" || title="登录" || title="管理" || title="API") || (host="api.baidu.com" || host="admin.baidu.com" || host="dev.baidu.com" || host="test.baidu.com" || host="uat.baidu.com" || host="pre.baidu.com"))',
    "M066-S006": 'product_category="邮件系统" && title="Mail" && country!="US"',
    "M067-S008": 'country="CN" && region!="Hong Kong" && region!="Macao" && region!="Taiwan" && port="8888"',
    "M068-S005": 'body="Jenkins" && title!="Jenkins"',
    "M069-S001": 'region="Taiwan" && asn="AS20940" && port="443" && protocol="tls1.3" && cert.issuer!="Let\'s Encrypt" && cert.issuer!="ZeroSSL"',
    "M070-S003": 'app="HFS" && country!="JP" && status_code="200" && title="HFS /" && cloud_name!="Amazon AWS"',
    "M071-S006": 'country="CN" && region!="Hong Kong" && region!="Macao" && region!="Taiwan" && app="Grafana"',
    "M072-S008": 'domain=".edu.ar" && (port="80" || port="443") && server!="Nginx" && server!="WAF"',
    "M073-S003": 'ip="1.1.1.1" && is_domain="true"',
    "M074-S008": 'cert="aliyun.com" && cert.is_valid="true" && is_domain="false"',
    "M075-S006": 'country="CN" && is_domain="true" && header="x-qiniu-zone" && domain!="qiniudn.com"',
    "M076-S004": 'title="" && status_code="200" && fid!="" && icon_hash!="" && host*="admin" && (domain=".cn" || domain="????.com")',
    "M077-S009": 'body="class=\\"container\\""',
    "M078-S009": 'body="\\"exception\\": \\"Symfony\\\\Component\\\\ErrorHandler\\\\Error\\\\FatalError\\""',
    "M079-S006": 'ip="40.88.0.0/16"',
    "M080-S006": 'ip="47.96.0.1-47.96.0.5" && (port="80" || port="443")',
    "M081-S011": FIXED,
    "M082-S001": '(domain="kuaihuoyun.com" || domain="wlhyos.cn" || domain="wlhyos.com" || domain="56ctms.com" || domain="xiaokuaikeji.com" || domain="zhihuiwuliu.org.cn" || cert="kuaihuoyun.com" || cert="wlhyos.cn" || cert="wlhyos.com" || cert="56ctms.com" || cert="xiaokuaikeji.com" || cert="zhihuiwuliu.org.cn") && cert.is_valid="true" && cert.is_expired="false" && after="2024-01-01" && before="2026-08-30"',
    "M083-S008": 'server="nginx" && title="Welcome"',
    "M084-S004": 'title="Grafana" && body="JavaScript"',
    "M085-S001": 'body="login" && (domain*="bet" || domain*="casino" || domain*="kasino")',
    "M086-S006": 'domain="google" && domain!="google.com" && title=""',
    "M087-S009": '(server="Tengine" || header="x-cache: MISS")',
    "M088-S004": 'asn!="4134" && region="Hong Kong" && server="Apache"',
    "M089-S010": '(app="HFS" && port="80") || (app="HFS" && port="8080" && status_code="200")',
    "M090-S008": 'server="nginx" && header="Etag: \\"6aa522a3-493\\"" && header="Content-Length: 1171"',
    "M091-S009": FIXED,
    "M092-S007": FIXED,
    "M093-S004": FIXED,
    "M094-S004": FIXED,
    "M095-S010": FIXED,
    "M096-S001": 'body="Jenkins-Version" || body="Jenkins-Remoting" || body="Jenkins-Slave-Jvm" || body="Jenkins-Client-Name" || body="Jenkins-Session-Version" || body="Jenkins-Instance-Identity" || body="Jenkins-Remoting-Server-ID"',
    "M097-S001": 'icon_hash="-1018697114"',
    "M098-S001": 'host*=".police.com" && is_fraud="true"',
    "M099-S001": 'app="Apache httpd" && (version="2.4.49" || version="2.4.50")',
    "M100-S001": 'cert.issuer="ZeroSSL ECC DV SSL CA 2" && cert.serial_number="63:BD:83:71:62:14:83:6E:F8:00:75:35:61:61:EB:06"',
}


def main():
    out_dir = Path(r"D:/GoWork/1")
    out_dir.mkdir(parents=True, exist_ok=True)

    # 读取题目（从工作目录读取）
    questions_path = out_dir / "题目.json"
    with open(questions_path, "r", encoding="utf-8") as f:
        questions = json.load(f)

    # 生成答案
    answers = []
    missing = []
    for q in questions:
        qid = q["题号"]
        if qid not in ANSWERS:
            missing.append(qid)
            ans = FIXED
        else:
            ans = ANSWERS[qid]
        answers.append({"题号": qid, "查询语句": ans})

    if missing:
        print(f"[WARN] 题号未匹配，使用固定答案：{missing}")

    # 答案文件
    answer_doc = {
        "选手名称": "GoEngineer-参赛者",
        "参赛包编号": "pkg-08e82c8d",
        "答案": answers,
    }

    answer_path = out_dir / "答案.json"
    with open(answer_path, "w", encoding="utf-8") as f:
        json.dump(answer_doc, f, ensure_ascii=False, indent=2)

    # 答案模板
    template = {
        "选手名称": "GoEngineer-参赛者",
        "参赛包编号": "pkg-08e82c8d",
        "答案": [{"题号": q["题号"], "查询语句": ANSWERS.get(q["题号"], FIXED)} for q in questions],
    }
    template_path = out_dir / "答案模板.json"
    with open(template_path, "w", encoding="utf-8") as f:
        json.dump(template, f, ensure_ascii=False, indent=2)

    # 参赛包.txt
    pkg_path = out_dir / "参赛包.txt"
    if not pkg_path.exists():
        pkg_path.write_text("pkg-08e82c8d\n2026-09-22T10:56:20+08:00\n", encoding="utf-8")

    print(f"[OK] 已生成 {len(answers)} 道答案 -> {answer_path}")
    print(f"[OK] 模板文件 -> {template_path}")
    print(f"[OK] 题目数量: {len(questions)}, 已匹配: {len(answers) - len(missing)}, 未匹配（固定答案）: {len(missing)}")


if __name__ == "__main__":
    main()
