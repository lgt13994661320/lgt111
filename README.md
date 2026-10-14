# FOFA 自然语言查询转换参赛项目

本目录是 FOFA 网络空间测绘自然语言查询转换比赛的产出物。参赛包编号：**pkg-08e82c8d**，发放时间：2026-09-22 10:56:20。

## 文件清单

| 文件 | 说明 |
|------|------|
| `题目.json` | 100 道原始题目（题号 + 自然语言输入） |
| `答案.json` | 完成后的答案文件（**比赛提交此文件**） |
| `答案模板.json` | 空白答案模板，题号已填好 |
| `参赛包.txt` | 参赛包编号与发放时间 |
| `README.md` | 本说明 |
| `main.go` | Go 主程序入口 |
| `types.go` | 数据结构定义 |
| `rules.go` | FOFA 映射规则（国家、地区、城市、产品等） |
| `converter.go` | 自然语言到 FOFA Query 的转换逻辑 |
| `generate_answers.py` | Python 脚本，用于批量生成 `答案.json` |

## 使用方式

### 直接提交答案

直接将 `答案.json` 上传至比赛网站。

### 重新生成答案

需要 Python 3.x 环境：

```bash
python generate_answers.py
```

### 调试单题

```bash
go run . -q "请查询 IP 地址为 1.1.1.1 的资产。"
```

输出示例：

```
ip="1.1.1.1"
```

### 使用 Go 程序批量处理

```bash
go run . -i 题目.json -o 答案.json -p "选手名称" -pkg "pkg-08e82c8d"
```

## 转换规则速查（FOFA 查询语法）

```
=        等于（精确匹配）
==       完全等于（区分大小写）
!=       不等于
*=       模糊匹配（个人版及以上）
&&       AND
||       OR
()       优先级
```

主要字段：

| 类别 | 字段 |
|------|------|
| 网络/IP | `ip` / `host` / `domain` / `cname` / `asn` / `port` / `protocol` / `base_protocol` |
| 地理/组织 | `country` / `region` / `city` / `org` / `cloud_name` / `is_cloud` |
| 服务器 | `server` / `os` / `app` / `product` / `product_category` / `version` / `framework` / `middleware` |
| 内容 | `title` / `body` / `header` / `banner` / `js_name` / `icp` / `status_code` |
| 证书 | `cert` / `cert.subject` / `cert.issuer` / `cert.subject.org` / `cert.serial_number` / `cert.is_valid` / `cert.is_expired` / `cert.domain` |
| 标记 | `fid` / `jarm` / `ja3s` / `icon_hash` / `header_hash` / `body_hash` |
| 风险 | `is_honeypot` / `is_fraud` / `is_ipv6` / `is_domain` |
| 时间 | `after` / `before` |

## 解答思路

1. **信息抽取**：从自然语言中提取 IP、CIDR、IP 范围、端口、协议、国家、地区、城市、ASN、组织、云厂商、关键字、证书字段、协议 banner 等；
2. **字段映射**：基于 FOFA 语法将抽取结果映射到对应字段；
3. **逻辑拼接**：使用 `&&` / `||` / `!=` / `()` 组合；
4. **跨平台查询翻译**：把 Shodan、 Google Dork、urlscan、 Hunter、 Censys 翻译成 FOFA 语法；
5. **不可转换**：当输入为非法值（端口 1000000、IP 1.2.3.4.5）、矛盾查询（country=US 且 country!=US）、或语义上 FOFA 无法表达（"最安全的网站"、"容器内存使用率 >80%"）时，填写固定答案 `该需求不能直接转换为FOFA搜索语句`。

## 固定答案清单

下列 9 道题使用固定答案：

| 题号 | 自然语言输入（摘要） |
|------|---------------------|
| M015-S001 | fofa有识别SOCKS的v5版本吗？（问题而非查询） |
| M025-S010 | 按"中间件"门类查找资产（FOFA 无中间件大类） |
| M047-S011 | 证书颁发者与持有者不匹配（FOFA 无比较字段） |
| M081-S011 | 至少四项有两项有值（FOFA 无"至少 N 项"语义） |
| M091-S009 | 端口 1000000（端口值不合法） |
| M092-S007 | 地址 1.2.3.4.5（IP 值不合法） |
| M093-S004 | country=US 且 country!=US（矛盾） |
| M094-S004 | 最安全的网站（无法量化） |
| M095-S010 | 容器内存使用率超过 80%（FOFA 无此数据） |
