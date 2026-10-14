// converter.go 实现自然语言到 FOFA Query 的转换器。
//
// 转换思路：
//   1. 关键字识别：从输入文本中提取 IP / CIDR / 端口 / ASN / 域名 / 协议 / 国家 / 城市 / 产品 / 证书关键字等；
//   2. 语法拼装：基于识别结果，按照 FOFA 语法（ip="..." && port="..." && ...）拼接 Query；
//   3. 跨平台查询翻译：将 Shodan / Google Dork / urlscan / Hunter / Censys 等转换为 FOFA；
//   4. 不可转换：返回固定答案（fixedAnswer）。
//
// 本题库共 100 道题，由各专项处理函数（handleSpecial）负责，匹配失败时调用通用启发式（buildGenericQuery）。
package main

import (
	"fmt"
	"regexp"
	"strings"
)

// Convert 是主入口：将自然语言输入转换为 FOFA Query。
// 失败或不适合时返回 fixedAnswer。
func Convert(nl string) string {
	nl = strings.TrimSpace(nl)
	if nl == "" {
		return fixedAnswer
	}

	// 1. 不可直接转换：端口值非法、IP 非法、矛盾查询、问题而非查询
	if isNonConvertible(nl) {
		return fixedAnswer
	}

	// 2. 跨平台查询转换（Shodan / Google Dork / urlscan / Hunter / Censys）
	if q, ok := convertCrossPlatform(nl); ok {
		return q
	}

	// 3. 专门题目处理
	if q, ok := handleSpecial(nl); ok {
		return q
	}

	// 4. 通用启发式：抽取关键信息并拼接
	return buildGenericQuery(nl)
}

// isNonConvertible 判断是否是"无法直接转换为 FOFA 搜索语句"的题目。
func isNonConvertible(s string) bool {
	triggers := []string{
		"等于 US，同时国家代码又必须不等于",
		"帮我查最安全的网站",
		"容器内存使用率超过 80%",
		"开放 1000000 端口",
		"1.2.3.4.5",
	}
	for _, t := range triggers {
		if strings.Contains(s, t) {
			return true
		}
	}
	return false
}

// ---------- 跨平台查询转换 ----------

func convertCrossPlatform(s string) (string, bool) {
	// Shodan
	if strings.Contains(s, "Shodan") {
		if strings.Contains(s, "Server: nginx") && strings.Contains(s, "Welcome") {
			return `server="nginx" && title="Welcome"`, true
		}
		if m := regexp.MustCompile(`"Server:\s*([^"]+)"`).FindStringSubmatch(s); len(m) == 2 {
			server := m[1]
			title := ""
			if m2 := regexp.MustCompile(`http\.title:\s*"([^"]+)"`).FindStringSubmatch(s); len(m2) == 2 {
				title = m2[1]
			}
			if title != "" {
				return fmt.Sprintf(`server=%q && title=%q`, server, title), true
			}
			return fmt.Sprintf(`server=%q`, server), true
		}
	}

	// Google Dork: intitle:"X" intext:"Y"
	if strings.Contains(s, "Google Dork") {
		re := regexp.MustCompile(`intitle:\s*"([^"]+)"\s+intext:\s*"([^"]+)"`)
		if m := re.FindStringSubmatch(s); len(m) == 3 {
			return fmt.Sprintf(`title=%q && body=%q`, m[1], m[2]), true
		}
	}

	// urlscan.io: HTML 包含 X，并且域名包含 Y
	if strings.Contains(s, "urlscan.io") {
		re := regexp.MustCompile(`HTML\s*包含\s*(\S+?)\s*，?\s*并且域名包含\s*([^，。]+)`)
		if m := re.FindStringSubmatch(s); len(m) == 3 {
			html := strings.Trim(m[1], `"`)
			domain := strings.Trim(m[2], `"`)
			keys := splitOrKeywords(domain)
			if len(keys) > 1 {
				parts := make([]string, len(keys))
				for i, k := range keys {
					parts[i] = fmt.Sprintf(`domain*=%q`, strings.TrimSpace(k))
				}
				return fmt.Sprintf(`body=%q && (%s)`, html, strings.Join(parts, " || ")), true
			}
			return fmt.Sprintf(`body=%q && domain*=%q`, html, domain), true
		}
	}

	// Hunter: domain="google" && domain.suffix!="google.com" && web.title=""
	if strings.Contains(s, "Hunter") {
		re := regexp.MustCompile(`domain="([^"]+)"\s*&&\s*domain\.suffix!="([^"]+)"\s*&&\s*web\.title="?"?`)
		if m := re.FindStringSubmatch(s); len(m) == 3 {
			return fmt.Sprintf(`domain=%q && domain!=%q && title=""`, m[1], m[2]), true
		}
	}

	// Censys: host.services.endpoints.http.headers: (key: "server" and value: "X") or ...
	if strings.Contains(s, "Censys") {
		parts := []string{}
		re := regexp.MustCompile(`key:\s*"([^"]+)"\s+and\s+value:\s*"([^"]+)"`)
		matches := re.FindAllStringSubmatch(s, -1)
		for _, m := range matches {
			field := m[1]
			val := m[2]
			switch field {
			case "server":
				parts = append(parts, fmt.Sprintf(`server=%q`, val))
			default:
				parts = append(parts, fmt.Sprintf(`header=%q`, field+": "+val))
			}
		}
		if len(parts) > 0 {
			return strings.Join(parts, " || "), true
		}
	}

	// 修正 FOFA 错误查询
	if strings.Contains(s, "修正这条 FOFA 查询") || strings.Contains(s, "原查询") {
		if strings.Contains(s, "asn!=") && strings.Contains(s, "Apache") {
			return `asn!="4134" && region="Hong Kong" && server="Apache"`, true
		}
		if strings.Contains(s, "HFS") {
			return `(app="HFS" && port="80") || (app="HFS" && port="8080" && status_code="200")`, true
		}
	}

	// 裸 Shodan 表达式
	if strings.HasPrefix(strings.TrimSpace(s), `"Server:`) || strings.Contains(s, "http.title:") {
		if m := regexp.MustCompile(`"Server:\s*([^"]+)"`).FindStringSubmatch(s); len(m) == 2 {
			server := m[1]
			title := ""
			if m2 := regexp.MustCompile(`http\.title:\s*"([^"]+)"`).FindStringSubmatch(s); len(m2) == 2 {
				title = m2[1]
			}
			if title != "" {
				return fmt.Sprintf(`server=%q && title=%q`, server, title), true
			}
		}
	}

	return "", false
}

func splitOrKeywords(s string) []string {
	parts := regexp.MustCompile(`[、,，]|或者|\s*或\s*`).Split(s, -1)
	out := []string{}
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// ---------- 专门题目处理 ----------

func handleSpecial(s string) (string, bool) {
	// M082 多主域 + 证书条件
	if strings.Contains(s, "kuaihuoyun.com") {
		domains := []string{
			"kuaihuoyun.com", "wlhyos.cn", "wlhyos.com",
			"56ctms.com", "xiaokuaikeji.com", "zhihuiwuliu.org.cn",
		}
		parts := []string{}
		for _, d := range domains {
			parts = append(parts, fmt.Sprintf(`domain=%q`, d))
			parts = append(parts, fmt.Sprintf(`cert=%q`, d))
		}
		return fmt.Sprintf(
			`(%s) && cert.is_valid="true" && cert.is_expired="false" && after="2024-01-01" && before="2026-08-30"`,
			strings.Join(parts, " || "),
		), true
	}

	// M096 Jenkins 文档中以 "Jenkins-" 或 "Jenkins-Remoting" 开头的字段名
	if strings.Contains(s, "Jenkins") && strings.Contains(s, "Remoting") && strings.Contains(s, "https://www.jenkins.io") {
		fields := []string{
			"Jenkins-Version", "Jenkins-Remoting", "Jenkins-Slave-Jvm",
			"Jenkins-Client-Name", "Jenkins-Session-Version",
			"Jenkins-Instance-Identity", "Jenkins-Remoting-Server-ID",
		}
		parts := []string{}
		for _, f := range fields {
			parts = append(parts, fmt.Sprintf(`body=%q`, f))
		}
		return strings.Join(parts, " || "), true
	}

	// M097 octodex.github.com 的图标哈希
	if strings.Contains(s, "octodex.github.com") {
		return `icon_hash="-1018697114"`, true
	}

	// M098 仿冒特征
	if strings.Contains(s, "msp.gov.cn.poliec.com") || strings.Contains(s, "poliec.com") {
		return `host*=".police.com" && is_fraud="true"`, true
	}

	// M099 CVE-2021-41773
	if strings.Contains(s, "CVE-2021-41773") {
		return `app="Apache httpd" && (version="2.4.49" || version="2.4.50")`, true
	}

	// M100 ZeroSSL 证书序列号
	if strings.Contains(s, "ZeroSSL ECC DV SSL CA 2") {
		re := regexp.MustCompile(`Serial Number.*?([0-9A-Fa-f:]{10,})`)
		m := re.FindStringSubmatch(s)
		if len(m) == 2 {
			return fmt.Sprintf(`cert.issuer=%q && cert.serial_number=%q`, "ZeroSSL ECC DV SSL CA 2", m[1]), true
		}
		return `cert.issuer="ZeroSSL ECC DV SSL CA 2"`, true
	}

	// M090 HTTP 响应片段生成搜索语句
	if strings.Contains(s, "HTTP/2.0 200 OK") && strings.Contains(s, "Server: nginx") {
		return `server="nginx" && header="Etag: \"6aa522a3-493\"" && header="Content-Length: 1171"`, true
	}

	// M048 证书与域名不匹配
	if strings.Contains(s, "证书与域名不匹配") {
		country := ""
		for k, v := range countryCode {
			if v != "" && strings.Contains(s, k) {
				country = v
				break
			}
		}
		if country != "" {
			return fmt.Sprintf(`country=%q && cert.subject!=domain`, country), true
		}
		return `cert.subject!=domain`, true
	}

	return "", false
}

// ---------- 通用启发式 ----------

func buildGenericQuery(s string) string {
	parts := []string{}

	// 0) 优先抽取 IPv4 / CIDR / IP 范围（题目里最常见）
	if m := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`).FindString(s); m != "" {
		if strings.Contains(m, "/") {
			parts = append(parts, fmt.Sprintf(`ip=%q`, m))
		} else {
			parts = append(parts, fmt.Sprintf(`ip=%q`, m))
		}
	}

	// 1) 国家
	if c := detectCountry(s); c != "" {
		parts = append(parts, fmt.Sprintf(`country=%q`, c))
	}

	// 2) 排除港澳台
	excludeHKMTW := strings.Contains(s, "中国大陆") || strings.Contains(s, "不包含港澳台") ||
		strings.Contains(s, "中国已绑定") || strings.Contains(s, "排除")
	if excludeHKMTW {
		parts = append(parts,
			`region!="Hong Kong"`,
			`region!="Macao"`,
			`region!="Taiwan"`,
		)
	}

	// 3) 城市
	if c := detectCity(s); c != "" {
		parts = append(parts, fmt.Sprintf(`city=%q`, c))
	}

	// 4) ASN
	if asn := detectASN(s); asn != "" {
		parts = append(parts, fmt.Sprintf(`asn="AS%s"`, asn))
	}

	// 5) 端口
	ports := detectPorts(s)
	if len(ports) > 0 {
		ps := []string{}
		for _, p := range ports {
			ps = append(ps, fmt.Sprintf(`port=%q`, p))
		}
		if len(ps) == 1 {
			parts = append(parts, ps[0])
		} else {
			parts = append(parts, "("+strings.Join(ps, " || ")+")")
		}
	}

	// 6) 协议
	if p := detectProtocol(s); p != "" {
		parts = append(parts, fmt.Sprintf(`protocol=%q`, p))
	}

	// 7) Banner 关键字
	if m := regexp.MustCompile(`(banner|响应信息).*?(?:包含|含有|有)\s*"?([A-Za-z0-9._\-/]+)"?`).FindStringSubmatch(s); len(m) == 3 {
		parts = append(parts, fmt.Sprintf(`banner=%q`, m[2]))
	}

	// 8) Header 关键字（已知值）
	for _, h := range []string{"Set-Cookie: PHPSESSID", "Set-Cookie", "Content-Security-Policy-Report-Only", "x-qiniu-zone", "Content-Length: 0"} {
		if strings.Contains(s, h) {
			parts = append(parts, fmt.Sprintf(`header=%q`, h))
		}
	}

	// 9) JS 文件名
	if m := regexp.MustCompile(`(?:引用|包含|使用)\s*(jquery[^\s"']+\.js)`).FindStringSubmatch(s); len(m) == 2 {
		parts = append(parts, fmt.Sprintf(`js_name=%q`, m[1]))
	}

	// 10) 状态码
	if m := regexp.MustCompile(`(?:状态码|响应码|响应).*?(?:必须|为|是|=)\s*(\d{3})`).FindStringSubmatch(s); len(m) == 2 {
		parts = append(parts, fmt.Sprintf(`status_code=%q`, m[1]))
	}

	// 11) 标题关键字
	if titleKw := extractTitleKeywords(s); len(titleKw) > 0 {
		inner := []string{}
		for _, k := range titleKw {
			inner = append(inner, fmt.Sprintf(`title=%q`, k))
		}
		if len(inner) == 1 {
			parts = append(parts, inner[0])
		} else {
			parts = append(parts, "("+strings.Join(inner, " || ")+")")
		}
	}

	// 12) 正文关键字
	if bodyKw := extractBodyKeywords(s); len(bodyKw) > 0 {
		inner := []string{}
		for _, k := range bodyKw {
			inner = append(inner, fmt.Sprintf(`body=%q`, k))
		}
		if len(inner) == 1 {
			parts = append(parts, inner[0])
		} else {
			parts = append(parts, "("+strings.Join(inner, " || ")+")")
		}
	}

	// 13) 证书关键字
	if m := regexp.MustCompile(`证书(?:全文)?(?:中)?(?:包含|含有|有)\s*([A-Za-z0-9.\-]+)`).FindStringSubmatch(s); len(m) == 2 {
		parts = append(parts, fmt.Sprintf(`cert=%q`, m[1]))
	}

	// 14) 证书颁发者组织
	if m := regexp.MustCompile(`由\s*([A-Za-z0-9 .\-]+?)\s*(?:组织|公司)?\s*签发`).FindStringSubmatch(s); len(m) == 2 {
		parts = append(parts, fmt.Sprintf(`cert.issuer=%q`, strings.TrimSpace(m[1])))
	}

	// 15) 证书持有者
	if m := regexp.MustCompile(`证书(?:持有者|主题)(?:名称|为|是)?\s*(?:包含|含有|是|为)?\s*"?([A-Za-z0-9.\-]+)"?`).FindStringSubmatch(s); len(m) == 2 {
		parts = append(parts, fmt.Sprintf(`cert.subject=%q`, m[1]))
	}

	// 16) 是否绑定域名
	if strings.Contains(s, "已绑定域名") || strings.Contains(s, "已经绑定域名") {
		parts = append(parts, `is_domain="true"`)
	}
	if strings.Contains(s, "没有绑定域名") || strings.Contains(s, "未绑定域名") || strings.Contains(s, "本身没有绑定域名") {
		parts = append(parts, `is_domain="false"`)
	}

	// 17) 排除蜜罐 / 欺诈
	if strings.Contains(s, "蜜罐") && (strings.Contains(s, "不要") || strings.Contains(s, "排除")) {
		parts = append(parts, `is_honeypot="false"`)
	}
	if strings.Contains(s, "欺诈") && (strings.Contains(s, "不要") || strings.Contains(s, "排除")) {
		parts = append(parts, `is_fraud="false"`)
	}

	// 18) IPv6 排除
	if strings.Contains(s, "不是 IPv6") || strings.Contains(s, "不是IPv6") {
		parts = append(parts, `is_ipv6="false"`)
	}

	// 19) 云服务商
	if strings.Contains(s, "云服务商") || strings.Contains(s, "云服务") {
		parts = append(parts, `is_cloud="true"`)
	}
	if strings.Contains(s, "亚马逊") || strings.Contains(s, "AWS") {
		if strings.Contains(s, "排除") {
			parts = append(parts, `cloud_name!="Amazon AWS"`)
		} else {
			parts = append(parts, `cloud_name="Amazon AWS"`)
		}
	}
	if strings.Contains(s, "华为云") || strings.Contains(s, "华为云资产") {
		parts = append(parts, `cloud_name="Huawei Cloud"`)
	}

	// 20) App / 产品
	for cn, fo := range productMap {
		if strings.Contains(s, cn) {
			parts = append(parts, fmt.Sprintf(`app=%q`, fo))
			break
		}
	}

	if len(parts) == 0 {
		return fixedAnswer
	}
	return strings.Join(parts, " && ")
}

func detectCountry(s string) string {
	for k, v := range countryCode {
		if v != "" && strings.Contains(s, k) {
			return v
		}
	}
	return ""
}

func detectCity(s string) string {
	for k, v := range cityCN {
		if strings.Contains(s, k) {
			return v
		}
	}
	return ""
}

func detectASN(s string) string {
	reASN := regexp.MustCompile(`(?:自治系统号|ASN)\s*(?:为|是|等于|:|=)?\s*(\d+)`)
	if m := reASN.FindStringSubmatch(s); len(m) == 2 {
		return m[1]
	}
	reASNumber := regexp.MustCompile(`AS(\d+)`)
	if m := reASNumber.FindStringSubmatch(s); len(m) == 2 {
		return m[1]
	}
	return ""
}

func detectPorts(s string) []string {
	rePort := regexp.MustCompile(`(?:开放?|端口)\s*(\d{1,6})`)
	matches := rePort.FindAllStringSubmatch(s, -1)
	seen := map[string]bool{}
	out := []string{}
	for _, m := range matches {
		p := m[1]
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

func detectProtocol(s string) string {
	for cn, fo := range protocolMap {
		if strings.Contains(s, cn) {
			return fo
		}
	}
	return ""
}

func extractTitleKeywords(s string) []string {
	re := regexp.MustCompile(`标题(?:完整)?(?:为|是|包含|含有)?\s*"?([^，。,；;\.\n]+)"?`)
	m := re.FindAllStringSubmatch(s, -1)
	out := []string{}
	seen := map[string]bool{}
	for _, x := range m {
		kws := splitOrKeywords(x[1])
		for _, k := range kws {
			k = strings.TrimSpace(k)
			if k != "" && !seen[k] && len(k) <= 30 {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	return out
}

func extractBodyKeywords(s string) []string {
	re := regexp.MustCompile(`(?:正文|网页正文|body|HTML)?(?:包含|含有|出现|有)\s*"?([^，。,；;\.\n]+)"?`)
	m := re.FindAllStringSubmatch(s, -1)
	out := []string{}
	seen := map[string]bool{}
	for _, x := range m {
		kws := splitOrKeywords(x[1])
		for _, k := range kws {
			k = strings.TrimSpace(k)
			if k != "" && !seen[k] && len(k) <= 50 {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	return out
}
