// ss/ssr/vmess URI decoder tools

package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/oschwald/geoip2-golang"
	"gopkg.in/yaml.v3"
)

var proxies map[string][]interface{}

var proxy_name_list = proxies["proxies"][:]
var proxy_list []map[string]interface{}
var uri_list string
var ifile string
var outfile string
var db_path string
var proxy_uri string
var geo2db *geoip2.Reader

func init() {
	flag.StringVar(&uri_list, "uri", "", "uri to be decoded.")
	flag.StringVar(&ifile, "ifile", "", "input file: base64 encoded data or normal text eg. ss://,ssr://,vmess://.")
	flag.StringVar(&outfile, "out", "", "output file path.")
	flag.StringVar(&db_path, "db", "Country.mmdb", "geoip2 Country mmdb path")
	flag.StringVar(&proxy_uri, "proxy", "socks5://127.0.0.1:1080", "use proxy")
}

func get_country(ipaddr string) string {

	addr, err := net.LookupIP(ipaddr)
	if err != nil {
		return "未知"
	}
	ip := addr[0]
	if ip == nil {
		return "未知"
	}
	record, err := geo2db.Country(ip)
	if err != nil {
		log.Fatal(err)
	}
	country := record.Country.Names["zh-CN"]
	if country == "" {
		country = "未知"
	}
	return country
}

/*
支持的解析URI格式:
ss://base64string@host:port/?plugin=xxx&obfs=xxx&obfs-host=xxx#备注信息
ss://base64string
ssr://server:server_port:protocol:method:obfs:base64-encode-password/?obfsparam=base64-encode-string&protoparam=base64-encode-string&remarks=base64-encode-string&group=base64-encode-string
vmess://base64string
其中，vmess的base64string内容为JSON配置格式： {"add":"server_ip","v":"2","ps":"name","port":158,"id":"683ec608-5af9-4f91-bd5b-ce493307fe56","aid":"0","net":"ws","type":"","host":"","path":"/path","tls":"tls"}

*/
// Decode decodes base64url string to byte array
func Decode(data string) (string, error) {
	data = strings.Replace(data, "-", "+", -1) // 62nd char of encoding
	data = strings.Replace(data, "_", "/", -1) // 63rd char of encoding

	switch len(data) % 4 { // Pad with trailing '='s
	case 0: // no padding
	case 2:
		data += "==" // 2 pad chars
	case 3:
		data += "=" // 1 pad char
	}
	result, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	return string(result), err
}

func decode_uri_ss(uri string) map[string]interface{} {
	// 解析 SS URI 信息
	// 格式一： # ss://base64string@host:port/?plugin=xxx&obfs=xxx&obfs-host=xxx#备注信息
	// 格式二： # ss://method:password@host:port
	// 格式三： # ss://base64string
	if uri[0:5] != "ss://" {
		//fmt.Println("ss link doesn't start with ss://.")
		return nil
	}
	result := make(map[string]interface{})
	result["type"] = "ss"
	real_uri := ""                   //最终URI格式 ss://method:password@host:port/?plugin=xxx&obfs=xxx&obfs-host=xxx#note
	user_info := ""                  //存储 method:password信息
	host_info := ""                  //存储地址后面信息
	if !strings.Contains(uri, "@") { // 格式三
		data, _ := Decode(uri[5:])
		tmp := strings.SplitN(data, "@", 2)
		user_info = tmp[0]
		host_info = tmp[1]
	} else { //格式一二
		b64str := strings.SplitN(uri[5:], "@", 2)
		user_info = b64str[0]
		host_info = b64str[1]
		if !strings.Contains(b64str[0], ":") {
			user2, _ := Decode(b64str[0])
			user_info = user2
		}
	}
	tmp := strings.SplitN(user_info, ":", 2)
	method, password := tmp[0], tmp[1]
	real_uri = "http://" + host_info
	//fmt.Println("user_info:", user_info, "host_info:", host_info, "real_uri:", real_uri)
	u, err := url.Parse(real_uri)
	if err != nil {
		log.Fatal(err)
	}
	result["server"] = u.Hostname()
	result["port"] = u.Port()
	result["password"] = password
	result["cipher"] = method
	port := result["port"]
	switch v := port.(type) {
	case string:
		result["port"], _ = strconv.ParseFloat(v, 8)
	default:
		result["port"] = port
	}
	q := u.Query()
	//fmt.Println("decode_result:", method, password, u.Hostname(), u.Port(), len(q))
	for k := range q {
		//fmt.Println(k, ":", q.Get(k))
		result[k] = q.Get(k)
	}
	return result
}

func decode_uri_ssr(uri string) map[string]interface{} {
	// 解析SSR
	// 格式一： ssr://server:server_port:protocol:method:obfs:base64-encode-password/?obfsparam=base64-encode-string&protoparam=base64-encode-string&remarks=base64-encode-string&group=base64-encode-string
	if uri[0:6] != "ssr://" {
		// fmt.Println("ssr link doesn't start with ssr://.")
		return nil
	}
	result := make(map[string]interface{})
	result["type"] = "ssr"
	b64str, _ := Decode(uri[6:])
	tmp := strings.SplitN(b64str, "/", 2)

	basic := strings.Split(tmp[0], ":")
	result["server"] = basic[0]
	result["port"] = basic[1]
	port := result["port"]
	switch v := port.(type) {
	case string:
		result["port"], _ = strconv.ParseFloat(v, 8)
	default:
		result["port"] = port
	}

	result["protocol"] = basic[2]
	result["cipher"] = basic[3]
	result["obfs"] = basic[4]
	result["password"], _ = Decode(basic[5])

	real_uri := "ssr://" + basic[0] + ":" + basic[1] + "/" + tmp[1]

	u1, _ := url.Parse(real_uri)
	q := u1.Query()

	switch {
	case q.Get("obfsparam") != "":
		result["obfs-param"], _ = Decode(q.Get("obfsparam"))
	case q.Get("obfs_param") != "":
		result["obfs-param"], _ = Decode(q.Get("obfs_param"))
	}
	switch {
	case q.Get("protoparam") != "":
		result["protocol-param"], _ = Decode(q.Get("protoparam"))
	case q.Get("protocol_param") != "":
		result["protocol-param"], _ = Decode(q.Get("protocol_param"))
	}
	return result
}

func decode_uri_vmess(vmess_uri string) map[string]interface{} {
	//解析VMess格式URI
	//格式: vmess://base64string
	// 其中，base64string内容为JSON配置格式：{"server": "server_ip", "server_port": 80, "uid": "3c24b6f3-69be-4128-bf61-d97f4443e1dc", "network": "ws", "path": "/path", "tls": ""}
	if vmess_uri[0:8] != "vmess://" {
		// fmt.Println("vmess uri doesn't start with vmess://")
	}
	tmp := make(map[string]interface{})
	result := make(map[string]interface{})
	result["type"] = "vmess"

	b64str, err := Decode(vmess_uri[8:])
	if err != nil {
		// fmt.Println(err)
		return nil
	}
	json.Unmarshal([]byte(b64str), &tmp)

	aid := tmp["aid"]
	switch v := aid.(type) {
	case string:
		result["alterId"], _ = strconv.ParseFloat(v, 8)
	default:
		result["alterId"] = aid
	}

	port := tmp["port"]
	switch v := port.(type) {
	case string:
		result["port"], _ = strconv.ParseFloat(v, 8)
	default:
		result["port"] = port
	}

	result["cipher"] = "auto"
	result["server"] = tmp["add"]
	result["uuid"] = tmp["id"]
	result["network"] = tmp["net"]
	if tmp["udp"] == nil || tmp["udp"] == "" || tmp["udp"] == "none" || tmp["udp"] == "false" {
		result["udp"] = false
	} else {
		result["udp"] = true
	}
	if tmp["net"] == "ws" {
		options := make(map[string]interface{})
		wsheaders := make(map[string]interface{})
		options["path"] = tmp["path"]

		if tmp["host"] != "" {
			wsheaders["Host"] = tmp["host"]
			options["headers"] = wsheaders
		}
		result["ws-opts"] = options
	} else if tmp["net"] == "h2" {
		options := make(map[string]interface{})
		wsheaders := make(map[string]interface{})
		options["path"] = tmp["path"]
		if tmp["host"] != "" {
			wsheaders["host"] = tmp["host"]
			options["host"] = wsheaders
		}
		result["h2-opts"] = options
	} else if tmp["net"] == "http" {
		options := make(map[string]interface{})
		wsheaders := make(map[string]interface{})
		options["path"] = tmp["path"]
		options["method"] = tmp["method"]
		if tmp["host"] != "" {
			wsheaders["host"] = tmp["host"]
			options["host"] = wsheaders
		}
		result["http-opts"] = options
	} else if tmp["net"] == "grpc" {
		options := make(map[string]interface{})
		options["grpc-service-name"] = tmp["grpc-service-name"]
		result["grpc-opts"] = options
	}

	if tmp["tls"] == "none" {
		result["tls"] = false
	} else {
		result["tls"] = true
	}
	return result
}

func print_ss(proxy map[string]interface{}) {
	if proxy == nil {
		return
	}
	fmt.Println("  - name: ", proxy["name"])
	fmt.Println("    type: ", proxy["type"])
	fmt.Println("    server: ", proxy["server"])
	fmt.Println("    port: ", proxy["port"])
	fmt.Println("    password: ", proxy["password"])
	fmt.Println("    cipher: ", proxy["cipher"])
	if proxy["plugin"] != nil {
		fmt.Println("    plugin: ", proxy["plugin"])
		fmt.Println("    mode: ", proxy["obfs"])
		fmt.Println("    host: ", proxy["obfs-host"])
	}
}

func print_vmess(proxy map[string]interface{}) {
	if proxy == nil {
		return
	}
	if proxy["network"] != nil && proxy["network"] == "http" {
		// 安全因素：不支持 http
		return
	}
	fmt.Println("  - name: ", proxy["name"])
	fmt.Println("    type: ", proxy["type"])
	fmt.Println("    server: ", proxy["server"])
	fmt.Println("    port: ", proxy["port"])
	fmt.Println("    uuid: ", proxy["uuid"])
	fmt.Println("    alterId: ", proxy["alterId"])
	fmt.Println("    cipher: ", proxy["cipher"])
	fmt.Println("    udp: ", proxy["udp"])
	fmt.Println("    tls: ", proxy["tls"])
	fmt.Println("    network: ", proxy["network"])
	if options, err := proxy["ws-opts"].(map[string]interface{}); err && options != nil {
		fmt.Println("    ws-opts:")
		fmt.Println("      path: ", options["path"])
		if headers, ok := options["headers"].(map[string]interface{}); ok {
			fmt.Println("      headers:")
			fmt.Println("        Host: ", headers["Host"])
		}
	} else if options, err := proxy["h2-opts"].(map[string]interface{}); err && options != nil {
		fmt.Println("    h2-opts:")
		fmt.Println("      path: ", options["path"])
		if headers, ok := options["headers"].(map[string]interface{}); ok {
			fmt.Println("      host:")
			fmt.Println("        - ", headers["host"])
		}
	} else if options, err := proxy["http-opts"].(map[string]interface{}); err && options != nil {
		fmt.Println("    http-opts:")
		if options["method"] != nil {
			fmt.Println("      method: ", options["method"])
		} else {
			fmt.Println("      method: ", "GET")
		}
		if options["path"] != nil {
			if headers, ok := options["path"].(map[string]interface{}); ok {
				fmt.Println("      path: ")
				fmt.Println("        - ", headers["path"])
			}
		}
	} else if options, err := proxy["grpc-opts"].(map[string]interface{}); err && options != nil {
		fmt.Println("    grpc-opts:")
		fmt.Println("      grpc-service-name: ", options["grpc-service-name"])
	}
}

func print_ssr(proxy map[string]interface{}) {
	if proxy == nil {
		return
	}
	fmt.Println("  - name: ", proxy["name"])
	fmt.Println("    type: ", proxy["type"])
	fmt.Println("    server: ", proxy["server"])
	fmt.Println("    port: ", proxy["port"])
	fmt.Println("    password: ", proxy["password"])
	fmt.Println("    cipher: ", proxy["cipher"])
	fmt.Println("    obfs: ", proxy["obfs"])
	fmt.Println("    protocol: ", proxy["protocol"])
	if proxy["obfs-param"] != nil {
		fmt.Println("    obfs-param: ", proxy["obfs-param"])
	}
	if proxy["protocol-param"] != nil {
		fmt.Println("    protocol-param: ", proxy["protocol-param"])
	}

}

func FormatPrintProxy(proxies []map[string]interface{}) {
	//Yaml格式化输出代理信息(为了保证字段输出顺序)
	fmt.Println("proxies:")
	for _, proxy := range proxies {
		switch proxy["type"] {
		case "ss":
			print_ss(proxy)
		case "ssr":
			print_ssr(proxy)
		case "vmess":
			print_vmess(proxy)
		default:
			return
		}
	}
}

// Decode decodes base64url string to byte array
func DecodeBase64(data string) (string, error) {
	data = strings.Replace(data, "-", "+", -1) // 62nd char of encoding
	data = strings.Replace(data, "_", "/", -1) // 63rd char of encoding

	switch len(data) % 4 { // Pad with trailing '='s
	case 0: // no padding
	case 2:
		data += "==" // 2 pad chars
	case 3:
		data += "=" // 1 pad char
	}
	result, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	return string(result), err
}

// 加载Yaml格式数据
func LoadYaml(data string) (m map[string]interface{}, err error) {
	err = yaml.Unmarshal([]byte(data), &m)
	return m, err
}

func DownloadUrl(myurl string) string {

	tr := &http.Transport{}
	if proxy_uri != "" {
		// 检测端口是否可访问
		if _, err1 := net.DialTimeout("tcp", proxy_uri, 3*time.Second); err1 == nil {

			// fmt.Println("DEBUG: proxy:", proxy_uri)
			// url.Parse 解析 proxy 字符串 返回一个 URL 结构体变量指针
			proxyURL, err := url.Parse(proxy_uri)
			if err != nil {
				panic(err)
			}
			// http.ProxyURL()调用proxyURL参数并返回一个proxy函数(给Transport的Proxy使用)
			tr.Proxy = http.ProxyURL(proxyURL)
		}
	}

	// 新建client,并初始化一个Transport配置信息，这样client的HTTP请求都会通过代理转发
	client := &http.Client{
		// checkRedirect: redirectPolicyFunc,
		Transport: tr,
	}

	request, err := http.NewRequest("GET", myurl, nil)
	if err != nil {
		panic(err)
	}

	resp, err := client.Do(request)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		// error
		panic(err)
	}
	return string(body)
}

// 解析HTTP(S)订阅源代理节点
func DecodeUrl(url string) error {
	url_content := DownloadUrl(url)
	uri_data, err := DecodeBase64(url_content)
	if err == nil {
		// Base64 解码成功
		DecodeUriList(uri_data)
	} else {
		yaml_data, err1 := LoadYaml(url_content)
		if err1 == nil {
			// Yaml格式加载成功,判断是否有 proxies 信息
			proxies_data, proxies_exist := yaml_data["proxies"]
			if proxies_exist {
				// 存在 proxies 节点信息
				for _, v := range proxies_data.([]interface{}) {
					proxy_list = append(proxy_list, v.(map[string]interface{}))
				}
				return nil
			}
		}
		// 非 Base64 编码数据,直接保存内容
		DecodeUriList(url_content)
	}
	return nil
}

// 解析proxy_uri列表数据
func DecodeUriList(uris string) {

	uri_array := strings.Fields(uris)
	var result map[string]interface{}

	for _, k := range uri_array {
		// fmt.Println("DEBUG:k=", k)
		if len(k) < 5 {
			continue
		}
		switch v := k[0:5]; v {
		case "ss://":
			result = decode_uri_ss(k)
		case "ssr:/":
			result = decode_uri_ssr(k)
		case "vmess":
			result = decode_uri_vmess(k)
		case "http:":
			DecodeUrl(k)
			continue
		case "https":
			DecodeUrl(k)
			continue
		default:
			// 无效链接信息
			continue
		}
		ipaddr := fmt.Sprintf("%v", result["server"])
		port := fmt.Sprintf("%v", result["port"])
		stype := fmt.Sprintf("%v", result["type"])
		result["name"] = get_country(ipaddr) + "_" + stype + "_" + ipaddr + ":" + port
		proxy_name_list = append(proxy_name_list, result["name"])
		proxy_list = append(proxy_list, result)
	}
}

// 支持解析 http(s)订阅地址/ss/ssr/vmess等格式
func StartDecode(data string) {
	proxy_data, err := DecodeBase64(data)
	if err != nil {
		panic(err)
	}
	DecodeUriList(proxy_data)

}

func decode_file(file string) {
	// decode proxy node from input file
	content, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}
	var decode_content string

	temp_content, err := base64.StdEncoding.DecodeString(string(content))
	if err != nil {
		//  base64 decode error
		decode_content = string(content)
	} else {
		decode_content = string(temp_content)
	}
	// decode as multiple uri
	decode_uri(decode_content)
}

func decode_uri(uris string) {

	uri_array := strings.Fields(uris)
	var result map[string]interface{}

	// test_node := "ss://YWVzLTI1Ni1nY206VGhpcyBpcyBhIFRlc3RAMTI3LjAuMC4xOjEwMDg2"
	// result = decode_uri_ss(test_node)
	// result["name"] = "test"
	// proxy_name_list = append(proxy_name_list, result["name"])
	// proxy_list = append(proxy_list, result)
	for _, k := range uri_array {
		switch v := k[0:5]; v {
		case "ss://":
			result = decode_uri_ss(k)
		case "ssr:/":
			result = decode_uri_ssr(k)
		case "vmess":
			result = decode_uri_vmess(k)
		}

		ipaddr := fmt.Sprintf("%v", result["server"])
		port := fmt.Sprintf("%v", result["port"])
		stype := fmt.Sprintf("%v", result["type"])
		result["name"] = get_country(ipaddr) + "_" + stype + "_" + ipaddr + ":" + port
		proxy_name_list = append(proxy_name_list, result["name"])
		proxy_list = append(proxy_list, result)
	}
	FormatPrintProxy(proxy_list)
}

func main() {
	flag.Parse()

	db, err := geoip2.Open(db_path)
	if err != nil {
		log.Fatal(err)
	}
	geo2db = db
	defer geo2db.Close()

	if ifile != "" {
		decode_file(ifile)
	} else if uri_list != "" {
		StartDecode(uri_list)
		FormatPrintProxy(proxy_list)
	} else {
		log.Fatal("no -uri and ifile is given!")
	}
}
