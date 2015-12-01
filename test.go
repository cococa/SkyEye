package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	// "net/url"
	"crypto/md5"
	// "encoding/hex"
	// "strconv"
	"encoding/hex"
	"strings"
	// "unsafe"
)

//  http://help.aliyun.com/document_detail/sls/api/errors.html

func httpGet() {

	RequestMethod := "GET"

	client := &http.Client{}
	// http://cn-hangzhou.sls.aliyuncs.com
	req, err := http.NewRequest(RequestMethod, "http://log-monitor.cn-hangzhou.sls.aliyuncs.com/logstores", strings.NewReader("name=cjb"))
	if err != nil {
		// handle error
	}
	assID := "L5ASLE8ue7wTNBxc"

	VERB := RequestMethod
	CONTENT_MD5 := ""
	CONTENT_TYPE := "application/x-protobuf"
	DATE := "Tue, 01 Dec 2015 03:58:50 GMT"                                                                    //Mon, 3 Jan 2010 08:33:47 GMT
	CanonicalizedSLSHeaders := "x-sls-apiversion:0.4.0\nx-sls-bodyrawsize:50\nx-sls-signaturemethod:hmac-sha1" //x-sls-apiversion:0.4.0\nx-sls-bodyrawsize:50\nx-sls-signaturemethod:hmac-sha1
	CanonicalizedResource := "/logstores/log-monitor"                                                          ///logstores/app_log

	SignString := VERB + "\n" + CONTENT_MD5 + "\n" + CONTENT_TYPE + "\n" + DATE + "\n" + CanonicalizedSLSHeaders + "\n" + CanonicalizedResource

	md5Ctx := md5.New()
	md5Ctx.Write([]byte(SignString))
	cipherStr := md5Ctx.Sum(nil)
	xx := hex.EncodeToString(cipherStr)
	fmt.Print(xx)

	yy := "SLS " + assID + ":" + xx

	req.Header.Set("Authorization", yy) //签名内容
	req.Header.Set("Content-Length", "0")
	req.Header.Set("Content-MD5", "")
	req.Header.Set("Content-Type", "application/x-protobuf") //RFC 2616中定义得HTTP请求Body类型。目前SLS API请求只支持application/x-protobuf。如果没有Body部分，则不需要提供该请求头。
	req.Header.Set("Date", DATE)
	req.Header.Set("Host", "log-monitor.cn-hangzhou.sls.aliyuncs.com")
	req.Header.Set("x-sls-apiversion", "0.4.0")
	req.Header.Set("x-sls-bodyrawsize", "50")
	// req.Header.Set("x-sls-compresstype", "111")
	// req.Header.Set("x-sls-date", DATE)
	req.Header.Set("x-sls-signaturemethod", "hmac-sha1") //签名计算方式，目前仅支持”hmac-sha1”。

	resp, err := client.Do(req)

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		// handle error
	}

	fmt.Println(string(body))
}

// func B2S(buf []byte) string {
// 	return *(*string)(unsafe.Pointer(&buf))
// }

func main() {
	httpGet()
}
