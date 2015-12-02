package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
	// "net/url"
	// "crypto/md5"
	// "encoding/hex"
	// "strconv"
	// "unsafe"
	// "io"
)

const (
	base64Table = "123QRSTUabcdVWXYZHijKLAWDCABDstEFGuvwxyzGHIJklmnopqr234560178912"
	assID       = "L5ASLE8ue7wTNBxc"
	accessKey   = "Y5Axn5jAZxPCTFY1sXwZcDxx6g3SqS"
)

//  http://help.aliyun.com/document_detail/sls/api/errors.html

func httpGet() {

	fmt.Println(getDateTime())

	RequestMethod := "GET"

	client := &http.Client{}
	// http://cn-hangzhou.sls.aliyuncs.com
	req, err := http.NewRequest(RequestMethod, "http://log-monitor.cn-hangzhou.sls.aliyuncs.com/logstores", strings.NewReader("name=cjb"))
	if err != nil {
		// handle error
	}

	VERB := RequestMethod
	CONTENT_MD5 := ""
	CONTENT_TYPE := ""                                                                                        //"application/x-protobuf"
	DATE := getDateTime()                                                                                     //Mon, 3 Jan 2010 08:33:47 GMT
	CanonicalizedSLSHeaders := "x-sls-apiversion:0.4.0\nx-sls-bodyrawsize:0\nx-sls-signaturemethod:hmac-sha1" //x-sls-apiversion:0.4.0\nx-sls-bodyrawsize:50\nx-sls-signaturemethod:hmac-sha1
	CanonicalizedResource := "/logstores"                                                                     ///log-monitor                                              ///logstores/app_log

	SignString := VERB + "\n" + CONTENT_MD5 + "\n" + CONTENT_TYPE + "\n" + DATE + "\n" + CanonicalizedSLSHeaders + "\n" + CanonicalizedResource
	fmt.Println(SignString)

	// fmt.Println(SignString)
	// md5Ctx := md5.New()
	// md5Ctx.Write([]byte(SignString))
	// cipherStr := md5Ctx.Sum(nil)
	// xx := sha1(SignString, accessKey)
	mkey := []byte(accessKey)
	mac := hmac.New(sha1.New, mkey)
	mac.Write([]byte(SignString))
	xx := hex.EncodeToString(mac.Sum(nil))

	fmt.Println(xx)

	// aaa := base64Encode([]byte(xx))
	// xxx := hex.EncodeToString(aaa)

	// fmt.Println(xxx)

	sssss := base64.StdEncoding.EncodeToString([]byte(xx))
	fmt.Println(sssss)

	yy := "SLS " + assID + ":" + sssss

	fmt.Println(yy)

	req.Header.Set("Authorization", yy) //签名内容
	// req.Header.Set("Content-Length", "0")
	req.Header.Set("Content-MD5", "")
	req.Header.Set("Content-Type", "") //RFC 2616中定义得HTTP请求Body类型。目前SLS API请求只支持application/x-protobuf。如果没有Body部分，则不需要提供该请求头。
	req.Header.Set("Date", DATE)
	req.Header.Set("Host", "log-monitor.cn-hangzhou.sls.aliyuncs.com")
	req.Header.Set("x-sls-apiversion", "0.4.0")
	req.Header.Set("x-sls-bodyrawsize", "0")
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

// func sha1(s string, key string) string {
// 	mkey := []byte(key)
// 	mac := hmac.New(sha1.New, mkey)
// 	mac.Write([]byte(s))
// 	return hex.EncodeToString(mac.Sum(nil))

// }

func base64Encode(src []byte) []byte {
	var coder = base64.NewEncoding(base64Table)
	return []byte(coder.EncodeToString(src))
}

// func B2S(buf []byte) string {
// 	return *(*string)(unsafe.Pointer(&buf))
// }

/**
*  %a, %d %b %Y %H:%M:%S GMT
*  Mon, 3 Jan 2010 08:33:47 GMT
 */
func getDateTime() string {
	// time.Now().Format("2006-01-02 15:04:05")
	return time.Now().UTC().Format("Mon, 2 Jan 2006 03:04:05 GMT")
}

func main() {
	httpGet()
}
