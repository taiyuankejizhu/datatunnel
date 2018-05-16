package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"os"
    "encoding/json"
    "log"
    "net/http"
    "strings"
)

type AuthTokenMap struct {
    Authtoken string `json:"authtoken"`
    Port  string `json:"port"`
}

func index(w http.ResponseWriter, r *http.Request) {
    r.ParseForm()
    fmt.Println("Form: ", r.Form)
    fmt.Println("Path: ", r.URL.Path)
    fmt.Fprint(w, "Hello World !")
}

func GetPortByAuthtoken(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	fmt.Println(r.Form["AuthToken"])

    var authtokenmap AuthTokenMap
	authtokenmap.Authtoken = strings.Join(r.Form["AuthToken"], "")

	// AES-128。key length：16, 24, 32 bytes for AES-128, AES-192, AES-256
	key := []byte("kyz023f_9fd&yhfl")

	result2, err := base64.StdEncoding.DecodeString(authtokenmap.Authtoken)
	if err != nil {
		panic(err)
	}
	origData, err := AesDecrypt(result2, key)
	if err != nil {
		panic(err)
	}
	//fmt.Println(string(origData))
	authtokenmap.Port = string(origData)

	fmt.Println(authtokenmap)
	ret, _ := json.Marshal(authtokenmap)
	fmt.Fprint(w, string(ret))
}

func main() {

	arg_num := len(os.Args)
	if arg_num < 2 {
		fmt.Println("Start in server mode!")
    	http.HandleFunc("/", index)
    	http.HandleFunc("/api/GetPortByAuthtoken", GetPortByAuthtoken)

    	if err := http.ListenAndServe("0.0.0.0:8080", nil); err != nil {
        	log.Fatal("ListenAndServer: ", err)
    	}
	} else {

		// AES-128。key length：16, 24, 32 bytes for AES-128, AES-192, AES-256
		key := []byte("kyz023f_9fd&yhfl")
		result, err := AesEncrypt([]byte(os.Args[1]), key)
		if err != nil {
			panic(err)
		}
		authtoken := base64.StdEncoding.EncodeToString(result)
		fmt.Println(authtoken)

		line := []byte(authtoken + "\n")
		file, _:=os.OpenFile("./authtokens.txt",os.O_RDWR|os.O_CREATE|os.O_APPEND,0644)  
		file.Write(line)
		file.Close()

		result1, err := base64.StdEncoding.DecodeString(authtoken)
		if err != nil {
			panic(err)
		}
		origData, err := AesDecrypt(result1, key)
		if err != nil {
			panic(err)
		}
		fmt.Println(string(origData))
	}
}

func AesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = PKCS5Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func AesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}