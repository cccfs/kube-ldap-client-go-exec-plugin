package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var url string

const TimeJsISOFormat = "2006-01-02T15:04:05.999Z07:00" //https://www.dazhuanlan.com/2019/08/23/5d5ee4ae8f39f/

type H map[string]interface{}

func main()  {
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		Help()
	}
	url = args[0]

	cacheFile := cachePath()
	if _, err := os.Stat(cacheFile); errors.Is(err, os.ErrNotExist) {
		os.Create(cacheFile)
		username, password := credentials()
		result := auth(username, password)
		ioutil.WriteFile(cacheFile, []byte(result), 0777)
	} else {
		jsonByte, _ := ioutil.ReadFile(cacheFile)
		jsonStr := string(jsonByte)
		var parseJsonResult map[string]map[string]string
		json.Unmarshal(jsonByte, &parseJsonResult)

		var statusMap map[string]string
		statusMap = parseJsonResult["status"]
		exp := statusMap["expirationTimestamp"]
		nowTime := time.Now().Format(TimeJsISOFormat)
		if exp > nowTime {
			fmt.Println(jsonStr)
			os.Exit(0)
		} else {
			username, password := credentials()
			result := auth(username, password)
			ioutil.WriteFile(cacheFile, []byte(result), 0777)
			fmt.Println(result)
		}
	}

}


func credentials() (string, string) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Fprintf(os.Stderr, "Username: ")
	username, _ := reader.ReadString('\n')

	fmt.Fprintf(os.Stderr, "Password: ")

	bytePassword, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		log.Fatal(err)
	}

	password := string(bytePassword)

	//password, _ := reader.ReadString('\n')
	return strings.TrimSpace(username), strings.TrimSpace(password)
}

var cachePath = func() string {
	userHomeDir, _ := os.UserHomeDir()
	path := filepath.Join(userHomeDir, ".kube", "cache")
	os.MkdirAll(path, 0777)
	file := filepath.Join(path, "kube-ldap-token.yaml")
	return file
}


func Help()  {
	fmt.Fprintf(os.Stderr, "Usage: %s KUBE-LDAP_URL \n " +
		"e.g https://kube-ldap-webhook.example.com \n", os.Args[0])
	os.Exit(1)
}

func auth(username, password string) string {
	client := &http.Client{}
	req, err := http.NewRequest("GET", url + "/auth", nil)
	if err != nil {
		fmt.Println("Url address error, e.g: https://xxx")
		os.Exit(1)
	}
	req.SetBasicAuth(username, password)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Login failed")
	}
	bodyText, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	token := string(bodyText)
	code := resp.StatusCode
	var result string
	if code != 200 {
		result = parseUnauthenticatedResponse(code)
	} else {
		decodedToken, _ := jwt.Parse(token, nil)
		claims, _ := decodedToken.Claims.(jwt.MapClaims)

		var parseExpTime time.Time
		switch exp := claims["exp"].(type) {
		case float64:
			parseExpTime = time.Unix(int64(exp), 0)
		case json.Number:
			v, _ := exp.Int64()
			parseExpTime = time.Unix(v, 0)
		}
		exp := parseExpTime.Format(TimeJsISOFormat)
		result = parseAuthenticatedResponse(token, exp)
	}
	time.Sleep(100 * time.Millisecond)
	return result
}

func parseAuthenticatedResponse(token, exp string) string  {
	var authenticatedTemplate = H{
		"apiVersion": "client.authentication.k8s.io/v1beta1",
		"kind": "ExecCredential",
		"status": H{
			"token": token,
			"expirationTimestamp": exp,
		},
	}
	authenticatedResponse, err := json.MarshalIndent(authenticatedTemplate, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	return string(authenticatedResponse)
}

func parseUnauthenticatedResponse(code int) string {
	unauthenticatedTemplate := H{
		"apiVersion": "client.authentication.k8s.io/v1beta1",
		"kind": "ExecCredential",
		"spec": H{
			"response": H{
				"code": code,
			},
		},
		"interactive": true,
	}
	unauthenticatedResponse, err := json.MarshalIndent(unauthenticatedTemplate, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	return string(unauthenticatedResponse)
}

