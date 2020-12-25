package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"github.com/dukeofdisaster/elastic-go/lib/models/elasticinternals"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func checkErr(e error) {
	if e != nil {
		panic(e)
	}
}

func contains(s []string, str string) bool {
	for i := range s {
		if s[i] == str {
			return true
		}
	}
	return false
}

// Config for this program
type Config struct {
	Log     Log
	Task    Task
	Cluster Cluster
}

// Log contains a path where ndjson will be written
type Log struct {
	Path string `yaml:"path"`
}

// Task contains min and ignored list needed for logic
type Task struct {
	Minimum string   `yaml:"minimum"`
	Ignored []string `yaml:"ignored"`
}

// Cluster contains meta about the cluster including creds, whether creds are
// encrypted in the config, path to a an RSA key, and url to the cluster
type Cluster struct {
	User           string `yaml:"user"`
	Password       string `yaml:"password"`
	EncryptedCreds bool   `yaml:"encrypted_creds"`
	KeyPath        string `yaml:"keypath"`
	Auth           bool   `yaml:"auth"`
	URL            string `yaml:"url"`
}

type loggableTask struct {
	Action       string  `json:"action"`
	IP           string  `json:"ip"`
	Node         string  `json:"node"`
	ParentTaskID string  `json:"parent_task_id"`
	RunningTime  string  `json:"running_time"`
	StartTime    string  `json:"start_time"`
	TaskID       string  `json:"task_id"`
	Timestamp    string  `json:"timestamp"`
	Type         string  `json:"type"`
	DurationSec  float64 `json:"duration_sec"`
}

func getRunningTimeUnits(time string) string {
	if strings.Contains(time, "micros") {
		return "micros"
	} else if strings.Contains(time, "ms") {
		return "ms"
	} else if strings.HasSuffix(time, "s") {
		return "s"
	} else if strings.HasSuffix(time, "m") {
		return "m"
	} else if strings.HasSuffix(time, "h") {
		return "h"
	} else {
		return "d"
	}
}

func showUnits(time string, units string) {
	switch units {
	case "micros":
		fmt.Println("MICROS:", time[:len(time)-6])
	case "ms":
		fmt.Println("MILLIS:", time[:len(time)-2])
	case "s":
		fmt.Println("SECONDS:", time[:len(time)-1])
	case "m":
		fmt.Println("MINUTES:", time[:len(time)-1])
	case "h":
		fmt.Println("HOURS:", time[:len(time)-1])
	case "d":
		fmt.Println("DAYS:", time[:len(time)-1])
	}
}

func getUsername() string {
	var tryAgain = true
	var user string
	for tryAgain {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("ENTER USERNAME: ")
		username, _ := reader.ReadString('\n')
		username = strings.TrimSpace(username)
		fmt.Print("CONFIRM USERNAME: ")
		userConfirm, _ := reader.ReadString('\n')
		userConfirm = strings.TrimSpace(userConfirm)
		if username == userConfirm {
			user = username
			tryAgain = false
		} else {
			fmt.Println("usernames did not match ...")
		}

	}
	return user
}

func getPassword() string {
	var tryAgain = true
	var pass string
	for tryAgain {
		fmt.Print("PASSWORD: ")
		password, _ := terminal.ReadPassword(int(syscall.Stdin))
		fmt.Print("\n")
		fmt.Print("CONFIRM PASSWORD: ")
		passConfirm, _ := terminal.ReadPassword(0)
		if string(password) == string(passConfirm) {
			tryAgain = false
			pass = string(password)
		} else {
			fmt.Println("! Passwords do not match")
		}
	}
	fmt.Println()
	return pass
}

func getGeneric(entry string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("ENTER %v: ", entry)
	configVal, _ := reader.ReadString('\n')
	configVal = strings.TrimSpace(configVal)
	return configVal
}
func genConfig() {
	user := getUsername()
	pass := getPassword()
	clusterURL := getGeneric("CLUSTER URL")
	minDuration := getGeneric("MINIMU TASK DURATION")
	cryptUser, cryptPass, keyHash := cryptCredsWithNewKey(user, pass)
	keyFilename := fmt.Sprintf("%s.key", keyHash)
	conf := getConfigString(cryptUser, cryptPass, true, keyFilename, true, clusterURL, minDuration)
	dumpBytesToFile("taskwatcher.yaml", []byte(conf))
	fmt.Println("Writing config to: taskwatcher.yaml\n====")
	fmt.Println(conf)

}

// dump yaml config from given vars; uses a default logpath
func getConfigString(u string, p string, e bool, k string, auth bool, url string, min string) string {
	c := Config{
		Log{Path: "/var/log/taskwatcher.log"},
		Task{Minimum: min, Ignored: []string{"ex1", "ex2"}},
		Cluster{User: u, Password: p, EncryptedCreds: e, KeyPath: k, Auth: auth, URL: url},
	}
	confBytes, err := yaml.Marshal(&c)
	checkErr(err)
	return string(confBytes)
}

func dumpBytesToFile(filename string, data []byte) {
	// mainly used to dump priv key, should be rw only by owner
	err := ioutil.WriteFile(filename, data, 0600)
	checkErr(err)
}
func exportPrivKeyPem(priv *rsa.PrivateKey) string {
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	privPem := pem.EncodeToMemory(
		&pem.Block{
			Type:    "RSA PRIVATE KEY",
			Bytes:   privBytes,
			Headers: nil,
		},
	)
	return string(privPem)
}

func getPrivateFromPemBytes(priv []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(priv)
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	checkErr(err)
	return privKey, nil
}

func getSHA256Sum(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func getConfigFromFile(path string) Config {
	confData, err := ioutil.ReadFile(path)
	checkErr(err)
	newConf := Config{}
	err = yaml.Unmarshal(confData, &newConf)
	checkErr(err)
	return newConf
}
func readBytes(path string) []byte {
	data, err := ioutil.ReadFile(path)
	checkErr(err)
	return data
}

func decryptCredsFromConfig(c Config) (string, string, error) {
	if c.Cluster.User == "" {
		return "", "", errors.New("empty/nil user in config,can not decrypt this")
	} else if c.Cluster.Password == "" {
		return "", "", errors.New("empty/nil password; can not decrypt this")
	} else if c.Cluster.KeyPath == "" {
		return "", "", errors.New("empty/nil key path; can not find key")
	}
	privBytes, err := ioutil.ReadFile(c.Cluster.KeyPath)
	if err != nil {
		return "", "", err
	}
	privKey, err := getPrivateFromPemBytes(privBytes)
	if err != nil {
		return "", "", err
	}
	userBytes, err := b64.StdEncoding.DecodeString(c.Cluster.User)
	if err != nil {
		return "", "", err
	}
	passBytes, err := b64.StdEncoding.DecodeString(c.Cluster.Password)
	plainUser, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, userBytes, nil)
	if err != nil {
		return "", "", err
	}
	plainPass, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, passBytes, nil)
	if err != nil {
		return "", "", err
	}
	return string(plainUser), string(plainPass), nil
}

// This looks kinda messyy; should probably have separate dump function
func cryptCredsWithNewKey(user string, pass string) (string, string, string) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	checkErr(err)
	publicKey := privKey.PublicKey

	cryptedUser, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &publicKey, []byte(user), nil)
	checkErr(err)
	userEncoded := b64.StdEncoding.EncodeToString(cryptedUser)

	cryptedPass, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &publicKey, []byte(pass), nil)
	checkErr(err)
	passEncoded := b64.StdEncoding.EncodeToString(cryptedPass)

	writeablePrivKey := exportPrivKeyPem(privKey)
	pemHash := getSHA256Sum([]byte(writeablePrivKey))
	keyFilename := fmt.Sprintf("%s.key", pemHash)
	dumpBytesToFile(keyFilename, []byte(writeablePrivKey))
	dumpBytesToFile("crypted-pass.crypted", []byte(cryptedPass))
	dumpBytesToFile("encoded-pass.b64", []byte(passEncoded))
	fmt.Println("CRYPT USER:", userEncoded)
	fmt.Println("CRYPTED PASS:", passEncoded)
	fmt.Println("RSA KEY - SAVE YOUR PRIV KEY SOMEWHERE\n===")
	fmt.Println(writeablePrivKey)
	fmt.Println("====")
	fmt.Println("Dumped key:", keyFilename)
	fmt.Println("Key SHA256:", pemHash)
	fmt.Println("Dumped crypted and encoded pass: crypted-pass.crypted, encoded-pass.b64")
	fmt.Println("test: cat crypted-pass.crypted | openssl pkeyutl -decrypt -inkey 202012xxx.key -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 > decrypted-pass.txt")
	return userEncoded, passEncoded, pemHash

}

func handleBadResponse(resp *http.Response) {
	fmt.Printf("NON 200 SATUS from api: %v\n", resp.StatusCode)
	body, err := ioutil.ReadAll(resp.Body)
	checkErr(err)
	resp.Body.Close()
	fmt.Println(string(body))
}

func getTasksFromResponse(resp *http.Response) *[]elasticinternals.CatTaskItem {
	tasks := new([]elasticinternals.CatTaskItem)
	body, err := ioutil.ReadAll(resp.Body)
	checkErr(err)
	err = json.Unmarshal(body, &tasks)
	checkErr(err)
	return tasks
}

// given a running time string i.e. 3micros 3.4ms 3d 4h, convert to
// seconds
func getSecondsFromRunningTime(r string) float64 {
	units := getRunningTimeUnits(r)
	var output float64
	switch units {
	case "micros":
		i, e := strconv.ParseFloat(r[:len(r)-6], 64)
		checkErr(e)
		secs := i / 1000000.0
		output = secs
	case "ms":
		i, e := strconv.ParseFloat(r[:len(r)-2], 64)
		checkErr(e)
		secs := i / 1000.0
		output = secs
	case "s":
		i, e := strconv.ParseFloat(r[:len(r)-1], 64)
		checkErr(e)
		output = i
	case "m":
		i, e := strconv.ParseFloat(r[:len(r)-1], 64)
		checkErr(e)
		secs := i * 60.0
		output = secs
	case "h":
		i, e := strconv.ParseFloat(r[:len(r)-1], 64)
		checkErr(e)
		secs := i * 60 * 60
		output = secs
	case "d":
		i, e := strconv.ParseFloat(r[:len(r)-1], 64)
		checkErr(e)
		secs := i * 60 * 60 * 24
		output = secs
	}
	return output
}

func appendToLog(entry string, path string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	checkErr(err)
	defer f.Close()
	_, err = f.WriteString(entry + "\n")
	checkErr(err)
}

// returns json string that includes seconds for math in elastic
func getLoggableTaskString(task elasticinternals.CatTaskItem) string {
	var withsecs loggableTask
	dumpedBytes, err := json.Marshal(task)
	checkErr(err)
	err = json.Unmarshal(dumpedBytes, &withsecs)
	withsecs.DurationSec = getSecondsFromRunningTime(task.RunningTime)
	logBytes, err := json.Marshal(withsecs)
	checkErr(err)
	return string(logBytes)
}

func getTasksWithCryptedCreds(conf Config) *http.Response {
	user, pass, err := decryptCredsFromConfig(conf)
	checkErr(err)
	api := fmt.Sprintf("%s/_cat/tasks?format=json", conf.Cluster.URL)
	req, err := http.NewRequest("GET", api, nil)
	req.SetBasicAuth(user, pass)
	client := &http.Client{}
	resp, err := client.Do(req)
	checkErr(err)
	return resp
}

func extractThresholdTasks(list []elasticinternals.CatTaskItem, conf Config) []elasticinternals.CatTaskItem {
	var extracted = new([]elasticinternals.CatTaskItem)
	for i := range list {
		runtime := list[i].RunningTime
		secs := getSecondsFromRunningTime(runtime)
		threshold := getSecondsFromRunningTime(conf.Task.Minimum)
		if secs >= threshold && !contains(conf.Task.Ignored, list[i].TaskID) {
			*extracted = append(*extracted, list[i])
		}
	}
	return *extracted
}

func logThresholdTasks(list []elasticinternals.CatTaskItem, path string) {
	for i := range list {
		logString := getLoggableTaskString(list[i])
		appendToLog(logString, path)
	}
}

func main() {
	genPtr := flag.Bool("g", false, "read input from user to generate config options")
	confPtr := flag.String("c", "", "path to config file")
	flag.Parse()
	if *genPtr {
		genConfig()
		os.Exit(0)

	} else if *confPtr != "" {
		config := getConfigFromFile(*confPtr)
		if config.Cluster.EncryptedCreds {
			resp := getTasksWithCryptedCreds(config)
			if resp.StatusCode != 200 {
				handleBadResponse(resp)
				os.Exit(1)
			}
			defer resp.Body.Close()
			tasks := getTasksFromResponse(resp)
			thresholdTasks := extractThresholdTasks(*tasks, config)
			fmt.Println("TASKS > THRESHOLD:", len(thresholdTasks))
			logThresholdTasks(thresholdTasks, config.Log.Path)
			os.Exit(0)

		} else if !config.Cluster.EncryptedCreds && config.Cluster.Auth {
			fmt.Println("Avoid using plaintext creds in configs...")
			// do basic auth
		}
	} else if len(os.Args) == 1 {
		fmt.Println("main w/out args not implemented yet")
		os.Exit(0)
	}
}
