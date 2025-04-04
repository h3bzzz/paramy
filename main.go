package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
)

type Config struct {
	Domain          string
	DomainsFile     string
	OutputDir       string
	Placeholder     string
	Threads         int
	Timeout         int
	Proxy           string
	Verbose         bool
	Stream          bool
	ParamWordlist   string
	BruteForce      bool
	BruteDepth      int
	ReflectionCheck bool
	IgnoreExts      []string
	Sources         []string
}

type Result struct {
	URL        string   `json:"url"`
	Parameters []string `json:"parameters"`
	Reflective []string `json:"reflective"`
	Source     string   `json:"source"`
}

var (
	config     Config
	userAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
	}
	yellow               = color.New(color.FgYellow).SprintFunc()
	green                = color.New(color.FgGreen).SprintFunc()
	cyan                 = color.New(color.FgCyan).SprintFunc()
	red                  = color.New(color.FgRed).SprintFunc()
	results              []Result
	resultMu             sync.Mutex
	httpClient           *http.Client
	defaultParamWordlist = `id
page
q
search
query
user
username
pass
password
token
session
lang
ref
referrer
redirect
url
target
dest
destination
sort
order
limit
offset
filter
category
type
mode
action
callback
format
debug
trace
source
index
key
api_key
client
client_id
secret
hash
nonce
code
state
scope
ip
addr
cid
aid
pid
uid
gid
lid
mid
fid
bid
tid
did
eid
v
version
langid
country
region
city
zipcode
postal
phone
email
address
street
company
name
fname
lname
nickname
dob
birthdate
gender
age
status
active
enabled
disabled
flag
level
score
rank
role
permission
access
auth
login
logout
session_id
device
browser
os
platform
resolution
color_depth
timezone
lat
lon
latitude
longitude
alt
altitude
accuracy
bearing
speed
distance
duration
time
timestamp
date
year
month
day
hour
minute
second
ms
code_id
order_id
invoice
transaction
amount
price
cost
total
balance
currency
symbol
rate
percent
percentage
discount
tax
fee
charge
note
comment
description
detail
info
data
meta
version_id
revision
update
new
old
current
previous
next
first
last
item
number
count
quantity
size
length
width
height
depth
weight
mass
volume
color_code
hex
rgb
rgba
hsl
css
html
xml
json
yaml
csv
txt
file
image
picture
photo
video
media
audio
document
report
log
error
warning
info_msg
debug_msg
trace_msg
config
setting
option
parameter`
)

func validParamName(param string) bool {
	match, _ := regexp.MatchString(`^[A-Za-z_][A-Za-z0-9_-]*$`, param)
	return match
}

func main() {
	banner := `
    _____
    |  __ \
    | |__) |_ _ _ __ __ _ _ __ ___  _   _
    |  ___/ _| | '__/ _| | '_ ` + "`" + ` _ \| | | |
    | |  | (_| | | | (_| | | | | | | |_| |
    |_|   \__,_|_|  \__,_|_| |_| |_|\__, |
                                     __/ |
                                    |___/
                                    by h3bzzz
`
	fmt.Println(yellow(banner))
	flag.StringVar(&config.Domain, "d", "", "Domain to scan for parameters")
	flag.StringVar(&config.DomainsFile, "l", "", "File containing list of domains")
	flag.StringVar(&config.OutputDir, "o", "results", "Output directory for results")
	flag.StringVar(&config.Placeholder, "p", "FUZZ", "Placeholder for parameter values")
	flag.IntVar(&config.Threads, "t", 10, "Number of concurrent threads")
	flag.IntVar(&config.Timeout, "timeout", 30, "HTTP request timeout in seconds")
	flag.StringVar(&config.Proxy, "proxy", "", "Proxy URL (e.g., http://127.0.0.1:8080)")
	flag.BoolVar(&config.Verbose, "v", false, "Verbose output")
	flag.BoolVar(&config.Stream, "s", false, "Stream results to terminal")
	flag.StringVar(&config.ParamWordlist, "w", "", "Parameter wordlist for brute forcing")
	flag.BoolVar(&config.BruteForce, "b", false, "Enable parameter brute forcing")
	flag.IntVar(&config.BruteDepth, "depth", 1, "Brute force crawl depth")
	flag.BoolVar(&config.ReflectionCheck, "r", false, "Check for parameter reflection")
	flag.Parse()
	if config.Domain == "" && config.DomainsFile == "" {
		fmt.Println(red("Error: Please provide either a domain (-d) or a list of domains (-l)"))
		flag.Usage()
		os.Exit(1)
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:    100,
		IdleConnTimeout: 90 * time.Second,
	}
	httpClient = &http.Client{
		Transport: transport,
		Timeout:   time.Duration(config.Timeout) * time.Second,
	}
	if err := os.MkdirAll(config.OutputDir, 0o755); err != nil {
		fmt.Println(red("Error creating output directory:"), err)
		os.Exit(1)
	}
	var domains []string
	var err error
	if config.Domain != "" {
		domains = []string{config.Domain}
	} else {
		domains, err = loadDomainsFromFile(config.DomainsFile)
		if err != nil {
			fmt.Println(red("Error loading domains:"), err)
			os.Exit(1)
		}
	}
	for _, domain := range domains {
		domain = cleanDomain(domain)
		fmt.Printf("%s Processing domain: %s\n", yellow("[INFO]"), cyan(domain))
		urlChan := make(chan string, config.Threads)
		progressChan := make(chan int, 100)
		bar := progressbar.NewOptions(-1, progressbar.OptionSetDescription("Processing URLs"), progressbar.OptionShowCount())
		go func() {
			for n := range progressChan {
				bar.Add(n)
			}
		}()
		var wg sync.WaitGroup
		for i := 0; i < config.Threads; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for urlStr := range urlChan {
					processURL(urlStr, domain)
					progressChan <- 1
				}
			}()
		}
		for _, source := range config.Sources {
			switch source {
			case "wayback":
				fetchWaybackURLs(domain, urlChan)
				time.Sleep(500 * time.Millisecond)
			case "commoncrawl":
				fetchCommonCrawlURLs(domain, urlChan)
				time.Sleep(500 * time.Millisecond)
			case "alienvault":
				fetchAlienVaultURLs(domain, urlChan)
				time.Sleep(500 * time.Millisecond)
			case "urlscan":
				fetchURLScanURLs(domain, urlChan)
				time.Sleep(500 * time.Millisecond)
			}
		}
		regexExtractParams(domain, urlChan)
		if config.BruteForce {
			bruteForceParameters(domain, urlChan)
		}
		close(urlChan)
		wg.Wait()
		close(progressChan)
		saveResults(domain)
	}
	fmt.Println(green("[SUCCESS]"), "Parameter hunting completed!")
}

func cleanDomain(domain string) string {
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimSuffix(domain, "/")
	domain = strings.TrimPrefix(domain, "www.")
	return domain
}

func loadDomainsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			domains = append(domains, line)
		}
	}
	return domains, scanner.Err()
}

func fetchWaybackURLs(domain string, urlChan chan<- string) {
	fmt.Printf("%s Fetching URLs from Wayback Machine for %s\n", yellow("[INFO]"), cyan(domain))
	waybackURL := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=%s/*&output=json&collapse=urlkey&fl=original", domain)
	resp, err := makeRequest(waybackURL)
	if err != nil {
		fmt.Printf("%s Error fetching from Wayback Machine: %v\n", red("[ERROR]"), err)
		return
	}
	defer resp.Body.Close()
	var cdxData [][]string
	if err := json.NewDecoder(resp.Body).Decode(&cdxData); err != nil {
		fmt.Printf("%s Error parsing Wayback Machine response: %v\n", red("[ERROR]"), err)
		return
	}
	if len(cdxData) > 0 {
		cdxData = cdxData[1:]
	}
	fmt.Printf("%s Found %s URLs from Wayback Machine\n", yellow("[INFO]"), green(fmt.Sprintf("%d", len(cdxData))))
	for _, row := range cdxData {
		if len(row) > 0 {
			urlStr := row[0]
			if shouldProcessURL(urlStr) {
				urlChan <- urlStr
			}
		}
	}
}

func fetchCommonCrawlURLs(domain string, urlChan chan<- string) {
	fmt.Printf("%s Fetching URLs from Common Crawl for %s\n", yellow("[INFO]"), cyan(domain))
	indexURL := "https://index.commoncrawl.org/collinfo.json"
	resp, err := makeRequest(indexURL)
	if err != nil {
		fmt.Printf("%s Error fetching Common Crawl index: %v\n", red("[ERROR]"), err)
		return
	}
	var indices []struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&indices); err != nil {
		fmt.Printf("%s Error parsing Common Crawl index: %v\n", red("[ERROR]"), err)
		resp.Body.Close()
		return
	}
	resp.Body.Close()
	if len(indices) == 0 {
		fmt.Printf("%s No Common Crawl indices found\n", red("[ERROR]"))
		return
	}
	latestIndex := indices[0].ID
	ccURL := fmt.Sprintf("https://index.commoncrawl.org/%s-index?url=*.%s/*&output=json", latestIndex, domain)
	resp, err = makeRequest(ccURL)
	if err != nil {
		fmt.Printf("%s Error fetching from Common Crawl: %v\n", red("[ERROR]"), err)
		return
	}
	defer resp.Body.Close()
	scanner := bufio.NewScanner(resp.Body)
	var count int
	for scanner.Scan() {
		line := scanner.Text()
		var res struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal([]byte(line), &res); err != nil {
			continue
		}
		if shouldProcessURL(res.URL) {
			urlChan <- res.URL
			count++
		}
	}
	fmt.Printf("%s Found %s URLs from Common Crawl\n", yellow("[INFO]"), green(fmt.Sprintf("%d", count)))
}

func fetchAlienVaultURLs(domain string, urlChan chan<- string) {
	fmt.Printf("%s Fetching URLs from AlienVault OTX for %s\n", yellow("[INFO]"), cyan(domain))
	avURL := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/url_list", domain)
	resp, err := makeRequest(avURL)
	if err != nil {
		fmt.Printf("%s Error fetching from AlienVault: %v\n", red("[ERROR]"), err)
		return
	}
	defer resp.Body.Close()
	var result struct {
		URLList []struct {
			URL string `json:"url"`
		} `json:"url_list"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Printf("%s Error parsing AlienVault response: %v\n", red("[ERROR]"), err)
		return
	}
	fmt.Printf("%s Found %s URLs from AlienVault\n", yellow("[INFO]"), green(fmt.Sprintf("%d", len(result.URLList))))
	for _, item := range result.URLList {
		if shouldProcessURL(item.URL) {
			urlChan <- item.URL
		}
	}
}

func fetchURLScanURLs(domain string, urlChan chan<- string) {
	fmt.Printf("%s Fetching URLs from URLScan.io for %s\n", yellow("[INFO]"), cyan(domain))
	urlscanURL := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s", domain)
	resp, err := makeRequest(urlscanURL)
	if err != nil {
		fmt.Printf("%s Error fetching from URLScan.io: %v\n", red("[ERROR]"), err)
		return
	}
	defer resp.Body.Close()
	var result struct {
		Results []struct {
			Page struct {
				URL string `json:"url"`
			} `json:"page"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Printf("%s Error parsing URLScan.io response: %v\n", red("[ERROR]"), err)
		return
	}
	fmt.Printf("%s Found %s URLs from URLScan.io\n", yellow("[INFO]"), green(fmt.Sprintf("%d", len(result.Results))))
	for _, item := range result.Results {
		if shouldProcessURL(item.Page.URL) {
			urlChan <- item.Page.URL
		}
	}
}

func regexExtractParams(domain string, urlChan chan<- string) {
	resp, err := httpClient.Get("https://" + domain)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	r1 := regexp.MustCompile(`name=["']([^"']+)["']`)
	matches1 := r1.FindAllStringSubmatch(string(body), -1)
	uniqueParams := make(map[string]bool)
	for _, m := range matches1 {
		if len(m) > 1 && validParamName(m[1]) {
			uniqueParams[m[1]] = true
		}
	}
	r2 := regexp.MustCompile(`\?([^"' >]+)`)
	matches2 := r2.FindAllStringSubmatch(string(body), -1)
	for _, m := range matches2 {
		if len(m) > 1 {
			parts := strings.Split(m[1], "&")
			for _, part := range parts {
				kv := strings.SplitN(part, "=", 2)
				if len(kv) > 0 && validParamName(kv[0]) {
					uniqueParams[kv[0]] = true
				}
			}
		}
	}
	re := regexp.MustCompile(`^param\d+$`)
	for param := range uniqueParams {
		if re.MatchString(param) {
			delete(uniqueParams, param)
		}
	}
	for param := range uniqueParams {
		constructedURL := fmt.Sprintf("https://%s/?%s=%s", domain, param, config.Placeholder)
		urlChan <- constructedURL
	}
}

func bruteForceParameters(domain string, urlChan chan<- string) {
	var params []string
	if config.ParamWordlist != "" {
		data, err := os.ReadFile(config.ParamWordlist)
		if err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" && validParamName(line) {
					params = append(params, line)
				}
			}
		}
	} else {
		lines := strings.Split(defaultParamWordlist, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && validParamName(line) {
				params = append(params, line)
			}
		}
	}
	baseURLs := []string{
		fmt.Sprintf("https://%s/", domain),
		fmt.Sprintf("https://www.%s/", domain),
	}
	commonPaths := []string{"", "search", "index.php", "index.html", "api", "app", "main"}
	var urls []string
	for _, baseURL := range baseURLs {
		for _, path := range commonPaths {
			if path == "" {
				urls = append(urls, baseURL)
			} else {
				urls = append(urls, fmt.Sprintf("%s%s", baseURL, path))
			}
		}
	}
	for _, urlStr := range urls {
		for _, param := range params {
			constructedURL := fmt.Sprintf("%s?%s=%s", urlStr, param, config.Placeholder)
			urlChan <- constructedURL
		}
	}
}

func makeRequest(urlStr string) (*http.Response, error) {
	var resp *http.Response
	var err error
	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		req, err := http.NewRequest("GET", urlStr, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", getRandomUserAgent())
		resp, err = httpClient.Do(req)
		if err == nil {
			return resp, nil
		}
		time.Sleep(time.Duration(1<<i) * time.Second)
	}
	return nil, err
}

func getRandomUserAgent() string {
	return userAgents[rand.Intn(len(userAgents))]
}

func shouldProcessURL(urlStr string) bool {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	ext := strings.ToLower(filepath.Ext(parsedURL.Path))
	for _, ignoreExt := range config.IgnoreExts {
		if ext == ignoreExt {
			return false
		}
	}
	return true
}

func processURL(urlStr, domain string) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		if config.Verbose {
			fmt.Printf("%s Error parsing URL %s: %v\n", red("[ERROR]"), urlStr, err)
		}
		return
	}
	if parsedURL.RawQuery == "" {
		return
	}
	var paramNames []string
	params := parsedURL.Query()
	if len(params) > 0 {
		for name := range params {
			if validParamName(name) {
				paramNames = append(paramNames, name)
				params.Set(name, config.Placeholder)
			}
		}
	} else {
		for _, pair := range strings.Split(parsedURL.RawQuery, "&") {
			parts := strings.SplitN(pair, "=", 2)
			if len(parts) > 0 && parts[0] != "" && validParamName(parts[0]) {
				found := false
				for _, p := range paramNames {
					if p == parts[0] {
						found = true
						break
					}
				}
				if !found {
					paramNames = append(paramNames, parts[0])
				}
			}
		}
		var pairs []string
		for _, name := range paramNames {
			pairs = append(pairs, name+"="+config.Placeholder)
		}
		parsedURL.RawQuery = strings.Join(pairs, "&")
	}
	if len(paramNames) == 0 {
		return
	}
	cleanedURL := parsedURL.String()
	var reflectiveParams []string
	if config.ReflectionCheck {
		reflectiveParams = checkReflection(urlStr, paramNames)
	}
	res := Result{
		URL:        cleanedURL,
		Parameters: paramNames,
		Reflective: reflectiveParams,
		Source:     "archive",
	}
	if config.Stream {
		fmt.Println(cleanedURL)
	}
	resultMu.Lock()
	results = append(results, res)
	resultMu.Unlock()
}

func checkReflection(urlStr string, paramNames []string) []string {
	var reflectiveParams []string
	for _, param := range paramNames {
		testValue := fmt.Sprintf("r3fl3ct10n_%s_%d", param, rand.Int())
		parsedURL, err := url.Parse(urlStr)
		if err != nil {
			continue
		}
		query := parsedURL.Query()
		query.Set(param, testValue)
		parsedURL.RawQuery = query.Encode()
		resp, err := makeRequest(parsedURL.String())
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		if strings.Contains(string(body), testValue) {
			reflectiveParams = append(reflectiveParams, param)
		}
	}
	return reflectiveParams
}

func saveResults(domain string) {
	if len(results) == 0 {
		fmt.Printf("%s No parameters found for %s\n", yellow("[INFO]"), cyan(domain))
		return
	}
	outputFile := filepath.Join(config.OutputDir, domain+".json")
	file, err := os.Create(outputFile)
	if err != nil {
		fmt.Printf("%s Error creating output file: %v\n", red("[ERROR]"), err)
		return
	}
	defer file.Close()
	textFile, err := os.Create(filepath.Join(config.OutputDir, domain+".txt"))
	if err != nil {
		fmt.Printf("%s Error creating text output file: %v\n", red("[ERROR]"), err)
		return
	}
	defer textFile.Close()
	for _, res := range results {
		fmt.Fprintln(textFile, res.URL)
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		fmt.Printf("%s Error writing results: %v\n", red("[ERROR]"), err)
		return
	}
	fmt.Printf("%s Saved %s results to %s\n", green("[SUCCESS]"), green(fmt.Sprintf("%d", len(results))), cyan(outputFile))
	resultMu.Lock()
	results = nil
	resultMu.Unlock()
}
