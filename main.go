package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	urlsFilePath string
	payloads     = []string{"'", "\"", ">", "<", "&"}
	proxy        string

	green = color.New(color.FgGreen).SprintFunc()
	red   = color.New(color.FgRed).SprintFunc()
)

func main() {
	rootCmd := &cobra.Command{
		Use:     "xssprobe",
		Short:   "A tool for finding XSS",
		Long:    `XSSProbe is a tool for finding XSS across a range of URLs.`,
		Example: `./xssprobe -u ./urls.txt`,
		Run:     run,
	}

	rootCmd.PersistentFlags().StringVarP(&urlsFilePath, "urls", "u", "", "file containing the URLs to be checked (required)")
	rootCmd.PersistentFlags().StringVarP(&proxy, "proxy", "p", "", "proxy URL (default: \"\")")

	rootCmd.Execute()
}

func run(cmd *cobra.Command, args []string) {
	printIntro()

	if urlsFilePath == "" {
		log.Fatal(red("URLs file path is required. Use -u <file_path> to specify the file."))
	}

	urls, err := readURLsFromFile(urlsFilePath)
	if err != nil {
		log.Fatalf(red("Error reading URLs from file: %s"), err)
	}

	for _, u := range urls {
		processURL(u)
	}
}

func printIntro() {
	color.Green("##################################\n")
	color.Green("#                                #\n")
	color.Green("#          XSSProbe              #\n")
	color.Green("#                                #\n")
	color.Green("##################################\n\n")
}

func readURLsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		urls = append(urls, scanner.Text())
	}

	return urls, scanner.Err()
}

func processURL(rawURL string) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		log.Printf(red("Error parsing URL: %s"), err)
		return
	}

	testURLForXSS(parsedURL)
}

func testURLForXSS(parsedURL *url.URL) {
	queryValues := parsedURL.Query()
	for param, values := range queryValues {
		originalValue := values[0]
		for _, payload := range payloads {
			testPayloads(parsedURL, param, originalValue, payload)
		}
		queryValues.Set(param, originalValue)
	}
}

func testPayloads(parsedURL *url.URL, param, originalValue, payload string) {
	encodedPayloads := encodePayloads(payload)
	for _, encodedPayload := range encodedPayloads {
		parsedURL.Query().Set(param, encodedPayload)
		parsedURL.RawQuery = parsedURL.Query().Encode()

		response, err := sendRequest(parsedURL.String())
		if err != nil {
			log.Printf(red("Error sending request: %s"), err)
			continue
		}

		if analyzeResponse(response, payload) {
			log.Printf(green("Potential XSS detected at %s with payload %s"), parsedURL.String(), payload)
		}
	}
}

func encodePayloads(payload string) []string {
	var encodedPayloads []string
	encodedPayloads = append(encodedPayloads, url.QueryEscape(payload))
	encodedPayloads = append(encodedPayloads, url.QueryEscape(url.QueryEscape(payload)))
	return encodedPayloads
}

// sendRequest sends an HTTP GET request to the given URL using the optional proxy and returns the response body
func sendRequest(reqURL string) (string, error) {
	client := &http.Client{}

	// If a proxy URL is provided, configure the client to use it
	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			return "", fmt.Errorf("invalid proxy URL: %v", err)
		}
		client.Transport = &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		}
	}

	resp, err := client.Get(reqURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func analyzeResponse(response, payload string) bool {
	return strings.Contains(response, payload)
}
