package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"
)

type EncryptRequest struct {
	PayloadB64 string `json:"payload_b64"`
}

type DecryptRequest struct {
	CiphertextB64   string `json:"ciphertext_b64"`
	NonceB64        string `json:"nonce_b64"`
	EncryptedDekB64 string `json:"encrypted_dek_b64"`
	DekNonceB64     string `json:"dek_nonce_b64"`
	KeyID           string `json:"key_id"`
}

type EncryptResponse struct {
	CiphertextB64   string `json:"ciphertext_b64"`
	NonceB64        string `json:"nonce_b64"`
	EncryptedDekB64 string `json:"encrypted_dek_b64"`
	DekNonceB64     string `json:"dek_nonce_b64"`
	KeyID           string `json:"key_id"`
}

type DecryptResponse struct {
	PayloadB64 string `json:"payload_b64"`
}

type Result struct {
	Latency     time.Duration
	Success     bool
	RateLimited bool
	Err         string
}

// Captured from first successful /encrypt response during load test.
var (
	encryptResult EncryptResponse
	encryptOnce   sync.Once
)

var (
	baseURL    string
	apiKey     string
	conc       int
	totalReq   int
	httpClient *http.Client
)

// --------------------------------------------------------------------------
// HTTP HELPERS
// --------------------------------------------------------------------------

func doPost(url string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	return httpClient.Do(req)
}

// --------------------------------------------------------------------------
// SMOKE TEST
// --------------------------------------------------------------------------

func runSmokeTest() bool {
	fmt.Println("\n=== Smoke Test: single encrypt + decrypt ===")

	// Encrypt
	plaintext := base64.StdEncoding.EncodeToString([]byte("hello secret-manager"))
	encBody, _ := json.Marshal(EncryptRequest{PayloadB64: plaintext})

	fmt.Printf("  Encrypting: %q (base64: %s)\n", "hello secret-manager", plaintext)
	resp, err := doPost(baseURL+"/encrypt", encBody)
	if err != nil {
		fmt.Printf("  ✗ Encrypt request failed: %v\n", err)
		return false
	}
	defer resp.Body.Close()
	encBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		fmt.Printf("  ✗ Encrypt returned %d: %s\n", resp.StatusCode, string(encBytes))
		return false
	}

	var encResp EncryptResponse
	if err := json.Unmarshal(encBytes, &encResp); err != nil {
		fmt.Printf("  ✗ Bad JSON: %v\n", err)
		return false
	}
	fmt.Printf("  ✓ Encrypted OK — ciphertext_b64=%s...\n", encResp.CiphertextB64[:min(40, len(encResp.CiphertextB64))])

	// Decrypt
	decBody, _ := json.Marshal(DecryptRequest{
		CiphertextB64:   encResp.CiphertextB64,
		NonceB64:        encResp.NonceB64,
		EncryptedDekB64: encResp.EncryptedDekB64,
		DekNonceB64:     encResp.DekNonceB64,
		KeyID:           encResp.KeyID,
	})

	resp2, err := doPost(baseURL+"/decrypt", decBody)
	if err != nil {
		fmt.Printf("  ✗ Decrypt request failed: %v\n", err)
		return false
	}
	defer resp2.Body.Close()
	decBytes, _ := io.ReadAll(resp2.Body)

	if resp2.StatusCode != 200 {
		fmt.Printf("  ✗ Decrypt returned %d: %s\n", resp2.StatusCode, string(decBytes))
		return false
	}

	var decResp DecryptResponse
	if err := json.Unmarshal(decBytes, &decResp); err != nil {
		fmt.Printf("  ✗ Bad JSON: %v\n", err)
		return false
	}

	decoded, _ := base64.StdEncoding.DecodeString(decResp.PayloadB64)
	fmt.Printf("  ✓ Decrypted OK — payload: %q\n", string(decoded))

	if string(decoded) == "hello secret-manager" {
		fmt.Println("  ✓ Roundtrip verified — plaintext matches!")
		fmt.Println("=== Smoke Test PASSED ===")
		return true
	}

	fmt.Printf("  ✗ Roundtrip MISMATCH: expected %q, got %q\n", "hello secret-manager", string(decoded))
	fmt.Println("=== Smoke Test FAILED ===")
	return false
}

// --------------------------------------------------------------------------
// MAIN TEST FUNCTIONS
// --------------------------------------------------------------------------

func runEncryptTest() {
	fmt.Println("\n=== Running /encrypt Performance Test ===")
	start := time.Now()
	results := runLoad(baseURL+"/encrypt", conc, totalReq, func() []byte {
		body, _ := json.Marshal(EncryptRequest{PayloadB64: "c3RyaW5n"})
		return body
	}, func(body []byte) {
		encryptOnce.Do(func() {
			var resp EncryptResponse
			if err := json.Unmarshal(body, &resp); err == nil {
				encryptResult = resp
			}
		})
	})
	duration := time.Since(start)
	reportResults(results, duration)
}

func runDecryptTest() {
	if encryptResult.CiphertextB64 == "" {
		fmt.Println("No encrypt result available — skipping decrypt test")
		return
	}
	fmt.Printf("Using captured envelope: ciphertext_b64=%s...\n", encryptResult.CiphertextB64[:min(40, len(encryptResult.CiphertextB64))])

	fmt.Println("\n=== Running /decrypt Performance Test ===")
	start := time.Now()
	results := runLoad(baseURL+"/decrypt", conc, totalReq, func() []byte {
		body, _ := json.Marshal(DecryptRequest{
			CiphertextB64:   encryptResult.CiphertextB64,
			NonceB64:        encryptResult.NonceB64,
			EncryptedDekB64: encryptResult.EncryptedDekB64,
			DekNonceB64:     encryptResult.DekNonceB64,
			KeyID:           encryptResult.KeyID,
		})
		return body
	}, nil)
	duration := time.Since(start)
	reportResults(results, duration)
}

// --------------------------------------------------------------------------
// CORE LOAD TESTER
// --------------------------------------------------------------------------

func runLoad(url string, concurrency, requests int, buildBody func() []byte, onSuccess func([]byte)) []Result {
	var wg sync.WaitGroup
	results := make([]Result, requests)
	idxChan := make(chan int, requests)

	for i := 0; i < requests; i++ {
		idxChan <- i
	}
	close(idxChan)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range idxChan {
				body := buildBody()
				rateLimited := false
				var latency time.Duration
				var errMsg string
				var success bool
				const maxRetries = 3
				for attempt := 0; attempt <= maxRetries; attempt++ {
					start := time.Now()
					resp, err := doPost(url, body)
					latency = time.Since(start)

					if resp != nil {
						bodyBytes, _ := io.ReadAll(resp.Body)
						resp.Body.Close()

						if resp.StatusCode == 429 {
							if attempt < maxRetries {
								time.Sleep(1 * time.Second)
								continue
							}
							// exhausted retries — record as rate-limited failure
							rateLimited = true
							errMsg = fmt.Sprintf("status=%d body=%s", resp.StatusCode, string(bodyBytes))
							if err != nil {
								errMsg = fmt.Sprintf("err=%v %s", err, errMsg)
							}
							break
						}

						if err == nil && resp.StatusCode == 200 {
							success = true
							if onSuccess != nil {
								onSuccess(bodyBytes)
							}
						} else {
							errMsg = fmt.Sprintf("status=%d body=%s", resp.StatusCode, string(bodyBytes))
							if err != nil {
								errMsg = fmt.Sprintf("err=%v %s", err, errMsg)
							}
						}
					} else {
						errMsg = fmt.Sprintf("err=%v", err)
					}
					break
				}

				results[idx] = Result{
					Latency:     latency,
					Success:     success,
					RateLimited: rateLimited,
					Err:         errMsg,
				}
			}
		}()
	}

	wg.Wait()
	return results
}

// --------------------------------------------------------------------------
// METRIC CALCULATION
// --------------------------------------------------------------------------

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	k := (p / 100) * float64(len(sorted)-1)
	f := math.Floor(k)
	c := math.Ceil(k)
	if f == c {
		return sorted[int(k)]
	}
	d0 := sorted[int(f)] * (c - k)
	d1 := sorted[int(c)] * (k - f)
	return d0 + d1
}

func reportResults(results []Result, duration time.Duration) {
	latencies := []float64{}
	success := 0
	fail := 0
	rateLimited := 0
	firstErr := ""

	for _, r := range results {
		if r.Success {
			success++
		} else {
			fail++
			if r.RateLimited {
				rateLimited++
			} else if firstErr == "" {
				firstErr = r.Err
			}
		}
		latencies = append(latencies, float64(r.Latency.Microseconds()))
	}

	sort.Float64s(latencies)

	total := float64(0)
	for _, v := range latencies {
		total += v
	}

	avg := total / float64(len(latencies))
	min := latencies[0]
	max := latencies[len(latencies)-1]

	// Std deviation
	var variance float64
	for _, v := range latencies {
		variance += (v - avg) * (v - avg)
	}
	stddev := math.Sqrt(variance / float64(len(latencies)))

	// Percentiles
	p50 := percentile(latencies, 50)
	p90 := percentile(latencies, 90)
	p95 := percentile(latencies, 95)
	p99 := percentile(latencies, 99)

	// Requests per second
	rps := float64(len(results)) / duration.Seconds()

	// Error rate
	errorRate := float64(fail) / float64(len(results)) * 100

	// Histogram buckets (10ms bucket)
	buckets := make(map[int]int)
	for _, v := range latencies {
		ms := int(v / 1000)
		bucket := (ms / 10) * 10
		buckets[bucket]++
	}

	// ----------------------------------------------------------------------
	// PRINT RESULTS
	// ----------------------------------------------------------------------
	fmt.Println("------------------------------------------------------------")
	fmt.Printf("Total Requests: %d\n", len(results))
	fmt.Printf("Success: %d, Failed: %d (%.2f%% errors)\n", success, fail, errorRate)
	fmt.Printf("Rate Limited (429): %d\n", rateLimited)
	if firstErr != "" {
		fmt.Printf("Sample error: %s\n", firstErr)
	}
	fmt.Printf("Total Test Duration: %v\n", duration)
	fmt.Printf("Requests per Second (RPS): %.2f\n\n", rps)

	fmt.Println("Latency Metrics (microseconds):")
	fmt.Printf("  Average: %.0f µs\n", avg)
	fmt.Printf("  Min: %.0f µs\n", min)
	fmt.Printf("  Max: %.0f µs\n", max)
	fmt.Printf("  Std Dev: %.0f µs\n\n", stddev)

	fmt.Println("Percentiles:")
	fmt.Printf("  P50: %.0f µs\n", p50)
	fmt.Printf("  P90: %.0f µs\n", p90)
	fmt.Printf("  P95: %.0f µs\n", p95)
	fmt.Printf("  P99: %.0f µs\n\n", p99)

	fmt.Println("Histogram (buckets of 10ms):")
	keys := []int{}
	for k := range buckets {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	for _, k := range keys {
		fmt.Printf("  %d–%d ms : %d\n", k, k+10, buckets[k])
	}
	fmt.Println("------------------------------------------------------------")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// --------------------------------------------------------------------------
// MAIN
// --------------------------------------------------------------------------

func main() {
	flag.StringVar(&baseURL, "url", "http://localhost:8080", "Base URL of the secret-manager service")
	flag.StringVar(&apiKey, "apikey", "", "API key for Authorization header (or set APP_API_KEY env)")
	flag.IntVar(&conc, "c", 100, "Concurrency (parallel goroutines)")
	flag.IntVar(&totalReq, "n", 1000, "Total requests per test")
	smokeOnly := flag.Bool("smoke", false, "Run single encrypt+decrypt roundtrip only (no load test)")
	flag.Parse()

	// Fallback to env if flag not set
	if apiKey == "" {
		apiKey = os.Getenv("APP_API_KEY")
	}

	if apiKey == "" {
		fmt.Println("ERROR: No API key provided. Set -apikey flag or APP_API_KEY env var.")
		fmt.Println("Usage: go run perf-test.go -apikey <key> [-url <url>] [-c 100] [-n 1000]")
		os.Exit(1)
	}

	httpClient = &http.Client{Timeout: 30 * time.Second}

	fmt.Printf("Target:    %s\n", baseURL)
	fmt.Printf("API Key:   %s...%s\n", apiKey[:min(4, len(apiKey))], apiKey[max(0, len(apiKey)-4):])
	fmt.Printf("Concurrency: %d\n", conc)
	fmt.Printf("Requests:  %d\n", totalReq)

	if *smokeOnly {
		ok := runSmokeTest()
		if !ok {
			os.Exit(1)
		}
		return
	}

	// Run smoke test first, then load tests
	if !runSmokeTest() {
		fmt.Println("\nSmoke test failed — aborting load tests.")
		os.Exit(1)
	}

	runEncryptTest()
	runDecryptTest()
}
