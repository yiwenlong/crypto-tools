package pem

import (
	"log"
	"testing"
	"time"
)

func TestDecodeX509Certificate(t *testing.T) {
	pemCert := "-----BEGIN CERTIFICATE-----\nMIICRzCCAe6gAwIBAgIRAMoSf0qPz8JvkfyakEQ7GxYwCgYIKoZIzj0EAwIwgYcx\nCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1TYW4g\nRnJhbmNpc2NvMSMwIQYDVQQKExpvcmcxLmV4YW1wbGUuZm5vZG9ja2VyLmljdTEm\nMCQGA1UEAxMdY2Eub3JnMS5leGFtcGxlLmZub2RvY2tlci5pY3UwHhcNMjAwNzEw\nMDI0MDAwWhcNMzAwNzA4MDI0MDAwWjB0MQswCQYDVQQGEwJVUzETMBEGA1UECBMK\nQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzENMAsGA1UECxMEcGVl\ncjEpMCcGA1UEAxMgcGVlcjAub3JnMS5leGFtcGxlLmZub2RvY2tlci5pY3UwWTAT\nBgcqhkjOPQIBBggqhkjOPQMBBwNCAAThWx7+ifMIk4dntLe6IR+slH8pRplUCjuS\ntZjIcWZUov5RZX05byPbbrXxxw8PzmVHPE6RERudwnCoscltytEdo00wSzAOBgNV\nHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADArBgNVHSMEJDAigCAe78Xd0ado/CdU\nR88XdzpuREvB46SJOTdwX/uvbLl8ITAKBggqhkjOPQQDAgNHADBEAiBTtc3TSQxu\n5dg3zo0mLVOYN5+ThaZIsciwcWXUXY5AwQIgUOFgihBkIFHe4Dxwg3Dw94t5HMaR\nL50sVCAOVhnmHfM=\n-----END CERTIFICATE-----\n"
	start := time.Now().Nanosecond();
	log.Println("Start decode certificate: ")
	for i := 1; i <= 1000000; i++ {
		_, _ = DecodeX509Certificate([]byte(pemCert))
		if i % 10000 == 0 {
			log.Printf("Complete count: %d\n", i)
		}
	}
	log.Println("Decode certificate complete.")
	log.Println(time.Now().Nanosecond() - start)
}
