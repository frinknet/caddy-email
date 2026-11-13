package shared

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

func SignHMAC(secret string, body []byte) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(body)
	return "sha256=" + hex.EncodeToString(h.Sum(nil))
}

func VerifyHMAC(secret string, body []byte, sig string) bool {
	expected := SignHMAC(secret, body)
	return hmac.Equal([]byte(expected), []byte(sig))
}
