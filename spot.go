package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/pquerna/otp"
)

type RequestPayload struct {
	Key  string `json:"key"`
	TOTP string `json:"totp"`
	Data string `json:"data,omitempty"`
}

const (
	dataDir            = "data"
	encryptedFileName  = "payload.bin"
	totpSecretFileName = "secret.key"

	totpIssuer  = "SPOT"
	totpAccount = "admin"
)

var secretKey *otp.Key

func handleDecrypt(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}

	var requestData RequestPayload
	if err := json.Unmarshal(body, &requestData); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if !validateTOTP(requestData.TOTP) {
		http.Error(w, "Invalid TOTP", http.StatusUnauthorized)
		return
	}

	encryptedData, err := os.ReadFile(filepath.Join(dataDir, encryptedFileName))
	if err != nil {
		http.Error(w, "Error reading encrypted file", http.StatusInternalServerError)
		return
	}

	decryptedData, err := decryptAES(string(encryptedData), requestData.Key)
	if err != nil {
		http.Error(w, "Decryption failed", http.StatusInternalServerError)
		return
	}

	var jsonData interface{}
	if err := json.Unmarshal([]byte(decryptedData), &jsonData); err != nil {
		http.Error(w, "Decryption failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jsonData)
}

func handleEncrypt(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}

	var requestData RequestPayload
	if err := json.Unmarshal(body, &requestData); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if !validateTOTP(requestData.TOTP) {
		http.Error(w, "Invalid TOTP", http.StatusUnauthorized)
		return
	}

	encryptedData, err := encryptAES(requestData.Data, requestData.Key)
	if err != nil {
		http.Error(w, "Encryption failed", http.StatusInternalServerError)
		return
	}

	if err := os.WriteFile(filepath.Join(dataDir, encryptedFileName), []byte(encryptedData), 0644); err != nil {
		http.Error(w, "Failed to write encrypted file", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("File encrypted successfully"))
}

func init() {
	os.MkdirAll(dataDir, os.ModePerm)
	secretKey = initSecretKey()
	if secretKey == nil {
		panic("Could not initialize TOTP secret key")
	}
	log.Println("TOTP secret:", secretKey.Secret())
}

func main() {
	http.HandleFunc("POST /api/decrypt", handleDecrypt)
	http.HandleFunc("POST /api/encrypt", handleEncrypt)
	log.Println("Server running on port 3000...")
	http.ListenAndServe(":3000", nil)
}
