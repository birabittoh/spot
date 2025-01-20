package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func validateTOTP(providedTOTP string) bool {
	return totp.Validate(providedTOTP, secretKey.Secret())
}

func initSecretKey() *otp.Key {
	totpSecretFilePath := filepath.Join(dataDir, totpSecretFileName)
	secretData, err := os.ReadFile(totpSecretFilePath)
	if err == nil {
		k, err := otp.NewKeyFromURL(string(secretData))
		if err == nil {
			return k
		}
		log.Println("Could not parse secret key:", err)
	}

	log.Println("Generating new TOTP secret...")
	k, err := totp.Generate(totp.GenerateOpts{Issuer: totpIssuer, AccountName: totpAccount})
	if err != nil {
		log.Println("Could not generate secret:", err)
		return nil
	}

	if err := os.WriteFile(totpSecretFilePath, []byte(k.URL()), 0644); err != nil {
		log.Println("Error: could not write secret to file:", err)
	}
	return k
}
