package oauthserver

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt"
)

const (
	appleAuthURL = "https://appleid.apple.com/auth/token"
	redirectURI  = "https://example-app.com/redirect"
)

// parseECPrivateKey parses an ECDSA private key from a PEM encoded string
func parseECPrivateKey(pemEncoded []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemEncoded)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER encoded private key: %v", err)
	}

	return privateKey.(*ecdsa.PrivateKey), nil
}

func getAppleClientSecret(appleClientID, appleTeamID, appleKeyID string, applePrivateKey []byte) (clientSecret string, err error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": appleTeamID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour * 24 * 180).Unix(), // 180 days
		"aud": "https://appleid.apple.com",
		"sub": appleClientID,
	})

	// Set the Key ID (kid) header
	token.Header["kid"] = appleKeyID

	key, err := parseECPrivateKey(applePrivateKey)
	if err != nil {
		return clientSecret, fmt.Errorf("error parsing private key: %v", err)
	}

	// Sign and get the complete encoded token as a string
	clientSecret, err = token.SignedString(key)
	if err != nil {
		return clientSecret, fmt.Errorf("error signing token: %v", err)
	}

	return clientSecret, nil
}

func GetAppleUserData(accessCode, appleClientID, appleTeamID, appleKeyID string, applePrivateKey []byte) (user User, err error) {
	appleClientSecret, err := getAppleClientSecret(appleClientID, appleTeamID, appleKeyID, applePrivateKey)
	if err != nil {
		return user, fmt.Errorf("error getting apple client secret: %v", err)
	}

	claims, err := getAppleClaims(appleClientID, appleClientSecret, accessCode)
	if err != nil {
		return user, fmt.Errorf("error getting apple claims: %v", err)
	}

	return User{
		Email:      claims["email"].(string),
		ProviderID: claims["sub"].(string),
	}, nil
}

func getAppleClaims(appleClientID string, appleClientSecret string, accessCode string) (jwt.MapClaims, error) {
	data := url.Values{}
	data.Set("client_id", appleClientID)
	data.Set("client_secret", appleClientSecret)
	data.Set("code", accessCode)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", redirectURI)

	res, err := http.PostForm(appleAuthURL, data)
	if err != nil {
		return nil, fmt.Errorf("error making request to apple: %v", err)
	}

	defer res.Body.Close()

	var responseDict map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&responseDict); err != nil {
		return nil, fmt.Errorf("error decoding response body")
	}

	if err, ok := responseDict["error"]; ok {
		return nil, fmt.Errorf("error from apple: %s, error description: %v", err, responseDict["error_description"])
	}

	if responseDict["id_token"] == "" {
		return nil, fmt.Errorf("apple didn't return id_token")
	}

	decoded, _, err := new(jwt.Parser).ParseUnverified(responseDict["id_token"].(string), jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("error decoding id_token")
	}

	claims, ok := decoded.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("error decoding id_token: claims not map")
	}
	return claims, nil
}
