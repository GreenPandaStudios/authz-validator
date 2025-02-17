package authz_validator

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/golang-jwt/jwt/v4"
)

var (
	keyCache = make(map[string]([]interface{}))
	cacheMutex = &sync.Mutex{}
)

func ValidateAccessToken(authHeader string, scopes []string, audience string) (bool, error) {


	tokenTypeAccessToken := strings.Split(authHeader, " ")
	if len(tokenTypeAccessToken) != 2 {
		return false, errors.New("invalid authorization header format")
	}
	tokenType, accessToken := tokenTypeAccessToken[0], tokenTypeAccessToken[1]

	token, _, err := new(jwt.Parser).ParseUnverified(accessToken, jwt.MapClaims{})
	if err != nil {
		return false, err
	}
	claims, ok := token.Claims.(jwt.MapClaims);

	if !ok {
		return false, errors.New("invalid token claims")
	}

	issuer, err := validateIssuer(claims)

	if !validateTokenType(claims,tokenType) {
		return false, errors.New("invalid token type")
	}

	if !validateScopes(claims, scopes) {
		return false, errors.New("invalid token scopes")
	}

	if !validateAudience(claims, audience) {
		return false, errors.New("invalid token audience")
	}


	if err != nil {
		return false, err
	}

	keys, err := getKeys(issuer)

	if err != nil {
		return false, err
	}

	return validateTokenWithKeys(accessToken, keys,issuer)
}



func validateTokenWithKeys(accessToken string, keys []interface{}, issuer string) (bool, error) {
	return validateTokenWithKeysRecursive(accessToken, keys, issuer, false)
}

func validateAudience(claims jwt.MapClaims, audience string) bool {
	if aud, ok := claims["aud"].(string); ok {
		return strings.EqualFold(aud, audience)
	}
	return false
}

func validateScopes(claims jwt.MapClaims, requiredScopes []string) bool {
	if scopes, ok := claims["scope"].(string); ok {
		for _, requiredScope := range requiredScopes {
			if !strings.Contains(scopes, requiredScope) {
				return false
			}
		}
		return true
	}
	return false
}

func validateTokenWithKeysRecursive(accessToken string, keys []interface{}, issuer string, base bool) (bool, error) {
	for _, key := range keys {
		token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
			return key, nil
		})
		if err == nil && token.Valid {
			return true, nil
		}
	}

	if base {
		return false, errors.New("invalid token")
	}
	
	// Otherwise, update the keys and try one more time
	keys,err := getUpdatedkeys(issuer)
	if err != nil {
		return false, err
	}

	return validateTokenWithKeysRecursive(accessToken, keys, issuer, true)
}


func validateIssuer(claims jwt.MapClaims) (string, error) {
	if issuer, ok := claims["iss"].(string); ok {
		return issuer, nil
	}
	return "", errors.New("issuer not found in token")
}

func validateTokenType(claims jwt.MapClaims,tokenType string) bool {
	return strings.EqualFold(claims["token_type"].(string), tokenType)
}

func getKeys(issuer string) (([]interface{}), error) {
	cacheMutex.Lock()
	if jwks, ok := keyCache[issuer]; ok {
		cacheMutex.Unlock()
		return jwks, nil
	}
	cacheMutex.Unlock()

	keys, err := getUpdatedkeys(issuer)
	if err != nil {
		return nil, err
	}
	cacheMutex.Lock()
	keyCache[issuer] = keys
	cacheMutex.Unlock()
	return keys, nil
}

func getUpdatedkeys(issuer string) ([]interface{}, error) {
	
	// Remove trailing slash from issuer
	if issuer[len(issuer)-1] == '/' {
		issuer = issuer[:len(issuer)-1]
	}

	url := fmt.Sprintf("%s/.well-known/openid-configuration", issuer)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get(url)

	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS from issuer: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get JWKS from issuer: status code %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response body: %w", err)
	}

	var jwks map[string]interface{}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWKS response body: %w", err)
	}

	// Find the JWKS URI in the response body
	jwksURI, ok := jwks["jwks_uri"].(string)
	if !ok {
		return nil, errors.New("jwks_uri not found in response body")
	}

	// Make a request to the JWKS URI to get the actual JWKS
	resp, err = http.Get(jwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS from JWKS URI: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get JWKS from JWKS URI: status code %d", resp.StatusCode)
	}

	body=nil
	err=nil

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response body: %w", err)
	}
	// Return the keys from the JWKS URI
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWKS response body: %w", err)
	}

	keys, ok := jwks["keys"].([]interface{})
	if !ok {
		return nil, errors.New("keys not found in JWKS response body")
	}
	if keys == nil {
		return nil, errors.New("keys not found in JWKS response body")
	}

	return keys, nil
}
