package gooauth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type (
	Twitter struct {
		OauthConsumerKey     string
		OauthConsumerSecret  string
		OauthNonce           string
		OauthSignatureMethod string
		OauthTimestamp       string
		OauthToken           string
		OauthTokenSecret     string
		OauthVersion         string
		OauthSignature       string
		OauthUrlCallback     string
		ApiUrl               string
		Parameters           map[string]string
		ParametersString     string
		BaseString           strings.Builder
		SigningKey           string
		ResponseReqToken     ResponseRequestToken
	}

	// ResponseRequestToken oauth_token=FeBpvQAAAAABrc5sAAABjLE_WJw&oauth_token_secret=1fqLzSgl6RfeeLstAHQBuJQFVJcAkQNb&oauth_callback_confirmed=true
	ResponseRequestToken struct {
		OauthToken             string
		OauthTokenSecret       string
		OauthCallbackConfirmed string
	}
)

func Oauth(accessToken string, tokenSecret string, consumerKey string, consumerSecret string, oauthVersion string, apiUrl string) (Twitter, error) {
	var err error
	tw := Twitter{
		OauthToken:           accessToken,
		OauthTokenSecret:     tokenSecret,
		OauthConsumerKey:     consumerKey,
		OauthConsumerSecret:  consumerSecret,
		OauthVersion:         oauthVersion,
		OauthSignatureMethod: "HMAC-SHA1",
		OauthTimestamp:       strconv.FormatInt(time.Now().Unix(), 10),
		ApiUrl:               apiUrl,
	}

	tw.Parameters = make(map[string]string)
	tw.generateNonce()
	tw.createCollectingParameters()
	err = tw.createSignatureBaseString()
	if err != nil {
		return Twitter{}, err
	}

	err = tw.createSigningKey()
	if err != nil {
		return Twitter{}, err
	}

	return tw, nil
}

// generateNonce - generate nonce
func (t *Twitter) generateNonce() {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	nonce := make([]rune, 32)

	for i := range nonce {
		nonce[i] = letters[r.Intn(len(letters))]
	}

	t.OauthNonce = string(nonce)
}

// collectingParameters Collecting parameters
func (t *Twitter) createCollectingParameters() {
	t.Parameters = map[string]string{
		"oauth_consumer_key":     t.OauthConsumerKey,
		"oauth_nonce":            t.OauthNonce,
		"oauth_signature_method": t.OauthSignatureMethod,
		"oauth_timestamp":        t.OauthTimestamp,
		"oauth_version":          t.OauthVersion,
		"oauth_token":            t.OauthToken,
	}

	// 1. Sort the list of parameters alphabetically [1] by encoded key [2].
	var keys []string
	for k := range t.Parameters {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parameters strings.Builder
	// Percent encode every key and value that will be signed.
	// Append the ‘=’ character to the output string.
	// If there are more key/value pairs remaining, append a ‘&’ character to the output string.
	for _, v := range keys {
		if v != "" {
			parameters.WriteString(url.QueryEscape(v))
			parameters.WriteString("=")
			parameters.WriteString(url.QueryEscape(t.Parameters[v]))
			parameters.WriteString("&")
		}
	}

	// Cut last symbol &
	t.ParametersString = strings.TrimRight(parameters.String(), "&")
}

// createSignatureBaseString - Creating the signature base string
func (t *Twitter) createSignatureBaseString() error {

	// Convert the HTTP Method to uppercase and set the output string equal to this value.
	// Append the ‘&’ character to the output string.
	_, err := t.BaseString.WriteString("POST&")
	if err != nil {
		return err
	}
	// Percent encode the URL and append it to the output string.
	_, err = t.BaseString.WriteString(url.QueryEscape(t.ApiUrl))
	if err != nil {
		return err
	}
	// Append the ‘&’ character to the output string.
	_, err = t.BaseString.WriteString("&")
	if err != nil {
		return err
	}

	// Percent encode the parameter string and append it to the output string.
	_, err = t.BaseString.WriteString(url.QueryEscape(t.ParametersString))
	if err != nil {
		return err
	}

	return nil
}

func (t *Twitter) createSigningKey() error {
	var err error
	var signingKey strings.Builder
	// Both of these values need to be combined to form a signing key which will be used to generate the signature.
	// The signing key is simply the percent encoded consumer secret, followed by an ampersand character ‘&’,
	// followed by the percent encoded token secret:
	signingKey.WriteString(url.QueryEscape(t.OauthConsumerSecret))
	signingKey.WriteString("&")
	signingKey.WriteString(url.QueryEscape(t.OauthTokenSecret))

	hmac := hmac.New(sha1.New, []byte(signingKey.String()))
	fmt.Println(t.BaseString.String())
	_, err = hmac.Write([]byte(t.BaseString.String()))
	if err != nil {
		return err
	}

	t.SigningKey = base64.StdEncoding.EncodeToString(hmac.Sum(nil))

	return nil

}

func (t *Twitter) CreateOAuthHeader() (string, error) {

	var paramsString strings.Builder
	paramsString.WriteString("OAuth ")

	for k, v := range t.Parameters {
		paramsString.WriteString(url.QueryEscape(k))
		paramsString.WriteString("=")
		paramsString.WriteString(url.QueryEscape(v))
		paramsString.WriteString(", ")
	}
	paramsString.WriteString("oauth_signature=")
	paramsString.WriteString(url.QueryEscape(t.SigningKey))
	return paramsString.String(), nil
}
