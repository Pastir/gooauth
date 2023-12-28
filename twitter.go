package gooauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Twitter struct {
	OauthConsumerKey     string
	OauthConsumerSecret  string
	OauthNonce           string
	OauthSignatureMethod string
	OauthTimestamp       string
	OauthToken           string
	OauthTokenSecret     string
	ApiUrl               string
	OauthVersion         string
	OauthSignature       string
	OauthUrlCallback     string

	OautHeader http.Header

	Params map[string]string
}

func (t *Twitter) Init(consumerKey string, accessToken string, consumerSecret string, tokenSecret string, oauthVersion string) error {
	t.OauthConsumerKey = consumerKey
	t.OauthConsumerSecret = consumerSecret
	t.OauthSignatureMethod = "HMAC-SHA1"
	t.OauthTimestamp = strconv.FormatInt(time.Now().Unix(), 10)
	t.OauthToken = accessToken
	t.OauthTokenSecret = tokenSecret
	t.OauthVersion = oauthVersion
	t.generateNonce()
	t.Params = map[string]string{
		"status":                 "Hello Twitter!",
		"oauth_consumer_key":     t.OauthConsumerKey,
		"oauth_nonce":            t.OauthNonce,
		"oauth_signature_method": t.OauthSignatureMethod,
		"oauth_timestamp":        t.OauthTimestamp,
		"oauth_token":            accessToken,
		"oauth_version":          oauthVersion,
	}

	err := t.generateOauthV1Signature()
	if err != nil {
		return err
	}

	err = t.createAuthHeader()
	if err != nil {
		return err
	}

	return nil
}

func (t *Twitter) generateNonce() {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	nonce := make([]rune, 32)

	for i := range nonce {
		nonce[i] = letters[r.Intn(len(letters))]
	}

	t.OauthNonce = string(nonce)
}

// generateSignature https://developer.twitter.com/en/docs/authentication/oauth-1-0a/creating-a-signature
func (t *Twitter) generateOauthV1Signature() error {
	// 1. Sort the list of parameters alphabetically [1] by encoded key [2].
	var keys []string

	for k := range t.Params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var paramString strings.Builder
	var baseString strings.Builder
	var signingKey strings.Builder

	// Convert the HTTP Method to uppercase and set the output string equal to this value.
	// Append the ‘&’ character to the output string.
	_, err := baseString.WriteString("POST&")
	if err != nil {
		return err
	}
	// Percent encode the URL and append it to the output string.
	// Append the ‘&’ character to the output string.
	_, err = baseString.WriteString(url.QueryEscape(t.ApiUrl))
	if err != nil {
		return err
	}
	_, err = baseString.WriteString("&")
	if err != nil {
		return err
	}

	// Append the encoded key to the output string.
	// Append the ‘=’ character to the output string.
	// Append the encoded value to the output string.
	// If there are more key/value pairs remaining, append a ‘&’ character to the output string.
	for _, k := range keys {
		_, err = paramString.WriteString(url.QueryEscape(k))
		if err != nil {
			return err
		}
		_, err = paramString.WriteString("=")
		if err != nil {
			return err
		}
		_, err = paramString.WriteString(url.QueryEscape(t.Params[k]))
		if err != nil {
			return err
		}
	}

	// The value which identifies your app to Twitter is called the consumer secret and can be found in the developer
	// portal by viewing the app details page. This will be the same for every request your Twitter app sends.
	_, err = signingKey.WriteString(url.QueryEscape(t.OauthConsumerSecret))
	if err != nil {
		return err
	}
	_, err = signingKey.WriteString("&")
	if err != nil {
		return err
	}
	_, err = signingKey.WriteString(url.QueryEscape(t.OauthTokenSecret))
	if err != nil {
		return err
	}

	// Getting a signing key
	hmac := hmac.New(sha1.New, []byte(signingKey.String()))
	_, err = hmac.Write([]byte(baseString.String()))
	if err != nil {
		return err
	}

	rawSignature := hmac.Sum(nil)
	t.OauthSignature = base64.StdEncoding.EncodeToString(rawSignature)

	return nil
}

func (t *Twitter) createAuthHeader() error {
	var err error
	var headerParts []string
	for k, v := range t.Params {
		var p strings.Builder
		if strings.HasPrefix(k, "oauth_") {
			_, err = p.WriteString(url.QueryEscape(k))
			if err != nil {
				return err
			}
			_, err = p.WriteString(`="`)
			if err != nil {
				return err
			}
			_, err = p.WriteString(url.QueryEscape(v))
			if err != nil {
				return err
			}
			_, err = p.WriteString(`"`)
			if err != nil {
				return err
			}

			headerParts = append(headerParts, p.String())
		}
	}

	t.OautHeader.Add("Authorization", "OAuth "+strings.Join(headerParts, ","))
	return nil
}

func (t *Twitter) Request() error {
	var err error
	ctx := context.Background()
	var endpoint strings.Builder
	endpoint.WriteString(TwitterUrl)
	endpoint.WriteString(TwitterOAuthEndpointRequestToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return errors.New(resp.Status)
	}

	resBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	fmt.Println(string(resBody))

	return nil
}
