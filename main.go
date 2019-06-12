package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const (
	MAX_TOKEN_LIFETIME_SECS = 3600
	GOOGLE_TOKEN_URI        = "https://www.googleapis.com/oauth2/v4/token"
	GRANT_TYPE              = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	CONTAINER_URI           = "https://container.googleapis.com/v1/projects/%s/locations/%s/clusters/%s"
)

var (
	CLOUDSDK_SCOPES = []string{
		"https://www.googleapis.com/auth/userinfo.email",
		"https://www.googleapis.com/auth/cloud-platform",
		"https://www.googleapis.com/auth/appengine.admin",
		"https://www.googleapis.com/auth/compute",
	}
	projectID  = flag.String("project", "", "project name (e.g. something-123)")
	locationID = flag.String("location", "", "location name (e.g. us-central1-a)")
	clusterID  = flag.String("cluster", "", "cluster name (e.g. somecluster)")
)

func main() {
	flag.Parse()
	if projectID == nil || *projectID == "" ||
		locationID == nil || *locationID == "" ||
		clusterID == nil || *clusterID == "" {
		flag.Usage()
		panic("missing parameters")
	}

	serviceAccount, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		panic(fmt.Errorf("unable to read stding: %s", err))
	}
	kubernetesConfig, err := getCreds(serviceAccount)
	if err != nil {
		panic(fmt.Errorf("unable to get kubernetes config: %s", err))
	}
	fmt.Println(string(kubernetesConfig))
}

type GoogleClaims struct {
	Audience  string `json:"aud,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	Scope     string `json:"scope,omitempty"`
}

func (GoogleClaims) Valid() error {
	// Ignore validation as we constructed it here
	return nil
}

type ServiceAccountConfig struct {
	Type                    string `json:"type"`
	ProjectID               string `json:"project_id"`
	PrivateKeyID            string `json:"private_key_id"`
	PrivateKey              string `json:"private_key"`
	ClientEmail             string `json:"client_email"`
	ClientID                string `json:"client_id"`
	AuthURI                 string `json:"auth_uri"`
	TokenURI                string `json:"token_uri"`
	AuthProviderX509CERTURL string `json:"auth_provider_x509_cert_url"`
	ClientX509CERTURL       string `json:"client_x509_cert_url"`
}

func constructTokenBody(serviceAccount []byte) ([]byte, error) {
	var serviceAccountConfig ServiceAccountConfig
	err := json.Unmarshal(serviceAccount, &serviceAccountConfig)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()

	claims := GoogleClaims{
		Audience:  GOOGLE_TOKEN_URI,
		ExpiresAt: now + MAX_TOKEN_LIFETIME_SECS,
		IssuedAt:  now,
		Issuer:    serviceAccountConfig.ClientEmail,
		Scope:     strings.Join(CLOUDSDK_SCOPES, " "),
	}
	method := jwt.SigningMethodRS256
	token := &jwt.Token{
		Header: map[string]interface{}{
			"typ": "JWT",
			"alg": method.Alg(),
			"kid": serviceAccountConfig.PrivateKeyID,
		},
		Claims: claims,
		Method: method,
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(serviceAccountConfig.PrivateKey))
	if err != nil {
		return nil, err
	}
	assertion, err := token.SignedString(key)
	if err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Add("grant_type", GRANT_TYPE)
	form.Add("assertion", assertion)
	body := form.Encode()
	return []byte(body), nil
}

type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func getCreds(serviceAccount []byte) ([]byte, error) {
	body, err := constructTokenBody(serviceAccount)
	if err != nil {
		return nil, err
	}
	resp, err := http.Post(GOOGLE_TOKEN_URI, "application/x-www-form-urlencoded", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("unable to get token: %s", err)
	}
	defer resp.Body.Close()

	var accessTokenResponse AccessTokenResponse
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&accessTokenResponse)
	if err != nil {
		return nil, err
	}

	contianerURI := fmt.Sprintf(CONTAINER_URI, *projectID, *locationID, *clusterID)
	req, err := http.NewRequest("GET", contianerURI, nil)

	req.Header.Add("Authorization", "Bearer "+accessTokenResponse.AccessToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable to get cluster data: %s", err)
	}
	defer resp.Body.Close()
	var clusterResponse ClusterResponse
	dec = json.NewDecoder(resp.Body)
	err = dec.Decode(&clusterResponse)
	if err != nil {
		return nil, err
	}
	return genKubeConfig(accessTokenResponse.AccessToken, &clusterResponse)
}
