package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/containerd/containerd/log"
	"github.com/pkg/errors"
	"golang.org/x/net/context/ctxhttp"
)

var (
	// ErrNoToken is returned if a request is successful but the body does not
	// contain an authorization token.
	ErrNoToken = errors.New("authorization server did not include a token in the response")
)

// ErrUnexpectedStatus is returned if a token request returned with unexpected HTTP status
type ErrUnexpectedStatus struct {
	Status     string
	StatusCode int
	Body       []byte
}

func (e ErrUnexpectedStatus) Error() string {
	return fmt.Sprintf("unexpected status: %s", e.Status)
}

func newUnexpectedStatusErr(resp *http.Response) error {
	var b []byte
	if resp.Body != nil {
		b, _ = ioutil.ReadAll(io.LimitReader(resp.Body, 64000)) // 64KB
	}
	return ErrUnexpectedStatus{Status: resp.Status, StatusCode: resp.StatusCode, Body: b}
}

// GenerateTokenOptions generates options for fetching a token based on a challenge
func GenerateTokenOptions(ctx context.Context, host, username, secret string, c Challenge) (TokenOptions, error) {
	realm, ok := c.Parameters["realm"]
	if !ok {
		return TokenOptions{}, errors.New("no realm specified for token auth challenge")
	}

	realmURL, err := url.Parse(realm)
	if err != nil {
		return TokenOptions{}, errors.Wrap(err, "invalid token auth challenge realm")
	}

	to := TokenOptions{
		Realm:    realmURL.String(),
		Service:  c.Parameters["service"],
		Username: username,
		Secret:   secret,
	}

	scope, ok := c.Parameters["scope"]
	if ok {
		to.Scopes = append(to.Scopes, scope)
	} else {
		log.G(ctx).WithField("host", host).Debug("no scope specified for token auth challenge")
	}

	return to, nil
}

// TokenOptions are optios for requesting a token
type TokenOptions struct {
	Realm    string
	Service  string
	Scopes   []string
	Username string
	Secret   string
}

// OAuthTokenResponse is response from fetching token with a OAuth POST request
type OAuthTokenResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresIn    int       `json:"expires_in"`
	IssuedAt     time.Time `json:"issued_at"`
	Scope        string    `json:"scope"`
}

// FetchTokenWithOAuth fetches a token using a POST request
func FetchTokenWithOAuth(ctx context.Context, client *http.Client, headers http.Header, clientID string, to TokenOptions) (*OAuthTokenResponse, error) {
	form := url.Values{}
	if len(to.Scopes) > 0 {
		form.Set("scope", strings.Join(to.Scopes, " "))
	}
	form.Set("service", to.Service)
	form.Set("client_id", clientID)

	if to.Username == "" {
		form.Set("grant_type", "refresh_token")
		form.Set("refresh_token", to.Secret)
	} else {
		form.Set("grant_type", "password")
		form.Set("username", to.Username)
		form.Set("password", to.Secret)
	}

	req, err := http.NewRequest("POST", to.Realm, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	if headers != nil {
		for k, v := range headers {
			req.Header[k] = append(req.Header[k], v...)
		}
	}

	resp, err := ctxhttp.Do(ctx, client, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return nil, errors.WithStack(newUnexpectedStatusErr(resp))
	}

	decoder := json.NewDecoder(resp.Body)

	var tr OAuthTokenResponse
	if err = decoder.Decode(&tr); err != nil {
		return nil, errors.Wrap(err, "unable to decode token response")
	}

	if tr.AccessToken == "" {
		return nil, errors.WithStack(ErrNoToken)
	}

	return &tr, nil
}

// FetchTokenResponse is response from fetching token with GET request
type FetchTokenResponse struct {
	Token        string    `json:"token"`
	AccessToken  string    `json:"access_token"`
	ExpiresIn    int       `json:"expires_in"`
	IssuedAt     time.Time `json:"issued_at"`
	RefreshToken string    `json:"refresh_token"`
}

// FetchToken fetches a token using a GET request
func FetchToken(ctx context.Context, client *http.Client, headers http.Header, to TokenOptions) (*FetchTokenResponse, error) {
	req, err := http.NewRequest("GET", to.Realm, nil)
	if err != nil {
		return nil, err
	}

	if headers != nil {
		for k, v := range headers {
			req.Header[k] = append(req.Header[k], v...)
		}
	}

	reqParams := req.URL.Query()

	if to.Service != "" {
		reqParams.Add("service", to.Service)
	}

	for _, scope := range to.Scopes {
		reqParams.Add("scope", scope)
	}

	if to.Secret != "" {
		req.SetBasicAuth(to.Username, to.Secret)
	}

	req.URL.RawQuery = reqParams.Encode()

	resp, err := ctxhttp.Do(ctx, client, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return nil, errors.WithStack(newUnexpectedStatusErr(resp))
	}

	decoder := json.NewDecoder(resp.Body)

	var tr FetchTokenResponse
	if err = decoder.Decode(&tr); err != nil {
		return nil, errors.Wrap(err, "unable to decode token response")
	}

	// `access_token` is equivalent to `token` and if both are specified
	// the choice is undefined.  Canonicalize `access_token` by sticking
	// things in `token`.
	if tr.AccessToken != "" {
		tr.Token = tr.AccessToken
	}

	if tr.Token == "" {
		return nil, errors.WithStack(ErrNoToken)
	}

	return &tr, nil
}
