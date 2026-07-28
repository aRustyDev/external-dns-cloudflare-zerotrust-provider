// Package cloudflare is a minimal client for the Cloudflare Zero Trust
// "Networks > Routes > Hostname Routes" API — the private-hostname routes that make a
// name resolve over WARP via the resolve-through-tunnel path.
//
// API reference:
//
//	List   GET    /accounts/{account_id}/zerotrust/routes/hostname
//	Create POST   /accounts/{account_id}/zerotrust/routes/hostname   {hostname, tunnel_id, comment}
//	Delete DELETE /accounts/{account_id}/zerotrust/routes/hostname/{id}
//
// It intentionally has no third-party dependencies so it stays trivially testable.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// DefaultBaseURL is the Cloudflare API v4 root.
const DefaultBaseURL = "https://api.cloudflare.com/client/v4"

// HostnameRoute is a Zero Trust private hostname route (hostname bound to a tunnel).
type HostnameRoute struct {
	ID         string     `json:"id"`
	Hostname   string     `json:"hostname"`
	TunnelID   string     `json:"tunnel_id"`
	TunnelName string     `json:"tunnel_name,omitempty"`
	TunType    string     `json:"tun_type,omitempty"`
	Comment    string     `json:"comment,omitempty"`
	CreatedAt  *time.Time `json:"created_at,omitempty"`
	DeletedAt  *time.Time `json:"deleted_at,omitempty"`
}

// Client talks to the Cloudflare Zero Trust hostname-routes API for one account.
type Client struct {
	AccountID  string
	BaseURL    string
	token      string
	httpClient *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithBaseURL overrides the API root (used in tests).
func WithBaseURL(u string) Option { return func(c *Client) { c.BaseURL = u } }

// WithHTTPClient overrides the underlying *http.Client.
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.httpClient = h } }

// New returns a Client authenticated with a scoped API token (recommended over a
// global API key: it can be limited to Account > Cloudflare Tunnel / Zero Trust edit).
func New(accountID, apiToken string, opts ...Option) *Client {
	c := &Client{
		AccountID:  accountID,
		BaseURL:    DefaultBaseURL,
		token:      apiToken,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// apiResponse is the standard Cloudflare envelope.
type apiResponse struct {
	Success    bool            `json:"success"`
	Errors     []apiError      `json:"errors"`
	Messages   []apiError      `json:"messages"`
	Result     json.RawMessage `json:"result"`
	ResultInfo *resultInfo     `json:"result_info,omitempty"`
}

type apiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type resultInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body any) (*apiResponse, error) {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}
	u := c.BaseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, reqBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	var out apiResponse
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, fmt.Errorf("decode response (status %d): %w", resp.StatusCode, err)
		}
	}
	if resp.StatusCode >= 300 || !out.Success {
		return &out, fmt.Errorf("cloudflare API %s %s: status %d: %s", method, path, resp.StatusCode, out.errString())
	}
	return &out, nil
}

func (r *apiResponse) errString() string {
	if len(r.Errors) == 0 {
		return "unknown error"
	}
	parts := make([]string, 0, len(r.Errors))
	for _, e := range r.Errors {
		parts = append(parts, fmt.Sprintf("[%d] %s", e.Code, e.Message))
	}
	return join(parts, "; ")
}

func join(parts []string, sep string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += sep
		}
		out += p
	}
	return out
}

func (c *Client) routesPath() string {
	return "/accounts/" + c.AccountID + "/zerotrust/routes/hostname"
}

// ListHostnameRoutes returns every hostname route bound to tunnelID (paginating fully).
// A blank tunnelID lists all routes in the account.
func (c *Client) ListHostnameRoutes(ctx context.Context, tunnelID string) ([]HostnameRoute, error) {
	var all []HostnameRoute
	page := 1
	for {
		q := url.Values{}
		if tunnelID != "" {
			q.Set("tunnel_id", tunnelID)
		}
		q.Set("page", strconv.Itoa(page))
		q.Set("per_page", "100")

		resp, err := c.do(ctx, http.MethodGet, c.routesPath(), q, nil)
		if err != nil {
			return nil, err
		}
		var batch []HostnameRoute
		if err := json.Unmarshal(resp.Result, &batch); err != nil {
			return nil, fmt.Errorf("decode routes: %w", err)
		}
		all = append(all, batch...)

		if resp.ResultInfo == nil || resp.ResultInfo.PerPage == 0 ||
			page*resp.ResultInfo.PerPage >= resp.ResultInfo.TotalCount || len(batch) == 0 {
			break
		}
		page++
	}
	return all, nil
}

type createRequest struct {
	Hostname string `json:"hostname"`
	TunnelID string `json:"tunnel_id"`
	Comment  string `json:"comment,omitempty"`
}

// CreateHostnameRoute binds hostname to tunnelID and returns the created route.
func (c *Client) CreateHostnameRoute(ctx context.Context, hostname, tunnelID, comment string) (*HostnameRoute, error) {
	resp, err := c.do(ctx, http.MethodPost, c.routesPath(), nil, createRequest{
		Hostname: hostname, TunnelID: tunnelID, Comment: comment,
	})
	if err != nil {
		return nil, err
	}
	var route HostnameRoute
	if err := json.Unmarshal(resp.Result, &route); err != nil {
		return nil, fmt.Errorf("decode created route: %w", err)
	}
	return &route, nil
}

// DeleteHostnameRoute removes the route with the given id.
func (c *Client) DeleteHostnameRoute(ctx context.Context, id string) error {
	_, err := c.do(ctx, http.MethodDelete, c.routesPath()+"/"+id, nil, nil)
	return err
}
