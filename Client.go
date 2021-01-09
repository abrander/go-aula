package aula

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/html"
)

const sessionCookieName = "PHPSESSID"

// Client is a client for accessing the unofficial Aula API.
type Client struct {
	client     *http.Client
	dumpWriter io.Writer

	SessionCookie string `json:"session_cookie"`
}

// Option is the type to set options on the client.
type Option func(*Client)

// SessionCookie will set a predefined session ID. This can be useful
// for clients keeping state. Quite a few HTTP roundtrips can be saved,
// if the session ID is reused. And some load would be taken of Aula
// servers.
// Generally this should not be used. Users of this package should save
// all exported fields from Client and re-use those at a later request.
// json.Marshal() and json.Unmarshal() can be used.
func SessionCookie(sessionCookie string) Option {
	return func(c *Client) {
		c.SessionCookie = sessionCookie
	}
}

// DumpWriter will instruct Client to dump all HTTP requests and
// responses to and from Aula to w.
func DumpWriter(w io.Writer) Option {
	return func(c *Client) {
		c.dumpWriter = w
	}
}

// NewClient returns a new client for accessing the unofficial Aula
// API.
func NewClient(options ...Option) *Client {
	c := &Client{
		client: &http.Client{
			// Do not follow redirects. We would like to control these
			// ourselfes to catch cookies.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}

	c.SetOptions(options...)

	return c
}

// SetOptions can be used to set various options on Client.
func (c *Client) SetOptions(options ...Option) {
	for _, option := range options {
		option(c)
	}
}

func (c *Client) newRequest(method string, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	if c.SessionCookie != "" {
		req.AddCookie(&http.Cookie{
			Value: c.SessionCookie,
			Name:  sessionCookieName,
		})
	}

	// Play nice and give Aula engineers a way to contact us.
	req.Header.Set("User-Agent", "github.com/abrander/go-aula")

	return req, nil
}

func (c *Client) getJSON(url string, target interface{}) error {
	req, err := c.newRequest("GET", url, nil)
	if err != nil {
		return err
	}

	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)

	return decoder.Decode(target)
}

func (c *Client) dump(reqResp interface{}) {
	if c.dumpWriter == nil {
		return
	}

	var dump []byte
	switch obj := reqResp.(type) {
	case *http.Request:
		_, _ = c.dumpWriter.Write([]byte("\n\nREQUEST\n"))
		dump, _ = httputil.DumpRequestOut(obj, true)
	case *http.Response:
		_, _ = c.dumpWriter.Write([]byte("\n\nRESPONSE\n"))
		dump, _ = httputil.DumpResponse(obj, true)
	default:
		panic("unsupported type")
	}

	_, _ = c.dumpWriter.Write(dump)
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	c.dump(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	c.dump(resp)

	return resp, err
}

// Authenticate will try to authenticate the user. Currently no error
// checking what so ever is done.
func (c *Client) Authenticate(username string, password string) error {
	max := 15

	const loginEntry = "https://login.aula.dk/auth/login.php?type=unilogin"

	var err error
	var req *http.Request
	var resp *http.Response

	var authSessionCookie *http.Cookie
	var kcRestartCookie *http.Cookie

	req, err = c.newRequest("GET", loginEntry, nil)
	if err != nil {
		return err
	}

	for {
		max--

		if max < 0 {
			err = fmt.Errorf("Authenticate failed")

			goto EXIT
		}

		if authSessionCookie != nil {
			req.AddCookie(authSessionCookie)
		}

		if kcRestartCookie != nil {
			req.AddCookie(kcRestartCookie)
		}

		resp, err = c.do(req)
		if err != nil {
			return err
		}

		// We try to sleep some to play nice and not hammer the backend.
		time.Sleep(50 * time.Millisecond)

		for _, cookie := range resp.Cookies() {
			if cookie.Name == "AUTH_SESSION_ID" {
				authSessionCookie = cookie
			}

			if cookie.Name == "KC_RESTART" {
				kcRestartCookie = cookie
			}

			// We receive multiples of these, only use the last one.
			if cookie.Name == sessionCookieName {
				c.SessionCookie = cookie.Value
			}
		}

		if resp.StatusCode == http.StatusSeeOther || resp.StatusCode == 302 {
			location := resp.Header.Get("location")
			if location == "/" {
				goto EXIT
			}

			req, err = c.newRequest("GET", location, nil)
			if err != nil {
				goto EXIT
			}

			resp.Body.Close()

			continue
		}

		doc, err := html.Parse(resp.Body)
		if err != nil {
			goto EXIT
		}

		// attrValue retrieves a value of a html node's attribute.
		attrValue := func(n *html.Node, key string) string {
			for _, a := range n.Attr {
				if a.Key == key {
					return a.Val
				}
			}

			return ""
		}

		action := ""
		formData := url.Values{}

		var f func(*html.Node)
		f = func(n *html.Node) {
			if n.Data == "form" {
				action = attrValue(n, "action")
			}

			if n.Data == "input" {
				formData[attrValue(n, "name")] = []string{attrValue(n, "value")}
			}

			for c := n.FirstChild; c != nil; c = c.NextSibling {
				f(c)
			}
		}
		f(doc)

		if action != "" {
			for name := range formData {
				if name == "username" {
					formData["username"] = []string{username}
				}

				if name == "password" {
					formData["password"] = []string{password}
				}
			}

			req, err = c.newRequest("POST", action, strings.NewReader(formData.Encode()))
			if err != nil {
				goto EXIT
			}

			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			resp.Body.Close()

			continue
		}

		break
	}

	return nil

EXIT:
	resp.Body.Close()

	return err
}

// Logout will end the session with Aula.
func (c *Client) Logout() error {
	URL := "https://login.aula.dk/auth/logout.php"

	req, err := c.newRequest("GET", URL, nil)
	if err != nil {
		return err
	}

	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	c.SessionCookie = ""

	return nil
}
