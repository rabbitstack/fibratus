/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
 * https://www.fibratus.io
 * All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package loldrivers

import (
	"context"
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// apiURL represents the default loldrivers API endpoint
const apiURL = "https://www.loldrivers.io/api/drivers.json"

// maxFileSizeMB specifies the maximum allowed size of the driver file
// for which the hash is calculated.
const maxFileSizeMB = 40

// Client is responsible for downloading loldrivers dataset.
// Driver dataset is indexed by SHA hash to provide more
// efficient lookups.
type Client struct {
	drivers map[string]Driver
	mu      sync.Mutex
	tick    *time.Ticker
	options opts
}

type opts struct {
	apiURL          string
	refreshInterval time.Duration
}

// Option represents the option for the loldrivers client.
type Option func(o *opts)

// WithURL sets the API endpoint.
func WithURL(url string) Option {
	return func(o *opts) {
		o.apiURL = url
	}
}

// WithRefresh sets the refresh interval for loldrivers dataset.
func WithRefresh(interval time.Duration) Option {
	return func(o *opts) {
		o.refreshInterval = interval
	}
}

var client *Client

// GetClient constructs a singleton instance of the loldrivers client.
func GetClient(options ...Option) *Client {
	if client == nil {
		var opts opts
		for _, opt := range options {
			opt(&opts)
		}

		if opts.apiURL == "" {
			opts.apiURL = apiURL
		}
		if opts.refreshInterval == 0 {
			opts.refreshInterval = time.Hour
		}

		client = &Client{
			options: opts,
			drivers: make(map[string]Driver),
			tick:    time.NewTicker(opts.refreshInterval),
		}
		err := client.download()
		if err != nil {
			log.Warnf("unable to download loldrivers.io dataset: %v", err)
		}

		go client.refresh()
	}
	return client
}

func (c *Client) MatchHash(path string) (bool, Driver) {
	f, err := os.Open(path)
	if err != nil {
		return c.matchPath(path)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err == nil {
		if (fi.Size() / 1024 / 1024) > maxFileSizeMB {
			log.Warnf("%s driver exceeds maximum allowed file size", path)
			return c.matchPath(path)
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	ok, driver := c.matchHash(crypto.SHA256, f, path)
	if !ok {
		// the driver doesn't have SHA256 hash, try with SHA1 hash
		return c.matchHash(crypto.SHA1, f, path)
	}
	return ok, driver
}

func (c *Client) matchHash(h crypto.Hash, r io.Reader, path string) (bool, Driver) {
	checksum, err := c.calculateHash(h, r)
	if err != nil {
		return c.matchPath(path)
	}
	driver, ok := c.drivers[strings.ToLower(checksum)]
	return ok, driver
}

func (c *Client) matchPath(path string) (bool, Driver) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, d := range c.drivers {
		if d.Filename == "" {
			continue
		}
		if strings.EqualFold(filepath.Base(path), d.Filename) {
			return true, d
		}
	}
	return false, Driver{}
}

func (c *Client) calculateHash(h crypto.Hash, r io.Reader) (string, error) {
	var w hash.Hash
	switch h {
	case crypto.SHA1:
		w = sha1.New()
	case crypto.SHA256:
		w = sha256.New()
	default:
		return "", fmt.Errorf("%v: invalid hash", h)
	}
	if _, err := io.Copy(w, r); err != nil {
		return "", err
	}
	return strings.ToLower(hex.EncodeToString(w.Sum(nil))), nil
}

func (c *Client) Drivers() []Driver {
	c.mu.Lock()
	defer c.mu.Unlock()
	drivers := make([]Driver, 0, len(c.drivers))
	for _, d := range c.drivers {
		drivers = append(drivers, d)
	}
	return drivers
}

func (c *Client) download() error {
	client := http.Client{
		Timeout: time.Second * 10,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", c.options.apiURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var drivers []RawDriver
	if err := json.Unmarshal(body, &drivers); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.drivers = make(map[string]Driver)

	for _, driver := range drivers {
		for _, sample := range driver.KnownVulnerableSamples {
			c.drivers[sample.SHA256] = Driver{
				Filename:     sample.Filename,
				SHA1:         strings.ToLower(sample.SHA1),
				SHA256:       strings.ToLower(sample.SHA256),
				IsMalicious:  driver.isMalicious(),
				IsVulnerable: !driver.isMalicious(),
			}
		}
	}

	return nil
}

func (c *Client) refresh() {
	for {
		<-c.tick.C
		err := c.download()
		if err != nil {
			log.Warnf("unable to refresh loldrivers dataset: %v", err)
		}
	}
}
