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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	log "github.com/sirupsen/logrus"
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
// Driver dataset is indexed by hash to provide more efficient
// lookups.
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

func (c *Client) MatchHash(filename string) (bool, Driver) {
	f, err := os.Open(filename)
	if err != nil {
		return c.matchFilename(filename)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err == nil {
		if (fi.Size() / 1024 / 1024) > maxFileSizeMB {
			log.Warnf("%s driver exceeds maximum allowed file size", filename)
			return c.matchFilename(filename)
		}
	}

	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return c.matchFilename(filename)
	}
	checksum := hex.EncodeToString(hash.Sum(nil))
	c.mu.Lock()
	defer c.mu.Unlock()
	return true, c.drivers[checksum]
}

func (c *Client) matchFilename(filename string) (bool, Driver) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, d := range c.drivers {
		if d.Filename == "" {
			continue
		}
		if strings.EqualFold(filepath.Base(filename), d.Filename) {
			return true, d
		}
	}
	return false, Driver{}
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

	for _, d := range drivers {
		for _, s := range d.KnownVulnerableSamples {
			c.drivers[s.SHA256] = Driver{
				Filename:     s.Filename,
				IsMalicious:  d.isMalicious(),
				IsVulnerable: !d.isMalicious(),
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
