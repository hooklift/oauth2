// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package render

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

// Options represents the set of values to pass when rendering content.
type Options struct {
	// HTTP status to return
	Status int
	// Content to serialize
	Data interface{}
	// Whether or not to cache the response
	Cache bool
}

// JSON renders JSON content and sends it to the HTTP client. It supports caching.
func JSON(w http.ResponseWriter, opts Options) error {
	if &w == nil {
		return fmt.Errorf("You must provide a valid http.ResponseWriter")
	}

	headers := w.Header()
	headers.Set("Content-Type", "application/json; charset=utf-8")

	if opts.Cache {
		headers.Set("Cache-Control", "no-cache, no-store, must-revalidate")
		headers.Set("Pragma", "no-cache")
		headers.Set("Expires", "0")
	}

	jsonBytes, err := json.Marshal(opts.Data)
	if err != nil {
		return err
	}

	headers.Set("Content-Length", strconv.Itoa(len(jsonBytes)))
	if opts.Status <= 0 {
		opts.Status = http.StatusOK
	}
	w.WriteHeader(opts.Status)
	w.Write(jsonBytes)

	return nil
}
