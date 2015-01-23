// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package render

import (
	"bytes"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"strconv"
)

// Errors
var (
	ErrNilResponseWriter = errors.New("You must provide a valid http.ResponseWriter")
	ErrNilHTMLTemplate   = errors.New("You must provide a valid HTML template")
)

// Options represents the set of values to pass when rendering content.
type Options struct {
	// HTTP status to return.
	Status int
	// Content to serialize.
	Data interface{}
	// When rendering HTML, a HTML template is required.
	Template *template.Template
	// Whether or not to cache the response, defaults to false.
	Cache bool
}

func cache(headers http.Header, opts Options) {
	if opts.Cache {
		headers.Set("Cache-Control", "no-store")
		headers.Set("Pragma", "no-cache")
		headers.Set("Expires", "0")
	}
}

// JSON renders JSON content and sends it back to the HTTP client.
func JSON(w http.ResponseWriter, opts Options) error {
	if &w == nil {
		return ErrNilResponseWriter
	}

	headers := w.Header()
	headers.Set("Content-Type", "application/json; charset=utf-8")
	cache(headers, opts)

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

// HTML renders HTML content and sends it back to the HTTP client.
func HTML(w http.ResponseWriter, opts Options) error {
	if &w == nil {
		return ErrNilResponseWriter
	}

	if opts.Template == nil {
		return ErrNilHTMLTemplate
	}

	headers := w.Header()
	headers.Set("Content-Type", "text/html; charset=utf-8")
	cache(headers, opts)

	if opts.Status <= 0 {
		opts.Status = http.StatusOK
	}

	buf := new(bytes.Buffer)
	opts.Template.Execute(buf, opts.Data)

	headers.Set("Content-Length", strconv.Itoa(buf.Len()))
	w.WriteHeader(opts.Status)
	w.Write(buf.Bytes())

	return nil
}
