// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package apivalidation

import "testing"

func TestCredentialURIValidation(t *testing.T) {
	for _, uri := range []string{
		"ate-secret://kubernetes.io/provider/ns/name",
		"ate-secret://vault.example/provider/secret",
	} {
		if !validCredentialURI(uri) {
			t.Errorf("validCredentialURI(%q) = false", uri)
		}
	}
	for _, uri := range []string{
		"https://kubernetes.io/provider/ns/name",
		"ate-secret://kubernetes.io/provider",
		"ate-secret://kubernetes.io//provider/secret",
		"ate-secret://kubernetes.io/provider/secret/",
		"ate-secret://kubernetes.io:443/provider/secret",
		"ate-secret://kubernetes.io/provider/sec%2Fret", // percent-encoded separator
		"ate-secret://kubernetes.io/provider/sec%2Dret", // percent-encoding of any kind
	} {
		if validCredentialURI(uri) {
			t.Errorf("validCredentialURI(%q) = true", uri)
		}
	}
}

func TestHeaderValueValidation(t *testing.T) {
	for _, value := range []string{"Bearer token", "value\tvalue", "\u0080\u0081"} {
		if !validHeaderValue(value) {
			t.Errorf("validHeaderValue(%q) = false", value)
		}
	}
	for _, value := range []string{"a\rb", "a\nb", "a\x00b", "a\x1fb", "a\x7fb"} {
		if validHeaderValue(value) {
			t.Errorf("validHeaderValue(%q) = true", value)
		}
	}
}

func TestHeaderNameValidation(t *testing.T) {
	for _, value := range []string{"Authorization", "x-custom_header", "!#$%&'*+-.^_`|~"} {
		if !validHeaderName(value) {
			t.Errorf("validHeaderName(%q) = false", value)
		}
	}
	for _, value := range []string{"", "bad header", "bad:header", "héader"} {
		if validHeaderName(value) {
			t.Errorf("validHeaderName(%q) = true", value)
		}
	}
}
