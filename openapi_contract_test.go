// Copyright 2026 Paul Greenberg greenpau@outlook.com
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

package security

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

const (
	openAPIContractModule = "github.com/greenpau/go-authcrunch"
	openAPIContractOrigin = "https://authcrunch-contract.invalid/"
	openAPIContractLimit  = 4 << 20
)

// This is a selected-operation consumer, not an OpenAPI bundler or a runtime
// dependency. It keeps authored documents intact and lets the public JSON Schema
// compiler resolve schema fragments through an exclusively local loader.
type openAPIContracts struct {
	mu       sync.Mutex // The compiler and its caches are mutable, including during compilation.
	docs     map[string]any
	compiler *jsonschema.Compiler
	schemas  map[string]*jsonschema.Schema
	version  string
	digest   string
	module   openAPIContractModuleInfo
}

type openAPIContractModuleInfo struct {
	Path    string
	Version string
	Dir     string
	Replace *openAPIContractModuleInfo
	Error   json.RawMessage
}

var selectedOpenAPIContracts struct {
	sync.Once
	contracts *openAPIContracts
	err       error
}

func newOpenAPIContracts(t testing.TB) *openAPIContracts {
	t.Helper()
	selectedOpenAPIContracts.Do(func() {
		module, err := resolveOpenAPIContractModule()
		if err != nil {
			selectedOpenAPIContracts.err = err
			return
		}
		selectedOpenAPIContracts.contracts, selectedOpenAPIContracts.err = loadOpenAPIContracts(filepath.Join(module.Dir, "assets", "openapi", "content"))
		if selectedOpenAPIContracts.err == nil {
			selectedOpenAPIContracts.contracts.module = module
		}
	})
	if selectedOpenAPIContracts.err != nil {
		t.Fatalf("OpenAPI authored contract unavailable: %v", selectedOpenAPIContracts.err)
	}
	c := selectedOpenAPIContracts.contracts
	// A replacement's nominal version is not an immutable source revision. The
	// digest covers the actual complete authored YAML snapshot used by this test.
	t.Logf("OpenAPI source: module=%s selected_version=%q replacement=%t directory=%q info.version=%q authored_sha256=%s", openAPIContractModule, c.module.Version, c.module.Replace != nil, c.module.Dir, c.version, c.digest)
	return c
}

type openAPIContractOutput struct{ bytes.Buffer }

func (b *openAPIContractOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 1<<20 {
		return 0, errors.New("module metadata exceeded limit")
	}
	return b.Buffer.Write(p)
}

func resolveOpenAPIContractModule() (openAPIContractModuleInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "list", "-mod=readonly", "-m", "-json", openAPIContractModule)
	cmd.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local")
	cmd.WaitDelay = time.Second
	var output openAPIContractOutput
	cmd.Stdout, cmd.Stderr = &output, io.Discard
	if err := cmd.Run(); err != nil {
		return openAPIContractModuleInfo{}, errors.New("selected module resolution failed")
	}
	return parseOpenAPIContractModule(output.Bytes())
}

func parseOpenAPIContractModule(data []byte) (openAPIContractModuleInfo, error) {
	var m openAPIContractModuleInfo
	decoder := json.NewDecoder(bytes.NewReader(data))
	if decoder.Decode(&m) != nil || decoder.Decode(new(any)) != io.EOF || m.Path != openAPIContractModule || len(m.Error) != 0 {
		return m, errors.New("invalid selected module metadata")
	}
	if m.Replace != nil {
		if len(m.Replace.Error) != 0 {
			return m, errors.New("invalid replacement module metadata")
		}
		m.Dir = m.Replace.Dir
	}
	if !filepath.IsAbs(m.Dir) {
		return m, errors.New("selected module has no absolute source directory")
	}
	return m, nil
}

func loadOpenAPIContracts(directory string) (*openAPIContracts, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, errors.New("authored content directory is unavailable")
	}
	defer root.Close()
	c := &openAPIContracts{docs: make(map[string]any), schemas: make(map[string]*jsonschema.Schema)}
	hash := sha256.New()
	total := 0
	// WalkDir is lexical. Root.Open prevents an entry changing into a symlink
	// from escaping the chosen content directory between inspection and reading.
	err = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("authored content contains an unreadable or symbolic entry")
		}
		if entry.IsDir() {
			return nil
		}
		if path.Ext(name) != ".yaml" {
			return nil
		}
		if !entry.Type().IsRegular() || len(c.docs) >= 4096 {
			return errors.New("authored content file inventory is invalid")
		}
		file, err := root.Open(name)
		if err != nil {
			return errors.New("authored content file cannot be opened")
		}
		data, readErr := io.ReadAll(io.LimitReader(file, openAPIContractLimit+1))
		closeErr := file.Close()
		total += len(data)
		if readErr != nil || closeErr != nil || len(data) > openAPIContractLimit || total > 16<<20 {
			return errors.New("authored content read limit exceeded")
		}
		doc, err := decodeOpenAPIYAML(data)
		if err != nil {
			return err
		}
		if err := auditOpenAPIReferences(name, doc); err != nil {
			return err
		}
		c.docs[name] = doc
		hash.Write([]byte(name))
		hash.Write([]byte{0})
		hash.Write(data)
		hash.Write([]byte{0})
		return nil
	})
	if err != nil {
		return nil, err
	}
	rootDoc, ok := c.docs["openapi.yaml"].(map[string]any)
	if !ok || rootDoc["openapi"] != "3.1.1" {
		return nil, errors.New("unsupported or missing OpenAPI root")
	}
	info, _ := rootDoc["info"].(map[string]any)
	c.version, _ = info["version"].(string)
	if c.version == "" {
		return nil, errors.New("OpenAPI source version is missing")
	}
	c.digest = hex.EncodeToString(hash.Sum(nil))
	c.compiler = jsonschema.NewCompiler()
	c.compiler.DefaultDraft(jsonschema.Draft2020)
	c.compiler.AssertFormat()
	c.compiler.UseLoader(c)
	return c, nil
}

func decodeOpenAPIYAML(data []byte) (any, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if decoder.Decode(&doc) != nil || len(doc.Content) != 1 || decoder.Decode(new(yaml.Node)) != io.EOF {
		return nil, errors.New("authored YAML must contain one document")
	}
	return openAPIYAMLValue(doc.Content[0], 0)
}

func openAPIYAMLValue(node *yaml.Node, depth int) (any, error) {
	if depth > 100 || node.Anchor != "" || node.Kind == yaml.AliasNode {
		return nil, errors.New("unsupported authored YAML nesting or alias")
	}
	switch node.Kind {
	case yaml.MappingNode:
		out := make(map[string]any, len(node.Content)/2)
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Anchor != "" {
				return nil, errors.New("authored YAML object key is not a string")
			}
			if _, exists := out[key.Value]; exists {
				return nil, errors.New("authored YAML object contains duplicate keys")
			}
			value, err := openAPIYAMLValue(node.Content[i+1], depth+1)
			if err != nil {
				return nil, err
			}
			out[key.Value] = value
		}
		return out, nil
	case yaml.SequenceNode:
		out := make([]any, len(node.Content))
		for i, child := range node.Content {
			value, err := openAPIYAMLValue(child, depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = value
		}
		return out, nil
	case yaml.ScalarNode:
		switch node.Tag {
		case "!!str":
			return node.Value, nil
		case "!!null":
			if node.Value == "" || node.Value == "~" || strings.EqualFold(node.Value, "null") {
				return nil, nil
			}
		case "!!bool":
			if strings.EqualFold(node.Value, "true") || strings.EqualFold(node.Value, "false") {
				return strings.EqualFold(node.Value, "true"), nil
			}
		case "!!int", "!!float":
			// YAML integers must not pass through float64 before JSON Schema sees
			// them. Unsupported YAML-only numeric notation is rejected explicitly.
			value, err := jsonschema.UnmarshalJSON(strings.NewReader(node.Value))
			if _, ok := value.(json.Number); err == nil && ok {
				return value, nil
			}
		}
	}
	return nil, errors.New("unsupported authored YAML value")
}

type openAPIContractNode struct {
	file    string
	pointer string
	value   any
}

func (n openAPIContractNode) child(key string) openAPIContractNode {
	object, _ := n.value.(map[string]any)
	return openAPIContractNode{n.file, n.pointer + "/" + strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1"), object[key]}
}

func openAPIReference(base, ref string) (string, string, error) {
	u, err := url.Parse(ref)
	if err != nil || u.IsAbs() || u.Host != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.ContainsAny(ref, "\\\x00") || strings.HasPrefix(u.Path, "/") || strings.Contains(u.RawPath, "%") {
		return "", "", errors.New("authored reference must be a contained local path")
	}
	file := base
	if u.Path != "" {
		file = path.Clean(path.Join(path.Dir(base), u.Path))
	}
	if !fs.ValidPath(file) || path.Ext(file) != ".yaml" || (u.Fragment != "" && !strings.HasPrefix(u.Fragment, "/")) {
		return "", "", errors.New("authored reference escapes content or has an unsupported fragment")
	}
	for _, token := range strings.Split(u.Fragment, "/") {
		for i := 0; i < len(token); i++ {
			if token[i] == '~' {
				i++
				if i == len(token) || (token[i] != '0' && token[i] != '1') {
					return "", "", errors.New("authored reference has an invalid JSON pointer")
				}
			}
		}
	}
	return file, u.Fragment, nil
}

func auditOpenAPIReferences(file string, value any) error {
	switch object := value.(type) {
	case map[string]any:
		for key, child := range object {
			if strings.HasPrefix(key, "x-") {
				continue
			}
			switch key {
			case "example", "examples", "default", "enum", "const":
				continue // Literal values are not schema references.
			case "$id", "$schema", "$dynamicRef", "$recursiveRef":
				return errors.New("unsupported authored schema resource directive")
			case "$ref":
				ref, ok := child.(string)
				if !ok {
					return errors.New("authored reference is not a string")
				}
				if _, _, err := openAPIReference(file, ref); err != nil {
					return err
				}
				continue
			case "properties", "patternProperties", "$defs", "dependentSchemas", "schemas", "paths", "responses", "content", "headers":
				// Keys in these maps are names, not schema keywords. A property
				// named "$ref", for example, is an ordinary application field.
				if entries, ok := child.(map[string]any); ok {
					for _, entry := range entries {
						if err := auditOpenAPIReferences(file, entry); err != nil {
							return err
						}
					}
					continue
				}
			}
			if err := auditOpenAPIReferences(file, child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range object {
			if err := auditOpenAPIReferences(file, child); err != nil {
				return err
			}
		}
	}
	return nil
}

// Load implements jsonschema.URLLoader. There is deliberately no network or
// filesystem fallback: every resource comes from the bounded authored snapshot.
func (c *openAPIContracts) Load(location string) (any, error) {
	u, err := url.Parse(location)
	if err != nil || u.Scheme != "https" || u.Host != "authcrunch-contract.invalid" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("schema resource is outside the authored snapshot")
	}
	file := strings.TrimPrefix(u.Path, "/")
	if !fs.ValidPath(file) {
		return nil, errors.New("invalid schema resource path")
	}
	doc, ok := c.docs[file]
	if !ok {
		return nil, errors.New("authored schema resource is missing")
	}
	return doc, nil
}

func (c *openAPIContracts) dereference(node openAPIContractNode) (openAPIContractNode, error) {
	seen := make(map[string]bool)
	for range 32 {
		object, ok := node.value.(map[string]any)
		if !ok {
			return node, errors.New("authored contract object is missing")
		}
		ref, isRef := object["$ref"].(string)
		if !isRef {
			return node, nil
		}
		for key := range object {
			if key != "$ref" && key != "summary" && key != "description" {
				return node, errors.New("unsupported structural reference siblings")
			}
		}
		file, pointer, err := openAPIReference(node.file, ref)
		if err != nil {
			return node, err
		}
		key := file + "#" + pointer
		if seen[key] {
			return node, errors.New("cyclic structural contract reference")
		}
		seen[key] = true
		node = openAPIContractNode{file, pointer, c.docs[file]}
		if pointer != "" {
			for _, part := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
				part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
				switch value := node.value.(type) {
				case map[string]any:
					node.value = value[part]
				case []any:
					i, err := strconv.Atoi(part)
					if err != nil || i < 0 || i >= len(value) || strconv.Itoa(i) != part {
						return node, errors.New("authored contract pointer is missing")
					}
					node.value = value[i]
				default:
					return node, errors.New("authored contract pointer is missing")
				}
			}
		}
	}
	return node, errors.New("structural contract reference limit exceeded")
}

func (c *openAPIContracts) operation(method, operationPath string) (openAPIContractNode, error) {
	root := openAPIContractNode{file: "openapi.yaml", value: c.docs["openapi.yaml"]}
	item, err := c.dereference(root.child("paths").child(operationPath))
	if err != nil {
		return item, errors.New("operation path is undocumented")
	}
	operation := item.child(strings.ToLower(method))
	if _, ok := operation.value.(map[string]any); !ok {
		return operation, errors.New("operation method is undocumented")
	}
	return operation, nil
}

func (c *openAPIContracts) validate(node openAPIContractNode, value any) error {
	if _, ok := node.value.(map[string]any); !ok {
		if _, ok := node.value.(bool); !ok {
			return errors.New("documented media has no schema")
		}
	}
	location := openAPIContractOrigin + node.file + "#" + node.pointer
	schema := c.schemas[location]
	if schema == nil {
		var err error
		schema, err = c.compiler.Compile(location)
		if err != nil {
			return errors.New("authored schema could not be compiled")
		}
		c.schemas[location] = schema
	}
	if schema.Validate(value) != nil {
		// JSON Schema errors contain instance values. Never expose them to test
		// logs, which may otherwise disclose passwords, cookies or signed tokens.
		return errors.New("body does not satisfy the documented schema")
	}
	return nil
}

func openAPIContent(content openAPIContractNode, headers http.Header) (string, openAPIContractNode, error) {
	values := headers.Values("Content-Type")
	if len(values) != 1 {
		return "", content, errors.New("one documented content type is required")
	}
	media, _, err := mime.ParseMediaType(values[0])
	if err != nil {
		return "", content, errors.New("response or request content type is invalid")
	}
	entry := content.child(media)
	if entry.value == nil {
		return "", entry, errors.New("response or request media type is undocumented")
	}
	return media, entry.child("schema"), nil
}

func openAPIBody(media string, body []byte, jsonText bool) (any, error) {
	if len(body) > openAPIContractLimit {
		return nil, errors.New("contract body limit exceeded")
	}
	if media == "application/json" || strings.HasSuffix(media, "+json") || jsonText {
		value, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
		if err != nil {
			return nil, errors.New("body is not one complete JSON value")
		}
		return value, nil
	}
	if media == "text/html" || media == "text/plain" {
		return string(body), nil
	}
	return nil, errors.New("documented media is outside this consumer's supported subset")
}

func (c *openAPIContracts) checkResponse(method, operationPath string, status int, headers http.Header, body []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	operation, err := c.operation(method, operationPath)
	if err != nil {
		return err
	}
	response, err := c.dereference(operation.child("responses").child(strconv.Itoa(status)))
	if err != nil {
		return errors.New("response status is undocumented or unresolved")
	}
	content := response.child("content")
	if method == http.MethodHead {
		if len(body) != 0 {
			return errors.New("HEAD response must be bodyless")
		}
		// JWKS HEAD intentionally has headers and no content schema. Its
		// representation headers are compared with GET by the HTTP consumer.
		if operationPath == "/.well-known/jwks.json" && content.value == nil {
			return nil
		}
		return errors.New("HEAD contract is outside this consumer's supported subset")
	}
	if content.value == nil {
		// These explicitly documented discovery failures are empty responses,
		// not permission to ignore a missing schema on an ordinary operation.
		if operationPath == "/.well-known/jwks.json" && (status == 404 || status == 405 || status == 500) && len(body) == 0 {
			return nil
		}
		return errors.New("response has no documented content schema")
	}
	if status >= 300 && status < 400 && len(body) == 0 && content.child("text/html").value != nil && response.child("headers").child("Location").value != nil {
		if headers.Get("Location") == "" {
			return errors.New("empty redirect requires a destination")
		}
		if len(headers.Values("Content-Type")) == 0 {
			return c.validate(content.child("text/html").child("schema"), "")
		}
	}
	media, schema, err := openAPIContent(content, headers)
	if err != nil {
		return err
	}
	var value any
	if method == http.MethodGet && operationPath == "/beacon" && status == 200 && media == "application/json" {
		if string(body) != "OK" {
			return errors.New("beacon success body must be the literal unquoted marker")
		}
		value = "OK"
	} else {
		value, err = openAPIBody(media, body, method == http.MethodGet && operationPath == "/api/server/metadata" && status == 200 && media == "text/plain")
		if err != nil {
			return err
		}
	}
	return c.validate(schema, value)
}

func (c *openAPIContracts) checkRequest(method, operationPath string, headers http.Header, body []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	operation, err := c.operation(method, operationPath)
	if err != nil {
		return err
	}
	request, err := c.dereference(operation.child("requestBody"))
	if err != nil {
		return errors.New("operation has no documented request body")
	}
	media, schema, err := openAPIContent(request.child("content"), headers)
	if err != nil {
		return err
	}
	value, err := openAPIBody(media, body, false)
	if err != nil {
		return err
	}
	return c.validate(schema, value)
}

func (c *openAPIContracts) checkComponent(name string, body []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	root := openAPIContractNode{file: "openapi.yaml", value: c.docs["openapi.yaml"]}
	schema := root.child("components").child("schemas").child(name)
	if schema.value == nil {
		return errors.New("schema component is undocumented")
	}
	value, err := openAPIBody("application/json", body, false)
	if err != nil {
		return err
	}
	return c.validate(schema, value)
}

func (c *openAPIContracts) AssertResponse(t testing.TB, method, operationPath string, status int, headers http.Header, body []byte) {
	t.Helper()
	if err := c.checkResponse(method, operationPath, status, headers, body); err != nil {
		t.Fatalf("OpenAPI response contract failed (status %d): %v", status, err)
	}
}

func (c *openAPIContracts) AssertRequest(t testing.TB, method, operationPath string, headers http.Header, body []byte) {
	t.Helper()
	if err := c.checkRequest(method, operationPath, headers, body); err != nil {
		t.Fatalf("OpenAPI request contract failed: %v", err)
	}
}

func (c *openAPIContracts) AssertComponent(t testing.TB, name string, body []byte) {
	t.Helper()
	if err := c.checkComponent(name, body); err != nil {
		t.Fatalf("OpenAPI component contract failed: %v", err)
	}
}

var _ jsonschema.URLLoader = (*openAPIContracts)(nil)
