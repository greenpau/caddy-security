// Copyright 2022 Paul Greenberg greenpau@outlook.com
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
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"unicode"
)

func writeSecurityLocalResponse(w io.Writer, operation, format string, data []byte) error {
	if format == "json" {
		var output bytes.Buffer
		if err := json.Indent(&output, data, "", "  "); err != nil {
			return fmt.Errorf("invalid response JSON")
		}
		output.WriteByte('\n')
		_, err := w.Write(output.Bytes())
		return err
	}
	var rows [][]string
	switch operation {
	case "realms":
		var response struct {
			Realms []struct{ Realm, Kind, Name string } `json:"realms"`
		}
		if err := json.Unmarshal(data, &response); err != nil {
			return fmt.Errorf("invalid realms response")
		}
		rows = append(rows, []string{"realm", "kind", "name"})
		for _, realm := range response.Realms {
			rows = append(rows, []string{realm.Realm, realm.Kind, realm.Name})
		}
	case "users":
		var response struct {
			Users []struct {
				Username, Name, Email string
				Roles                 []string
				Disabled              bool
			} `json:"users"`
		}
		if err := json.Unmarshal(data, &response); err != nil {
			return fmt.Errorf("invalid users response")
		}
		rows = append(rows, []string{"username", "name", "email", "roles", "disabled"})
		for _, user := range response.Users {
			rows = append(rows, []string{user.Username, user.Name, user.Email, strings.Join(user.Roles, ";"), strconv.FormatBool(user.Disabled)})
		}
	default:
		return fmt.Errorf("formatted output requires list users or list realms")
	}
	if format == "csv" {
		writer := csv.NewWriter(w)
		return writer.WriteAll(rows)
	}
	if format != "table" {
		return fmt.Errorf("unsupported output format")
	}
	writer := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	for _, row := range rows {
		for i, value := range row {
			// Names are server-controlled; do not let terminal escape sequences or
			// tabs/newlines rewrite a human-readable table.
			row[i] = strings.Map(func(c rune) rune {
				if unicode.IsControl(c) {
					return ' '
				}
				return c
			}, value)
		}
		if _, err := fmt.Fprintln(writer, strings.Join(row, "\t")); err != nil {
			return err
		}
	}
	return writer.Flush()
}
