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

func hasWord(s string, arr []string) bool {
	for _, el := range arr {
		if s == el {
			return true
		}
	}
	return false
}

func hasMatchTypeKeywords(s string) bool {
	keywords := []string{"exact", "partial", "prefix", "suffix", "regex"}
	return hasWord(s, keywords)
}

func lastArrayElement(args []string, argp int) bool {
	if (len(args) - 1) == argp {
		return true
	}
	return false
}

func arrayElementExists(args []string, argp int) bool {
	if len(args) > argp {
		return true
	}
	return false
}
