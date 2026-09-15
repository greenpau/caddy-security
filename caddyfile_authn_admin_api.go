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
	"fmt"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/authn"
	adminparser "github.com/greenpau/go-authcrunch/pkg/authn/admin_api/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func encodePortalAdminAPIDirective(keyword string, args []string) (string, error) {
	for _, arg := range args {
		// EncodeArgs can trim trailing empty fields. Preserve token boundaries
		// and reject these before the shared parser loses that information.
		if strings.TrimSpace(arg) == "" || strings.ContainsAny(arg, "\r\n") {
			return "", fmt.Errorf("empty or multiline admin API argument")
		}
	}
	return cfgutil.EncodeArgs(append([]string{keyword}, args...)), nil
}

func configurePortalAdminAPI(portal *authn.PortalConfig, statements []string) error {
	config, err := adminparser.NewAdminAPIConfigFromDirectives(statements)
	if err != nil {
		return err
	}
	return portal.ConfigureAdminAPI(config)
}
