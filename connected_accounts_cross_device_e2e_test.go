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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
)

func testConnectedAccountsCrossDevice(t *testing.T, cert, key string, roots *x509.CertPool, pair tls.Certificate) {
	f := newCaddyConnectedAccountsFixture(t, connectedAccountsOptions{
		mount: "/tenant/auth", localMFA: true, providerRefresh: true, localOP: true,
		configure: func(input string) string {
			return strings.Replace(input, "authentication portal myportal {", "authentication portal myportal {\nenable cross-device login", 1)
		},
	}, cert, key, roots, pair)
	linked := f.browser(t)
	f.connect(t, linked, "upstream", "alice")
	id := localIdentityRecord(t, f.database, "alice").ID
	requester, approver := crossDeviceBrowser(t, f.oidcRPFixture), crossDeviceBrowser(t, f.oidcRPFixture)
	interaction := crossDeviceStart(t, requester)
	f.secrets = append(f.secrets, interaction.Secret, interaction.Code, interaction.URI)
	crossDeviceBegin(t, approver, interaction)
	callback := f.login(t, approver.client, "upstream", http.StatusSeeOther)
	sandbox := callback.header.Get("Location")
	if !strings.Contains(sandbox, f.mount+"/sandbox/") || crossDeviceCookie(approver, "AUTHP_ACCESS_TOKEN") != "" {
		t.Fatal("connected OAuth bypassed the target's explicit local factors")
	}
	completed := connectedAccountsFinishLocal(t, f.localIdentityFixture, approver.client, sandbox, "alice")
	if completed.header.Get("Location") != f.mount+"/cross-device/confirm" {
		t.Fatal("external factor completion lost the explicit approval destination")
	}
	approvingToken := crossDeviceCookie(approver, "AUTHP_ACCESS_TOKEN")
	approving := f.verifyAccess(t, approvingToken)
	if approving["id"] != id || !slices.Contains(approving["amr"].([]any), any("federated")) || !slices.Contains(approving["amr"].([]any), any("otp")) || !slices.Contains(approving["amr"].([]any), any("pwd")) {
		t.Fatal("approving token omitted completed external or explicit local factors")
	}
	confirmation := approver.request(t, "GET", "/cross-device/confirm", nil, nil)
	confirmation.requireStatus(t, 200)
	crossDeviceDecision(t, approver, confirmation, "approve").requireStatus(t, 200)
	redeemed := crossDevicePost(t, requester, "poll", interaction.values())
	redeemed.requireStatus(t, 200)
	access := crossDeviceCookie(requester, "AUTHP_ACCESS_TOKEN")
	transferred := f.verifyAccess(t, access)
	if access == approvingToken || transferred["id"] != id || transferred["sid"] != nil || transferred["auth_time"] != approving["auth_time"] || fmt.Sprint(transferred["amr"]) != fmt.Sprint(approving["amr"]) || transferred["exp"].(float64) > approving["exp"].(float64) {
		t.Fatal("external MFA transfer changed identity, methods, family authority or expiry")
	}
	for _, name := range []string{"AUTHP_REFRESH_TOKEN", "AUTHP_OIDC_SESSION_ID", "AUTHP_ID_TOKEN"} {
		if crossDeviceCookie(requester, name) != "" {
			t.Fatal("external MFA transfer granted renewable or local OP authority")
		}
	}
	f.json(t, requester.client, "/api/profile", map[string]any{"kind": "fetch_user_api_keys"}, "", http.Header{"Origin": {f.base}}).requireStatus(t, 501)
	params := requester.authorization("trusted")
	params.Set("prompt", "none")
	requester.callback(t, requester.authorize(t, params), params, "login_required")
	crossDevicePost(t, requester, "poll", interaction.values()).requireStatus(t, 410)

	// Capacity was left available (max sessions eight). An ordinary local
	// transfer on the same running portal still receives independent renewable
	// and OP sessions; the external denial above is an authority distinction.
	localRequester, localApprover := crossDeviceBrowser(t, f.oidcRPFixture), crossDeviceBrowser(t, f.oidcRPFixture)
	local := crossDeviceStart(t, localRequester)
	f.secrets = append(f.secrets, local.Secret, local.Code, local.URI)
	crossDeviceBegin(t, localApprover, local)
	confirmation = crossDeviceLogin(t, localApprover, "bob", localIdentityBobPassword, false, f.database)
	crossDeviceDecision(t, localApprover, confirmation, "approve").requireStatus(t, 200)
	crossDevicePost(t, localRequester, "poll", local.values()).requireStatus(t, 200)
	localClaims := f.verifyAccess(t, crossDeviceCookie(localRequester, "AUTHP_ACCESS_TOKEN"))
	if localClaims["sid"] == nil || localClaims["sid"] == "" || localClaims["id"] != localIdentityRecord(t, f.database, "bob").ID {
		t.Fatal("ordinary local transfer lost its independent refresh family")
	}
	for _, name := range []string{"AUTHP_REFRESH_TOKEN", "AUTHP_OIDC_SESSION_ID"} {
		own, other := crossDeviceCookie(localRequester, name), crossDeviceCookie(localApprover, name)
		if own == "" || other == "" || own == other {
			t.Fatal("ordinary local transfer failed its independent credential control")
		}
		f.secrets = append(f.secrets, own, other)
	}
	f.json(t, localRequester.client, "/api/refresh_token", struct{}{}, "", http.Header{"Origin": {f.base}, "X-Authcrunch-Refresh": {"1"}}).requireStatus(t, 200)
}
