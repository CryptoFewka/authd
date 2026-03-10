//go:build withgoogle

package google_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/canonical/authd/authd-oidc-brokers/internal/providers/google"
	"github.com/canonical/authd/authd-oidc-brokers/internal/testutils/golden"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/authd/log"
	"golang.org/x/oauth2"
)

const testUserEmail = "user@example.com"

// makeIDToken creates a minimal JWT-format ID token string containing the
// given email claim. The signature part is a placeholder; our implementation
// only decodes the payload and does not verify the signature.
func makeIDToken(email string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"email":%q,"sub":"test-sub","email_verified":true}`, email)))
	return header + "." + payload + ".placeholder-signature"
}

// tokenWithIDToken returns an oauth2.Token carrying an id_token extra field.
func tokenWithIDToken(idToken string) *oauth2.Token {
	return (&oauth2.Token{
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		Expiry:       time.Now().Add(1000 * time.Hour),
	}).WithExtra(map[string]interface{}{
		"id_token": idToken,
	})
}

// startMockDirectoryServer starts an httptest.Server that handles
// GET /admin/directory/v1/groups with the provided handler.
func startMockDirectoryServer(t *testing.T, handler http.HandlerFunc) (serverURL string, cleanup func()) {
	t.Helper()
	if handler == nil {
		handler = simpleGroupsHandler
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(os.Stderr, "Mock Directory server: %s %s\n", r.Method, r.URL.RequestURI())
		if r.Method == http.MethodGet && r.URL.Path == "/admin/directory/v1/groups" {
			handler(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	return srv.URL, srv.Close
}

// ----- group response handlers -----

// simpleGroupsHandler returns two standard remote groups.
func simpleGroupsHandler(w http.ResponseWriter, _ *http.Request) {
	resp := map[string]any{
		"groups": []map[string]any{
			{"id": "id1", "name": "Group1"},
			{"id": "id2", "name": "Group2"},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// localGroupsHandler returns groups with the "linux-" prefix (local groups).
func localGroupsHandler(w http.ResponseWriter, _ *http.Request) {
	resp := map[string]any{
		"groups": []map[string]any{
			{"id": "local-id1", "name": "linux-local1"},
			{"id": "local-id2", "name": "linux-local2"},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// mixedGroupsHandler returns a mix of remote and local groups.
func mixedGroupsHandler(w http.ResponseWriter, _ *http.Request) {
	resp := map[string]any{
		"groups": []map[string]any{
			{"id": "id1", "name": "Group1"},
			{"id": "local-id1", "name": "linux-local1"},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// duplicateGroupsHandler returns groups with duplicate names (case-insensitively).
func duplicateGroupsHandler(w http.ResponseWriter, _ *http.Request) {
	resp := map[string]any{
		"groups": []map[string]any{
			{"id": "id1", "name": "Engineering"},
			{"id": "id2", "name": "engineering"}, // duplicate, should be skipped
			{"id": "id3", "name": "Finance"},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// emptyGroupsHandler returns an empty list of groups.
func emptyGroupsHandler(w http.ResponseWriter, _ *http.Request) {
	resp := map[string]any{"groups": []any{}}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// paginatedGroupsHandler returns groups across two pages.
func paginatedGroupsHandler(w http.ResponseWriter, r *http.Request) {
	pageToken := r.URL.Query().Get("pageToken")
	var resp map[string]any
	if pageToken == "" {
		resp = map[string]any{
			"groups": []map[string]any{
				{"id": "id1", "name": "Group1"},
			},
			"nextPageToken": "page2token",
		}
	} else {
		resp = map[string]any{
			"groups": []map[string]any{
				{"id": "id2", "name": "Group2"},
				{"id": "id3", "name": "Group3"},
			},
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// missingIDGroupsHandler returns a group missing the id field (should be skipped).
func missingIDGroupsHandler(w http.ResponseWriter, _ *http.Request) {
	resp := map[string]any{
		"groups": []map[string]any{
			{"name": "GroupMissingID"},
			{"id": "id2", "name": "Group2"},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// missingNameGroupsHandler returns a group missing the name field (should be skipped).
func missingNameGroupsHandler(w http.ResponseWriter, _ *http.Request) {
	resp := map[string]any{
		"groups": []map[string]any{
			{"id": "id-no-name"},
			{"id": "id2", "name": "Group2"},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// errorGroupsHandler returns a 403 Forbidden response.
func errorGroupsHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"error":{"code":403,"message":"Not Authorized to access this resource/api"}}`))
}

// ----- tests -----

func TestNew(t *testing.T) {
	t.Parallel()

	p := google.New()

	require.Empty(t, p, "New should return the default provider implementation with no parameters")
}

func TestAdditionalScopes(t *testing.T) {
	t.Parallel()

	p := google.New()

	scopes := p.AdditionalScopes()
	require.Contains(t, scopes,
		"https://www.googleapis.com/auth/admin.directory.group.readonly",
		"Google provider should request the admin.directory.group.readonly scope")
}

func TestGetGroups(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		handler   http.HandlerFunc
		noIDToken bool

		wantErr bool
	}{
		"Successfully_get_groups":                                     {},
		"Successfully_get_groups_with_local_groups":                   {handler: localGroupsHandler},
		"Successfully_get_groups_with_mixed_groups":                   {handler: mixedGroupsHandler},
		"Successfully_get_groups_with_pagination":                     {handler: paginatedGroupsHandler},
		"Successfully_get_groups_with_empty_list":                     {handler: emptyGroupsHandler},
		"Successfully_get_groups_skipping_missing_id":                 {handler: missingIDGroupsHandler},
		"Successfully_get_groups_skipping_missing_name":               {handler: missingNameGroupsHandler},
		"Successfully_get_groups_deduplicating_case_insensitive_name": {handler: duplicateGroupsHandler},

		"Error_when_token_has_no_id_token": {noIDToken: true, wantErr: true},
		"Error_when_api_returns_error":     {handler: errorGroupsHandler, wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var token *oauth2.Token
			if tc.noIDToken {
				token = &oauth2.Token{
					AccessToken: "test-access-token",
					Expiry:      time.Now().Add(1000 * time.Hour),
				}
			} else {
				token = tokenWithIDToken(makeIDToken(testUserEmail))
			}

			metadata := map[string]interface{}{}
			if !tc.noIDToken {
				srvURL, cleanup := startMockDirectoryServer(t, tc.handler)
				t.Cleanup(cleanup)
				metadata["directory_api_url"] = srvURL
			}

			p := google.New()
			got, err := p.GetGroups(
				context.Background(),
				"test-client-id",
				"https://accounts.google.com",
				token,
				metadata,
				nil,
			)

			if tc.wantErr {
				require.Error(t, err, "GetGroups should return an error")
				return
			}
			require.NoError(t, err, "GetGroups should not return an error")

			golden.CheckOrUpdateYAML(t, got)
		})
	}
}

func TestMain(m *testing.M) {
	log.SetLevel(log.DebugLevel)

	m.Run()
}
