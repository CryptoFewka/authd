//go:build withgoogle

// Package google is the google specific extension.
package google

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	providerErrors "github.com/canonical/authd/authd-oidc-brokers/internal/providers/errors"
	"github.com/canonical/authd/authd-oidc-brokers/internal/providers/genericprovider"
	"github.com/canonical/authd/authd-oidc-brokers/internal/providers/info"
	"github.com/ubuntu/authd/log"
	"golang.org/x/oauth2"
)

const (
	// localGroupPrefix is the prefix for groups that map to local Linux groups.
	localGroupPrefix = "linux-"

	// directoryGroupScope is the OAuth2 scope required to read Google Workspace group memberships.
	// A Google Workspace admin must pre-authorize this scope for the OAuth app in Google Admin Console.
	directoryGroupScope = "https://www.googleapis.com/auth/admin.directory.group.readonly"

	// defaultDirectoryAPIBaseURL is the base URL for the Google Admin SDK Directory API.
	defaultDirectoryAPIBaseURL = "https://admin.googleapis.com/admin/directory/v1"
)

// Provider is the google provider implementation.
type Provider struct {
	genericprovider.GenericProvider
}

// New returns a new GoogleProvider.
func New() Provider {
	return Provider{
		GenericProvider: genericprovider.New(),
	}
}

// AdditionalScopes returns the scopes required by the Google provider.
//
// Requesting admin.directory.group.readonly causes it to appear in every
// authenticated user's access token, provided the Google Workspace admin has
// authorized the OAuth client ID for this scope via "Manage domain-wide
// delegation" in Google Admin Console. The broker then uses the user's own
// access token to call the Google Admin SDK Directory API — no separate
// service-account credentials are required. This is the same mechanism used
// by Cloudflare Zero Trust for Google Workspace group lookups.
//
// Note that we do not return oidc.ScopeOfflineAccess, as for TV/limited input
// devices, the API call will fail as not supported by this application type.
// However, the refresh token will be acquired and is functional to refresh
// without user interaction.
// If we start to support other kinds of applications, we should revisit this.
// More info on https://developers.google.com/identity/protocols/oauth2/limited-input-device#allowedscopes.
func (Provider) AdditionalScopes() []string {
	return []string{directoryGroupScope}
}

// GetGroups retrieves the Google Workspace groups for the authenticated user
// using the user's own access token.
//
// The token carries the admin.directory.group.readonly scope because the
// admin authorized the OAuth client ID for that scope in Google Admin Console
// (Security > Access and data control > API controls > Manage domain-wide
// delegation). This grants the scope to every user in the domain who
// authenticates through this OAuth client, without requiring a service account.
//
// Prerequisites (one-time admin setup):
//   - Admin SDK API enabled in Google Cloud Console
//   - OAuth app type set to "Internal" in Google Cloud Console
//   - "Trust internal apps" enabled in Google Admin Console
//   - OAuth client ID authorized for admin.directory.group.readonly in
//     Manage domain-wide delegation in Google Admin Console
//
// The optional "directory_api_url" key in providerMetadata overrides the
// default API base URL, which is useful for testing.
func (p Provider) GetGroups(
	ctx context.Context,
	clientID string,
	issuerURL string,
	token *oauth2.Token,
	providerMetadata map[string]interface{},
	deviceRegistrationData []byte,
) ([]info.Group, error) {
	userEmail, err := userEmailFromToken(token)
	if err != nil {
		return nil, fmt.Errorf("failed to get user email from token: %w", err)
	}

	apiBaseURL := defaultDirectoryAPIBaseURL
	if override, ok := providerMetadata["directory_api_url"].(string); ok && override != "" {
		apiBaseURL = override
	}

	return fetchUserGroups(ctx, token.AccessToken, userEmail, apiBaseURL)
}

// userEmailFromToken extracts the authenticated user's email from the ID token
// stored in the OAuth2 token's extra fields.
func userEmailFromToken(token *oauth2.Token) (string, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return "", fmt.Errorf("id_token not found in token extra fields")
	}

	parts := strings.Split(rawIDToken, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid ID token format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode ID token payload: %w", err)
	}

	var claims struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("failed to unmarshal ID token claims: %w", err)
	}

	if claims.Email == "" {
		return "", fmt.Errorf("email claim missing from ID token")
	}

	return claims.Email, nil
}

// directoryGroupsResponse is the JSON response from the Directory API groups.list endpoint.
type directoryGroupsResponse struct {
	Groups        []directoryGroup `json:"groups"`
	NextPageToken string           `json:"nextPageToken"`
}

// directoryGroup represents a single group in the Directory API response.
type directoryGroup struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// fetchUserGroups calls the Google Admin SDK Directory API to list the groups
// the given user is a member of, handling pagination automatically.
func fetchUserGroups(ctx context.Context, accessToken, userEmail, apiBaseURL string) ([]info.Group, error) {
	log.Debugf(ctx, "Fetching Google Workspace groups for user %q", userEmail)

	var groups []info.Group
	var groupNames []string

	pageToken := ""
	for {
		apiURL, err := buildGroupsURL(apiBaseURL, userEmail, pageToken)
		if err != nil {
			return nil, fmt.Errorf("failed to build Directory API URL: %w", err)
		}

		resp, err := doDirectoryRequest(ctx, accessToken, apiURL)
		if err != nil {
			return nil, err
		}

		for _, g := range resp.Groups {
			group, originalName, skip := directoryGroupToInfoGroup(g)
			if skip {
				continue
			}
			if isDuplicateGroup(ctx, originalName, groupNames) {
				continue
			}
			groups = append(groups, group)
			groupNames = append(groupNames, originalName)
		}

		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}

	log.Debugf(ctx, "Got %d Google Workspace groups: %s", len(groups), strings.Join(groupNames, ", "))
	return groups, nil
}

// buildGroupsURL constructs the Directory API URL for listing a user's groups.
func buildGroupsURL(apiBaseURL, userEmail, pageToken string) (string, error) {
	u, err := url.Parse(apiBaseURL + "/groups")
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Set("userKey", userEmail)
	q.Set("maxResults", "200")
	if pageToken != "" {
		q.Set("pageToken", pageToken)
	}
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// doDirectoryRequest performs a single authenticated GET request to the Directory API.
func doDirectoryRequest(ctx context.Context, accessToken, apiURL string) (*directoryGroupsResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Directory API request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call Directory API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read Directory API response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf(
			"Error: failed to fetch Google Workspace groups (HTTP %d). "+
				"Ensure the Admin SDK is enabled in Google Cloud Console, the OAuth "+
				"client ID is authorized for the %q scope via "+
				"'Manage domain-wide delegation' in Google Admin Console, and "+
				"'Trust internal apps' is enabled under Security > API controls.",
			resp.StatusCode, directoryGroupScope,
		)
		return nil, &providerErrors.ForDisplayError{
			Message: msg,
			Err:     fmt.Errorf("directory API returned HTTP %d: %s", resp.StatusCode, body),
		}
	}

	var result directoryGroupsResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse Directory API response: %w", err)
	}

	return &result, nil
}

// directoryGroupToInfoGroup converts a Directory API group to an info.Group.
// Returns (group, originalName, skip). Groups with empty name or ID are skipped.
// Groups prefixed with "linux-" are treated as local groups (no UGID).
func directoryGroupToInfoGroup(g directoryGroup) (info.Group, string, bool) {
	if g.Name == "" || g.ID == "" {
		return info.Group{}, "", true
	}

	name := strings.ToLower(g.Name)
	group := info.Group{Name: name}

	if strings.HasPrefix(name, localGroupPrefix) {
		// Local group: strip the "linux-" prefix; no UGID (same convention as msentraid).
		group.Name = strings.TrimPrefix(name, localGroupPrefix)
	} else {
		group.UGID = g.ID
	}

	return group, g.Name, false
}

// isDuplicateGroup returns true if groupName already appears in groupNames (case-insensitive).
func isDuplicateGroup(ctx context.Context, groupName string, groupNames []string) bool {
	for _, name := range groupNames {
		if strings.EqualFold(name, groupName) {
			log.Warningf(ctx, "Duplicate Google Workspace group %q, ignoring", groupName)
			return true
		}
	}
	return false
}
