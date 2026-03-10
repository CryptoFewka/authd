# Implementation Plan: Google OIDC Broker Groups Support

## Background & Research Findings

### Why Google Groups Requires a Different Approach Than MS Entra ID

Microsoft Entra ID includes groups accessible via the Microsoft Graph API using the **user's own access token** (with the `GroupMember.Read.All` permission). Google's OIDC implementation does **not** include group claims in the ID token, and a regular user's access token cannot enumerate group memberships without additional configuration. Two viable approaches exist.

---

## Two Viable Approaches

### Approach A: Admin Pre-Authorization of OAuth Scopes (Cloudflare's Method — Recommended)

Cloudflare Zero Trust uses this approach for their Google Workspace OIDC integration. The mechanism is:

1. The OAuth application requests the `https://www.googleapis.com/auth/admin.directory.group.readonly` scope as part of the OIDC flow.
2. A **Google Workspace admin** pre-authorizes this scope for the OAuth app in Google Admin Console (Security > Access and data control > API controls). This is the "domain-wide authorization" for OAuth apps (distinct from service account DWD).
3. The Admin SDK must be enabled in Google Cloud Console.
4. In Google Admin Console, "Trust internal apps" must be enabled.
5. With these prerequisites in place, when users authenticate, their access token carries the `admin.directory.group.readonly` scope, and the broker uses it to call `GET /admin/directory/v1/groups?userKey={email}`.

**Advantages:**
- No service account JSON file to create, distribute, or rotate
- Mirrors the well-documented Cloudflare approach
- Simpler admin setup (no extra Google Cloud resources)
- Uses the user's own scoped token — aligns with least-privilege

**Disadvantages:**
- Requires a one-time admin authorization step in Google Admin Console
- The `admin.directory.group.readonly` scope is sensitive and requires admin pre-authorization to grant to users
- Must be configured as an "Internal" app in Google Cloud to avoid external access

### Approach B: Service Account with Domain-Wide Delegation (Traditional Enterprise Method)

1. Admin creates a Google Cloud Service Account, downloads a JSON key.
2. Admin grants it Domain-Wide Delegation (DWD) in Google Workspace Admin Console with the `admin.directory.group.readonly` scope.
3. The broker reads the JSON key, uses it to impersonate a domain admin, and calls the Directory API with `userKey={email}`.

**Advantages:**
- Fully server-side; no impact on user's OAuth flow or scopes
- Standard enterprise approach used by SSSD, Google GCDS, etc.

**Disadvantages:**
- Requires creating and managing a service account JSON key on disk
- Key rotation adds operational overhead

---

## Recommended Implementation: Approach A (Scope-Based, Cloudflare-Style) as Primary, Approach B (Service Account) as Fallback

The implementation should support **both** methods, with Approach A being the primary recommended path. The broker automatically uses whichever is configured:

- If `service_account_file` and `admin_email` are set in `[google]` config → use Approach B
- If only the `admin.directory.group.readonly` scope is present in the access token → use Approach A
- If neither is configured → return `nil, nil` (no groups, graceful no-op)

In practice, Approach A is cleaner for the end user, and the `providerMetadata` map can store whether the scope was granted (from the token's scope claim).

---

## Files to Create or Modify

### 1. `authd-oidc-brokers/go.mod` (and `go.sum`)

Add `google.golang.org/api` as a direct dependency (provides Admin SDK Directory API Go client):

```
go get google.golang.org/api/admin/directory/v1
go mod tidy
```

Run these commands from within the `authd-oidc-brokers/` directory.

---

### 2. `authd-oidc-brokers/internal/providers/google/google.go`

This is the core implementation. The `Provider` struct needs to:

1. **Override `AdditionalScopes()`** to request `admin.directory.group.readonly` (for Approach A):
   ```go
   func (Provider) AdditionalScopes() []string {
       return []string{"https://www.googleapis.com/auth/admin.directory.group.readonly"}
   }
   ```

2. **Implement `GetGroups()`** with dual-path logic:

```go
//go:build withgoogle

package google

import (
    "context"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "os"
    "strings"

    "github.com/canonical/authd/authd-oidc-brokers/internal/providers/genericprovider"
    providerErrors "github.com/canonical/authd/authd-oidc-brokers/internal/providers/errors"
    "github.com/canonical/authd/authd-oidc-brokers/internal/providers/info"
    "github.com/ubuntu/authd/log"
    "golang.org/x/oauth2"
    googleoauth "golang.org/x/oauth2/google"
    "google.golang.org/api/admin/directory/v1"
    "google.golang.org/api/option"
)

const (
    localGroupPrefix    = "linux-"
    directoryGroupScope = "https://www.googleapis.com/auth/admin.directory.group.readonly"
)

// Provider is the google provider implementation.
type Provider struct {
    genericprovider.GenericProvider
}

func New() Provider {
    return Provider{GenericProvider: genericprovider.New()}
}

// AdditionalScopes requests the Admin SDK scope so that when a domain admin
// has pre-authorized this OAuth app in Google Admin Console, all users
// receive an access token capable of querying the Directory API.
func (Provider) AdditionalScopes() []string {
    return []string{directoryGroupScope}
}

// GetGroups retrieves the Google Workspace groups for the authenticated user.
// It supports two mechanisms, tried in order:
//  1. Service account with Domain-Wide Delegation (if service_account_file is set in providerMetadata)
//  2. User access token with admin.directory.group.readonly scope (Cloudflare-style)
func (p Provider) GetGroups(
    ctx context.Context,
    clientID string,
    issuerURL string,
    token *oauth2.Token,
    providerMetadata map[string]interface{},
    deviceRegistrationData []byte,
) ([]info.Group, error) {
    userEmail, err := p.userEmailFromToken(token)
    if err != nil {
        return nil, fmt.Errorf("failed to get user email from token: %w", err)
    }

    // Approach B: Service account with DWD (if configured)
    serviceAccountFile, _ := providerMetadata["google_service_account_file"].(string)
    adminEmail, _ := providerMetadata["google_admin_email"].(string)

    if serviceAccountFile != "" && adminEmail != "" {
        return fetchGroupsWithServiceAccount(ctx, serviceAccountFile, adminEmail, userEmail)
    }

    // Approach A: Use the user's access token directly (Cloudflare-style)
    // This works when the Google Workspace admin has pre-authorized the
    // admin.directory.group.readonly scope for this OAuth app in Google Admin Console.
    return fetchGroupsWithAccessToken(ctx, token.AccessToken, userEmail)
}

// userEmailFromToken extracts the authenticated user's email address from
// the ID token stored in the OAuth2 token's extra fields.
func (p Provider) userEmailFromToken(token *oauth2.Token) (string, error) {
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

// fetchGroupsWithAccessToken calls the Directory API using the user's access token.
// Requires the admin.directory.group.readonly scope and prior domain-level authorization
// of the OAuth app in Google Admin Console.
func fetchGroupsWithAccessToken(ctx context.Context, accessToken, userEmail string) ([]info.Group, error) {
    log.Debugf(ctx, "Fetching Google Workspace groups for %q using access token", userEmail)

    tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: accessToken})
    svc, err := directory.NewService(ctx, option.WithTokenSource(tokenSource))
    if err != nil {
        return nil, fmt.Errorf("failed to create Admin SDK Directory service: %w", err)
    }

    return listGroups(ctx, svc, userEmail)
}

// fetchGroupsWithServiceAccount calls the Directory API using a service account
// with Domain-Wide Delegation.
func fetchGroupsWithServiceAccount(ctx context.Context, serviceAccountFile, adminEmail, userEmail string) ([]info.Group, error) {
    log.Debugf(ctx, "Fetching Google Workspace groups for %q using service account", userEmail)

    data, err := os.ReadFile(serviceAccountFile)
    if err != nil {
        return nil, fmt.Errorf("failed to read service account file %q: %w", serviceAccountFile, err)
    }
    conf, err := googleoauth.JWTConfigFromJSON(data, directoryGroupScope)
    if err != nil {
        return nil, fmt.Errorf("failed to parse service account JSON: %w", err)
    }
    conf.Subject = adminEmail

    svc, err := directory.NewService(ctx, option.WithHTTPClient(conf.Client(ctx)))
    if err != nil {
        return nil, fmt.Errorf("failed to create Admin SDK Directory service: %w", err)
    }

    return listGroups(ctx, svc, userEmail)
}

// listGroups pages through the Directory API to collect all groups for userEmail.
func listGroups(ctx context.Context, svc *directory.Service, userEmail string) ([]info.Group, error) {
    var groups []info.Group
    var groupNames []string

    pageToken := ""
    for {
        call := svc.Groups.List().UserKey(userEmail).MaxResults(200)
        if pageToken != "" {
            call = call.PageToken(pageToken)
        }
        result, err := call.Do()
        if err != nil {
            msg := fmt.Sprintf(
                "Error: failed to fetch Google Workspace groups for user %q. "+
                    "Ensure the Admin SDK is enabled, the OAuth app has been authorized in "+
                    "Google Admin Console with the %q scope, and 'Trust internal apps' is enabled.",
                userEmail, directoryGroupScope,
            )
            return nil, &providerErrors.ForDisplayError{Message: msg, Err: err}
        }

        for _, g := range result.Groups {
            group, originalName, skip := googleGroupToInfoGroup(g)
            if skip {
                continue
            }
            if isDuplicateGroup(originalName, groupNames) {
                continue
            }
            groups = append(groups, group)
            groupNames = append(groupNames, originalName)
        }

        if result.NextPageToken == "" {
            break
        }
        pageToken = result.NextPageToken
    }

    log.Debugf(ctx, "Got %d Google Workspace groups: %s", len(groups), strings.Join(groupNames, ", "))
    return groups, nil
}

// googleGroupToInfoGroup converts a Directory API Group to an info.Group.
// Returns (group, originalName, skip).
func googleGroupToInfoGroup(g *directory.Group) (info.Group, string, bool) {
    if g == nil || g.Name == "" {
        return info.Group{}, "", true
    }

    name := strings.ToLower(g.Name)
    isLocal := strings.HasPrefix(name, localGroupPrefix)

    group := info.Group{Name: name}
    if isLocal {
        group.Name = strings.TrimPrefix(name, localGroupPrefix)
        // Local groups have no UGID (same convention as msentraid)
    } else {
        group.UGID = g.Id
    }

    return group, g.Name, false
}

// isDuplicateGroup returns true if groupName is already in groupNames (case-insensitive).
func isDuplicateGroup(groupName string, groupNames []string) bool {
    for _, name := range groupNames {
        if strings.EqualFold(name, groupName) {
            log.Warningf(context.Background(), "Duplicate Google Workspace group %q, ignoring", groupName)
            return true
        }
    }
    return false
}
```

---

### 3. `authd-oidc-brokers/internal/broker/config.go`

Add a `[google]` config section for the optional service account fallback (Approach B). Add two fields to the `userConfig` struct and parse them:

```go
const (
    googleSection         = "google"
    serviceAccountFileKey = "service_account_file"
    adminEmailKey         = "admin_email"
)
```

In `parseConfig()`, add:
```go
googleSec := iniCfg.Section(googleSection)
if googleSec != nil {
    cfg.googleServiceAccountFile = googleSec.Key(serviceAccountFileKey).String()
    cfg.googleAdminEmail         = googleSec.Key(adminEmailKey).String()
}
```

New `userConfig` fields:
```go
googleServiceAccountFile string
googleAdminEmail         string
```

---

### 4. `authd-oidc-brokers/internal/broker/broker.go`

Update `getGroups()` to inject the current runtime service account config into `providerMetadata`. We clone the stored metadata and overlay the current config values so the Google provider can use whichever method is configured:

```go
func (b *Broker) getGroups(ctx context.Context, session *session, t *token.AuthCachedInfo) ([]info.Group, error) {
    if session.isOffline {
        return nil, errors.New("session is in offline mode")
    }

    metadata := maps.Clone(t.ProviderMetadata)
    if metadata == nil {
        metadata = make(map[string]interface{})
    }
    if b.cfg.googleServiceAccountFile != "" {
        metadata["google_service_account_file"] = b.cfg.googleServiceAccountFile
    }
    if b.cfg.googleAdminEmail != "" {
        metadata["google_admin_email"] = b.cfg.googleAdminEmail
    }

    return b.provider.GetGroups(ctx,
        b.cfg.clientID,
        b.cfg.issuerURL,
        t.Token,
        metadata,
        t.DeviceRegistrationData,
    )
}
```

Add `"maps"` to the imports (available in Go 1.21+ standard library; go.mod requires `go 1.25.0`).

---

### 5. `authd-oidc-brokers/internal/providers/google/google_test.go`

Replace and extend tests:

- **`TestNew`** — unchanged; verifies provider is created
- **`TestAdditionalScopes`** — updated: now asserts the `admin.directory.group.readonly` scope is returned (not empty)
- **`TestGetGroups_NoIDToken`** — returns error when token has no `id_token` field
- **`TestGetGroups_AccessTokenSuccess`** — mock HTTP server at the Directory API endpoint; access token path returns standard groups including `linux-` prefixed local groups; validates `[]info.Group` output
- **`TestGetGroups_AccessTokenAPIError`** — mock returns 403; validates a `ForDisplayError` is returned with the helpful message
- **`TestGetGroups_Pagination`** — mock returns multiple pages (`nextPageToken`); validates all groups are collected
- **`TestGetGroups_DuplicateGroups`** — mock returns duplicate group names; validates only first is kept
- **`TestGetGroups_ServiceAccountFallback`** — mock with service account file path in `providerMetadata`; validates service account code path is taken
- **`TestGetGroups_ServiceAccountFileNotFound`** — non-existent file path; validates error
- **`TestGetGroups_EmptyGroups`** — API returns zero groups; returns empty slice (not nil)

Use `httptest.NewServer` to mock `https://www.googleapis.com/admin/directory/v1/groups`. The `google.golang.org/api` client respects the `GOOGLE_API_BASE_URL` or custom HTTP client injection via `option.WithHTTPClient(httptest.Client)` for testing.

Golden test files in `testdata/golden/TestGetGroups/` should be added following the existing pattern in `msentraid`.

---

### 6. `authd-oidc-brokers/conf/variants/google/broker.conf`

Add the `[google]` section documentation:

```ini
[google]
## Google Workspace Groups Support
##
## authd can fetch Google Workspace group memberships for authenticated users.
## This requires the Google Admin SDK to be enabled and the OAuth app to be
## authorized in Google Admin Console.
##
## -- Recommended setup (Cloudflare-style, scope-based) --
##
## 1. In Google Cloud Console, ensure the Admin SDK API is enabled.
## 2. In Google Admin Console (admin.google.com), go to:
##    Security > Access and data control > API controls > Settings
##    Enable "Trust internal apps".
## 3. The OAuth app must be configured as type "Internal" in Google Cloud.
## 4. In Google Admin Console, go to:
##    Security > Access and data control > API controls > Manage domain-wide delegation
##    OR authorize the OAuth client ID with the scope:
##    https://www.googleapis.com/auth/admin.directory.group.readonly
##
## No extra configuration keys are required for this method — the broker
## automatically uses the user's access token to fetch group memberships.
##
## -- Alternative setup (Service Account with Domain-Wide Delegation) --
##
## Use this if the scope-based approach is not suitable for your environment.
##
## 1. Create a service account in Google Cloud Console.
## 2. Download a JSON key for the service account.
## 3. In Google Admin Console, go to:
##    Security > Access and data control > API controls > Manage domain-wide delegation
##    Add the service account Client ID with scope:
##    https://www.googleapis.com/auth/admin.directory.group.readonly
## 4. Set the options below.
##
## Absolute path to the Google Cloud service account JSON key file.
## Example: service_account_file = /var/snap/authd-google/current/service-account.json
#service_account_file =

## Email address of a Google Workspace admin to impersonate (service account method only).
## Example: admin_email = admin@yourdomain.com
#admin_email =
```

---

### 7. `docs/reference/group-management.md`

Remove the `{note}` callout that restricts groups to `msentraid` only. Add a **Google Workspace** section:

```markdown
## Google Workspace

Google Workspace groups can be mapped to local Linux groups.

### Prerequisites

- A **Google Workspace** organisation (personal Google accounts are not supported)
- Admin access to **Google Admin Console** and **Google Cloud Console**
- The **Admin SDK API** enabled in Google Cloud Console for your project

### How it works

Groups named with a `linux-` prefix in Google Workspace are treated as **local groups**
(e.g. a Google group named `linux-sudo` grants membership in the local `sudo` group).
All other Google Workspace groups become **remote groups** with a UGID.

### Setup

Configure Google Workspace groups support by following the guide in
[configure authd — Google IAM](../howto/configure-authd.md).

### Example

A user who is a member of Google Workspace groups `linux-sudo` and `Engineering`
will have the following groups on the local machine:

    ~$ groups
    user@example.com sudo engineering

There are three types of groups:
1. **Primary group**: Created automatically based on the username
2. **Local group**: Google groups prefixed with `linux-`. For example, `linux-sudo`
   becomes the local `sudo` group (no UGID is set).
3. **Remote group**: All other Google Workspace groups the user is a member of.
```

---

### 8. `docs/howto/configure-authd.md`

Add a **Google groups setup** subsection inside the Google IAM tab. It should cover:

1. **Enabling the Admin SDK** in Google Cloud Console
2. **Configuring "Trust internal apps"** in Google Admin Console
3. **Authorizing the OAuth app** for the `admin.directory.group.readonly` scope in Google Admin Console (the scope-based / Cloudflare-style method)
4. **Restarting the snap** to pick up changes
5. A note about the alternative service account approach with a pointer to the relevant `[google]` config keys

---

## Implementation Sequence

1. Add Go dependency (`go get google.golang.org/api/admin/directory/v1` + `go mod tidy` in `authd-oidc-brokers/`)
2. Update `google/google.go` — implement `GetGroups()` and `AdditionalScopes()`
3. Update `config.go` — add `[google]` section parsing for service account fallback
4. Update `broker.go` — inject service account config into `providerMetadata`
5. Update `broker.conf` template — document both setup methods
6. Write tests in `google_test.go`
7. Update documentation (`group-management.md`, `configure-authd.md`)

---

## Constraints and Edge Cases

| Scenario | Behaviour |
|---|---|
| No groups config, scope not authorized | `GetGroups()` returns `nil, nil` — graceful no-op |
| Admin SDK 403 (scope not authorized) | `ForDisplayError` with setup instructions |
| Service account file not found | Hard error with file path in message |
| API returns zero groups | Returns empty `[]info.Group{}` |
| Pagination (`nextPageToken`) | Handled with loop |
| Duplicate group names | Logged warning; first occurrence kept |
| Group name casing | All names lowercased (consistent with msentraid) |
| `linux-` prefix | Stripped; local group has no UGID |
| Personal Google accounts | Directory API will 403; `ForDisplayError` returned |
| Service account configured → takes priority over scope-based approach | Service account method used |

---

## What This Does NOT Cover

- **Cloud Identity Groups API** (for Cloud Identity customers without full Workspace) — can be added later
- **Consumer / free Google accounts** — not supported by the Directory API
- **Nested group expansion** (transitive memberships) — the `Groups.List(userKey)` endpoint only returns direct memberships; the `Members.HasMember` endpoint or Cloud Identity `searchTransitiveMemberships` would be needed for nested groups. Can be added later.
