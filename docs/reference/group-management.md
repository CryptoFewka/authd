---
myst:
  html_meta:
    "description lang=en": "Management of groups using authd with Microsoft Entra ID and Google Workspace."
---

(reference::group-management)=
# Group management

Groups are used to manage users that all need the same access and permissions to resources.
Groups from the remote provider can be mapped into local Linux groups for the user.

In addition, you can configure extra groups
[in the broker configuration file](ref::config-user-groups).

## Microsoft Entra ID

Microsoft Entra ID supports creating groups and adding users to them.

> See [Manage Microsoft Entra groups and group membership](https://learn.microsoft.com/en-us/entra/fundamentals/how-to-manage-groups)

For example the user `authd test`, is a member of the Entra ID groups `Azure_OIDC_Test` and `linux-sudo`:

![Azure portal interface showing the Azure groups.](../assets/entraid-groups.png)

This translates to the following unix groups on the local machine:

```shell
~$ groups
aadtest-testauthd@uaadtest.onmicrosoft.com sudo azure_oidc_test
```

There are three types of groups:
1. **Primary group**: Created automatically based on the user name
1. **Local group**: Group local to the machine prefixed with `linux-`. For instance if the user is a member of the Azure group `linux-sudo`, they will be a member of the `sudo` group locally.
1. **Remote group**: All the other Azure groups the user is a member of.

## Google Workspace

Google Workspace supports groups that can be mapped to local Linux groups.

> See [Google Workspace Admin Help: Groups overview](https://support.google.com/a/topic/25838)

```{note}
  Google Workspace group support requires a Google Workspace organisation.
  Personal Google accounts (gmail.com) are not supported.
```

### Prerequisites

- A **Google Workspace** organisation
- The **Admin SDK API** enabled in Google Cloud Console for your OAuth project
- The OAuth app configured as **Internal** in Google Cloud Console
- **"Trust internal apps"** enabled in Google Admin Console (Security >
  Access and data control > API controls > Settings)
- The OAuth app's client ID authorized in Google Admin Console for the scope
  `https://www.googleapis.com/auth/admin.directory.group.readonly` (Security >
  Access and data control > API controls > Manage domain-wide delegation)

See [configure authd](../howto/configure-authd.md) for step-by-step setup instructions.

### Example

A user who is a member of Google Workspace groups `linux-sudo` and `Engineering`
will have the following groups on the local machine:

```shell
~$ groups
user@example.com sudo engineering
```

There are three types of groups:
1. **Primary group**: Created automatically based on the username
1. **Local group**: Google groups prefixed with `linux-`. For instance, a member
   of the group `linux-sudo` will be added to the local `sudo` group.
1. **Remote group**: All other Google Workspace groups the user is a member of.
