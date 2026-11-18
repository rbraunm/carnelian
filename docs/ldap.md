# LDAP and Active Directory

Check a user name and password against a directory: Active Directory, Samba, or another
LDAP server. Carnelian finds the person's entry with a service account, checks the
password by binding as that entry on a separate connection, refuses a disabled Active
Directory account, and returns the groups the person belongs to, nested ones included.
Every connection is TLS: LDAPS, or StartTLS before anything else is said.

## What you configure

| Setting | Example |
|---|---|
| Host and port | `dc1.example.edu`, 636 for LDAPS (or 389 with `startTLS=True`) |
| Base DN | `DC=example,DC=edu` |
| Service account and password | A read-only account, e.g. `svc-app@example.edu`; keep the password out of source |
| The attribute users sign in with | `sAMAccountName` (the default), or `userPrincipalName`, `uid` |
| The directory's CA certificate | When it is not in the system's trust store |

## Signing in

```python
from carnelian.fetching import secureContext
from carnelian.ldap import Directory, DirectoryRefused

directory = Directory("dc1.example.edu", secureContext("/etc/ssl/directory-ca.pem"), "DC=example,DC=edu",
                      "svc-app@example.edu", servicePassword)
try:
  person = directory.signIn(userName, password)
except DirectoryRefused as refusal:
  ...  # "the user name or the password is wrong" for every kind of refusal, so names are not revealed
print(person.userName, person.displayName, person.email, person.groups)
```

`groups` holds the common names of every group the person is in, directly or through other
groups (Active Directory's in-chain matching rule).

## What is refused

An empty password before anything is sent (LDAP would treat it as an anonymous bind that
succeeds, the classic way past a directory check); a user name that matches no entry or
more than one; a disabled account; the wrong password. All of these give the same message.
A user name cannot inject filter syntax: filters are built as values, never parsed from
text. Connections without TLS are not offered.
