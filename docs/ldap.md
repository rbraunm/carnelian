# LDAP: Active Directory and OpenLDAP

Check a user name and password against a directory: Active Directory (or Samba), or
OpenLDAP. Carnelian finds the person's entry with a service account, checks the
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

`groups` holds the `sAMAccountName` of every group the person is in, directly or through
other groups (Active Directory's in-chain matching rule). It is unique in the domain, unlike
a group's common name, which anyone allowed to create groups in some OU could copy.

Only people are found (`objectCategory=person`), not computer accounts; searches ask Active
Directory to stay in the domain (its domain-scope control), and any referral that still
arrives is refused rather than followed or ignored. Every operation is bounded in time,
bytes and entries.

## OpenLDAP

Pass `kind=DirectoryKind.openLDAP` and `groupsBaseDN`, the one container the groups are in:

```python
from carnelian.ldap import Directory, DirectoryKind

directory = Directory("ldap.example.edu", secureContext(), "dc=example,dc=edu", "cn=service,ou=services,dc=example,dc=edu",
                      servicePassword, kind=DirectoryKind.openLDAP, groupsBaseDN="ou=groups,dc=example,dc=edu")
```

People are `inetOrgPerson` entries found by `uid` (or the `userAttribute` you give); groups
are `groupOfNames` in `groupsBaseDN`, named by `cn`. A `cn` is unique in the container only
when it is the group's RDN, so each group's DN must begin with `cn=<its cn>`; a group named
by another attribute (`description=x` with `cn: admins`, say) or by a multi-valued RDN is
refused rather than taken as a second `admins`. Groups are told apart by their `entryUUID`,
not by comparing DN text. Nested groups are followed within `ldap.maximumGroupNesting` (16)
levels, `maximumGroupSearches` (200) searches, `maximumGroups` (500) groups and
`maximumGroupWalkSeconds` (30) per sign-in; a walk past any of them is refused by name.
A disabled account is the server's password policy's to refuse: lock it
(`pwdAccountLockedTime`) and the bind fails.

## What is refused

An empty password before anything is sent (LDAP would treat it as an anonymous bind that
succeeds, the classic way past a directory check); a user name that matches no entry or
more than one; a disabled account; the wrong password. All of these give the same message.
A user name cannot inject filter syntax: filters are built as values, never parsed from
text. Connections without TLS are not offered.
