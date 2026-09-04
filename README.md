# bitwarden.el

`bitwarden.el` is an asynchronous, multi-buffer Emacs 31 client for the
official Bitwarden CLI.  It provides a vault navigator, sortable lists,
masked detail views, widget-based editors, attachments, Sends, generation,
import, and export without launching a shell.

## Requirements

- Emacs 31.1
- Bitwarden CLI (`bw`) on `exec-path`
- `magit-section` 4.7.1
- A Bitwarden or compatible self-hosted server

`magit-section` is also installed as a dependency of Magit.

## Installation

Add this directory to `load-path`, require the package, and run
`M-x bitwarden`:

```elisp
(add-to-list 'load-path "/path/to/bitwarden.el")
(require 'bitwarden)
```

If `bw` is not on `exec-path`:

```elisp
(setq bitwarden-executable "/absolute/path/to/bw")
```

`M-x bitwarden` immediately opens the navigator with a loading indicator, then
checks status, offers login or unlock when needed, and replaces that indicator
with the loaded vault.  Password, API-key, SSO, authenticator, email, and
YubiKey OTP login paths are supported.  Users whose accounts require FIDO2 or
Duo must use their personal API key because those methods are not available in
the CLI.

For a self-hosted server, run `M-x bitwarden-configure-server`.  Use a
prefix argument to configure individual API, identity, icons, events,
notifications, web-vault, and Key Connector endpoints.

## Buffers and keys

The package respects normal `display-buffer` rules.  Navigator, list, detail,
and form buffers are independent; it does not install a fixed window layout.
Navigator and detail buffers use `magit-section`, so `TAB` folds the current
section and Magit's normal section movement/cycling commands are available.

Navigator:

| Key | Action |
| --- | --- |
| `RET` | Open category, folder, organization, or tool |
| `g` | Refresh navigation metadata |
| `s` | Synchronize |
| `u` / `l` | Unlock / lock |
| `L` | Log out |

Lists:

| Key | Action |
| --- | --- |
| `RET` | Open detail |
| `/` | Search |
| `g` / `s` | Refresh / synchronize |
| `c` / `e` | Create / edit |
| `d` / `D` | Delete / permanently delete from Trash |
| `a` / `r` | Archive / restore |
| `C` / `M` | Clone / move to organization |
| `y` | Choose and copy a field |

Details:

| Key | Action |
| --- | --- |
| `v` | Reveal or hide the field at point |
| `y` / `i` | Copy / insert the field at point |
| `o` / `t` | Open URI / generate current TOTP |
| `A` | Add attachment |
| `w` / `x` | Download / delete attachment |
| `e`, `C`, `M` | Edit, clone, move |

Forms use `C-c C-c` to validate and save and `C-c C-k` to cancel.  Item forms
cover Login, Secure Note, Card, Identity, and SSH Key data, including folders,
favorites, master-password reprompt, URI matching, custom fields, and
organization collections.  SSH key material is entered at creation and is
read-only afterward.

## Security model

- The session key is kept only in an Emacs variable and is passed to each child
  through a process-local `BW_SESSION` value.  It is never added to the global
  Emacs environment.
- Long-lived passwords and API secrets use scoped environment variables.
  Prompts for which the CLI has no environment option use a PTY and are sent
  only after the hidden prompt appears.
- Commands are argument lists passed directly to `make-process`; no shell is
  involved.  JSON payloads are UTF-8/Base64 encoded in Emacs and sent on stdin.
- List responses are reduced immediately to metadata.  Complete decrypted
  objects live only in detail and form buffers, with undo disabled, and are
  discarded when those buffers close or the vault locks.
- Sensitive detail fields are masked by default.  TOTP values expire from the
  detail buffer after 30 seconds.
- The default `bitwarden-copy-policy` is deliberately `kill-ring`, as requested.
  Copied secrets remain in normal kill-ring history and are **not** cleared
  automatically.  Set it to `system-clipboard` if this is undesirable.
- The vault locks after 15 minutes without activity in a Bitwarden buffer.
  Auto-lock discards unsaved Bitwarden forms.  Lock and logout also clear all
  package caches and sensitive buffers.
- Export and attachment files are set to mode `0600`.  Plain JSON, CSV, and ZIP
  exports require an explicit warning confirmation.

## Asynchronous API

All supported programmatic interfaces are asynchronous.  A success callback
receives `(VALUE JOB)` and an error callback receives `(ERROR-INFO JOB)`.

```elisp
(bitwarden-api-list
 "items"
 :search "example"
 :on-success
 (lambda (items _job)
   (message "Found %d items" (length items)))
 :on-error
 (lambda (error-info _job)
   (message "%s" (bitwarden-cli-error-message error-info))))
```

`bitwarden-request` provides the lower-level queued interface and returns a
`bitwarden-job`.  `bitwarden-cancel-job` can cancel queued or running reads;
running mutations are intentionally not cancellable.

## Scope

This package manages the personal vault and organization ownership/collection
assignment exposed by `bw`.  It intentionally does not implement multi-account
profiles, organization administration, browser autofill, Passkeys, biometric
unlock, or a Bitwarden SSH Agent socket.

## Development

Tests use a fake CLI and never open the real vault.  In this workspace, all
Emacs operations are run through the existing Emacs server:

```sh
emacsclient --eval '
(progn
  (add-to-list (quote load-path) "/path/to/bitwarden.el")
  (load "/path/to/bitwarden.el/test/bitwarden-tests.el" nil t)
  (ert-run-tests-interactively "^bitwarden-test-"))'
```
