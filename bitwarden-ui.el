;;; bitwarden-ui.el --- Buffer UI for Bitwarden -*- lexical-binding: t; -*-

;; Version: 0.1.0
;; Package-Requires: ((emacs "31.1") (magit-section "4.7.1"))

;;; Commentary:

;; Independent navigator, list, detail, and form buffers for bitwarden.el.

;;; Code:

(require 'bitwarden-core)
(require 'cl-lib)
(require 'magit-section)
(require 'seq)
(require 'tabulated-list)
(require 'wid-edit)
(require 'browse-url)
(require 'url-parse)
(require 'url-util)

(defconst bitwarden-ui--item-types
  '((1 . "Login")
    (2 . "Secure Note")
    (3 . "Card")
    (4 . "Identity")
    (5 . "SSH Key")))

(defconst bitwarden-ui--login-match-types
  '((0 . "Domain")
    (1 . "Host")
    (2 . "Starts With")
    (3 . "Exact")
    (4 . "Regular Expression")
    (5 . "Never")))

(defconst bitwarden-ui--custom-field-types
  '((0 . "Text")
    (1 . "Hidden")
    (2 . "Boolean")))

(defconst bitwarden-ui--navigator-buffer "*Bitwarden Navigator*")

(defclass bitwarden-root-section (magit-section) ())
(defclass bitwarden-group-section (magit-section) ())
(defclass bitwarden-navigation-entry-section (magit-section)
  ((keymap :initform 'bitwarden-navigation-entry-section-map)))

(defvar-local bitwarden-list-kind nil)
(defvar-local bitwarden-list-filter nil)
(defvar-local bitwarden-list-title nil)
(defvar-local bitwarden-list-records nil)
(defvar-local bitwarden-detail-kind nil)
(defvar-local bitwarden-detail-object nil)
(defvar-local bitwarden-detail-revealed nil)
(defvar-local bitwarden-detail-totp nil)
(defvar-local bitwarden-detail-totp-timer nil)
(defvar-local bitwarden-form-kind nil)
(defvar-local bitwarden-form-original nil)
(defvar-local bitwarden-form-new-p nil)
(defvar-local bitwarden-form-widgets nil)
(defvar-local bitwarden-form-source-buffer nil)
(defvar-local bitwarden-form-unknown-fields nil)

(defun bitwarden-ui--display-buffer (buffer)
  "Display BUFFER without imposing a window layout."
  (if bitwarden-display-buffer-action
      (display-buffer buffer bitwarden-display-buffer-action)
    (pop-to-buffer buffer)))

(defun bitwarden-ui--error (error-info _job)
  "Display ERROR-INFO in the minibuffer."
  (message "Bitwarden: %s" (bitwarden-cli-error-message error-info)))

(defun bitwarden-ui--touch ()
  "Record activity from a Bitwarden buffer."
  (when (bitwarden-session-active-p)
    (bitwarden-touch)))

(defun bitwarden-ui--status-label ()
  "Return a concise account and status label."
  (let* ((status bitwarden--status)
         (data bitwarden--status-data)
         (email (and data (bitwarden-json-get 'userEmail data)))
         (server (and data (bitwarden-json-get 'serverUrl data))))
    (string-join
     (delq nil
           (list (format "Status: %s" (capitalize (symbol-name status)))
                 (and email (format "Account: %s" email))
                 (and server (format "Server: %s" server))))
     "   ")))

(defvar-keymap bitwarden-navigation-mode-map
  :doc "Keymap for `bitwarden-navigation-mode'."
  :parent magit-section-mode-map
  "g" #'bitwarden-navigation-refresh
  "s" #'bitwarden-sync
  "u" #'bitwarden-unlock
  "l" #'bitwarden-lock
  "L" #'bitwarden-logout
  "q" #'quit-window)

(defvar-keymap bitwarden-navigation-entry-section-map
  :doc "Keymap for actionable Bitwarden navigation sections."
  :parent magit-section-mode-map
  "RET" #'bitwarden-navigation-open-at-point)

(define-derived-mode bitwarden-navigation-mode magit-section-mode "Bitwarden-Nav"
  "Major mode for the Bitwarden navigator."
  (setq-local truncate-lines t)
  (add-hook 'post-command-hook #'bitwarden-ui--touch nil t))

(defvar-keymap bitwarden-list-mode-map
  :doc "Keymap for `bitwarden-list-mode'."
  :parent tabulated-list-mode-map
  "RET" #'bitwarden-list-open
  "/" #'bitwarden-list-search
  "g" #'bitwarden-list-refresh
  "s" #'bitwarden-list-sync
  "c" #'bitwarden-list-create
  "e" #'bitwarden-list-edit
  "d" #'bitwarden-list-delete
  "D" #'bitwarden-list-delete-permanently
  "a" #'bitwarden-list-archive
  "r" #'bitwarden-list-restore
  "y" #'bitwarden-list-copy
  "C" #'bitwarden-list-clone
  "M" #'bitwarden-list-move
  "q" #'quit-window)

(define-derived-mode bitwarden-list-mode tabulated-list-mode "Bitwarden-List"
  "Major mode for Bitwarden item, folder, and Send lists."
  (setq-local truncate-lines t)
  (setq-local tabulated-list-padding 2)
  (setq-local tabulated-list-sort-key '("Name" . nil))
  (add-hook 'post-command-hook #'bitwarden-ui--touch nil t)
  (tabulated-list-init-header))

(defun bitwarden-ui-open ()
  "Open Bitwarden, authenticating and synchronizing when necessary."
  (interactive)
  (bitwarden-api-status
   :on-success
   (lambda (data _job)
     (pcase (intern (downcase (bitwarden-json-get 'status data "unknown")))
       ('unauthenticated (bitwarden-login #'bitwarden-ui--ready))
       ('locked (bitwarden-unlock #'bitwarden-ui--ready))
       ('unlocked
        (if (bitwarden-session-active-p)
            (bitwarden-ui--ready)
          (bitwarden-unlock #'bitwarden-ui--ready)))
       (status (message "Unknown Bitwarden status: %s" status))))
   :on-error #'bitwarden-ui--error))

(defun bitwarden-ui--ready ()
  "Open the navigator and apply the configured initial sync policy."
  (if (eq bitwarden-sync-policy 'open-and-after-write)
      (bitwarden-sync #'bitwarden-navigation-open)
    (bitwarden-navigation-open)))

(defun bitwarden-ui--read-two-step ()
  "Prompt for an optional supported two-step method and return (METHOD . CODE)."
  (let* ((choice
          (completing-read
           "Two-step method: "
           '("None" "Authenticator" "Email" "YubiKey")
           nil t nil nil "None"))
         (method (pcase choice
                   ("Authenticator" 0)
                   ("Email" 1)
                   ("YubiKey" 3))))
    (cons method (and method (read-passwd "Two-step code: ")))))

(defun bitwarden-ui--login-prompt-handler (prompt)
  "Read an additional login response appropriate for CLI PROMPT."
  (cond
   ((string-match-p "New device verification" prompt)
    (read-passwd "New device email OTP: "))
   ((string-match-p "Two-step" prompt)
    (read-passwd "Two-step code: "))
   (t (read-passwd "Bitwarden verification response: "))))

(defun bitwarden-login (&optional callback)
  "Log in to Bitwarden and invoke CALLBACK when the vault is unlocked."
  (interactive)
  (let* ((choice (completing-read
                  "Login method: "
                  '("Password" "API Key" "SSO") nil t nil nil "Password"))
         (error-callback #'bitwarden-ui--error))
    (pcase choice
      ("Password"
       (let* ((email (read-string
                      "Email: "
                      (bitwarden-json-get
                       'userEmail bitwarden--status-data "")))
              (password (read-passwd "Master password: "))
              (two-step (bitwarden-ui--read-two-step))
              (method (car two-step))
              (code (cdr two-step)))
         (bitwarden-api-login
          'password :email email :password password
          :two-step-method method :two-step-code code
          :prompt-handler #'bitwarden-ui--login-prompt-handler
          :on-success (lambda (_session _job)
                        (message "Bitwarden logged in and unlocked")
                        (when callback (funcall callback)))
          :on-error error-callback)))
      ("API Key"
       (let ((client-id (read-string "Client ID: "))
             (client-secret (read-passwd "Client secret: ")))
         (bitwarden-api-login
          'api-key :client-id client-id :client-secret client-secret
          :on-success (lambda (_data _job)
                        (message "API login succeeded; unlock the vault")
                        (bitwarden-unlock callback))
          :on-error error-callback)))
      ("SSO"
       (let* ((identifier (read-string "Organization identifier (optional): "))
              (two-step (bitwarden-ui--read-two-step)))
         (bitwarden-api-login
          'sso :sso-identifier identifier
          :two-step-method (car two-step) :two-step-code (cdr two-step)
          :prompt-handler #'bitwarden-ui--login-prompt-handler
          :on-success (lambda (_data _job)
                        (message "SSO login succeeded; unlock the vault")
                        (bitwarden-unlock callback))
          :on-error error-callback))))))

(defun bitwarden-unlock (&optional callback)
  "Unlock the vault and invoke CALLBACK on success."
  (interactive)
  (let ((password (read-passwd "Master password: ")))
    (bitwarden-api-unlock
     password
     :on-success (lambda (_session _job)
                   (message "Bitwarden unlocked")
                   (when callback (funcall callback)))
     :on-error #'bitwarden-ui--error)))

(defun bitwarden-ui--dirty-form-buffers ()
  "Return modified Bitwarden form buffers."
  (seq-filter
   (lambda (buffer)
     (with-current-buffer buffer
       (and (eq major-mode 'bitwarden-form-mode)
            (buffer-modified-p))))
   (buffer-list)))

(defun bitwarden-lock ()
  "Lock Bitwarden and destroy sensitive buffers."
  (interactive)
  (when (or (null (bitwarden-ui--dirty-form-buffers))
            (yes-or-no-p "Discard unsaved Bitwarden forms and lock? "))
    (bitwarden-api-lock
     :on-success (lambda (_data _job) (message "Bitwarden locked"))
     :on-error #'bitwarden-ui--error)))

(defun bitwarden-logout ()
  "Log out the current Bitwarden CLI account."
  (interactive)
  (when (yes-or-no-p "Log out of the current Bitwarden account? ")
    (bitwarden-api-logout
     :on-success (lambda (_data _job) (message "Bitwarden logged out"))
     :on-error #'bitwarden-ui--error)))

(defun bitwarden-sync (&optional callback)
  "Synchronize the vault and invoke CALLBACK afterward."
  (interactive)
  (bitwarden-api-sync
   :on-success
   (lambda (_data _job)
     (message "Bitwarden synchronized")
     (run-hooks 'bitwarden-after-sync-hook)
     (when callback (funcall callback)))
   :on-error
   (lambda (error-info job)
     (bitwarden-ui--error error-info job)
     (when callback (funcall callback)))))

(defun bitwarden-configure-server (&optional advanced)
  "Configure the Bitwarden server, with endpoint overrides when ADVANCED."
  (interactive "P")
  (let* ((current (bitwarden-json-get
                   'serverUrl bitwarden--status-data "https://bitwarden.com"))
         (url (read-string "Server URL: " current))
         (web (and advanced (read-string "Web vault override (optional): ")))
         (api (and advanced (read-string "API override (optional): ")))
         (identity (and advanced (read-string "Identity override (optional): ")))
         (icons (and advanced (read-string "Icons override (optional): ")))
         (notifications
          (and advanced (read-string "Notifications override (optional): ")))
         (events (and advanced (read-string "Events override (optional): ")))
         (key-connector
          (and advanced (read-string "Key Connector override (optional): "))))
    (bitwarden-api-config-server
     url
     :web-vault (and web (not (string-empty-p web)) web)
     :api (and api (not (string-empty-p api)) api)
     :identity (and identity (not (string-empty-p identity)) identity)
     :icons (and icons (not (string-empty-p icons)) icons)
     :notifications (and notifications
                         (not (string-empty-p notifications)) notifications)
     :events (and events (not (string-empty-p events)) events)
     :key-connector (and key-connector
                         (not (string-empty-p key-connector)) key-connector)
     :on-success
     (lambda (_data _job)
       (message "Bitwarden server configured; log in to continue")
       (bitwarden-api-status))
     :on-error #'bitwarden-ui--error)))

(defun bitwarden-navigation-open ()
  "Open the Bitwarden navigator buffer."
  (interactive)
  (let ((buffer (get-buffer-create bitwarden-ui--navigator-buffer)))
    (with-current-buffer buffer
      (bitwarden-navigation-mode)
      (bitwarden-navigation-render))
    (bitwarden-ui--display-buffer buffer)
    (when (bitwarden-session-active-p)
      (bitwarden-navigation-refresh))))

(defun bitwarden-navigation-render ()
  "Render the current navigator buffer."
  (when (eq major-mode 'bitwarden-navigation-mode)
    (let ((inhibit-read-only t)
          (point-line (line-number-at-pos)))
      (erase-buffer)
      (magit-insert-section (bitwarden-root-section)
        (insert (propertize "Bitwarden\n" 'face '(:height 1.4 :weight bold)))
        (insert (bitwarden-ui--status-label) "\n")
        (if (not (bitwarden-session-active-p))
            (magit-insert-section (bitwarden-group-section 'account)
              (magit-insert-heading "Account")
              (bitwarden-navigation--insert-node
               "Unlock vault" (lambda () (bitwarden-unlock
                                       #'bitwarden-navigation-refresh)))
              (bitwarden-navigation--insert-node
               "Log in" (lambda () (bitwarden-login
                                 #'bitwarden-navigation-refresh)))
              (bitwarden-navigation--insert-node
               "Configure server" #'bitwarden-configure-server))
          (magit-insert-section (bitwarden-group-section 'vault)
            (magit-insert-heading "Vault")
            (bitwarden-navigation--insert-node
             "All Items" (lambda ()
                           (bitwarden-list-open-buffer
                            'items "All Items" nil)))
            (bitwarden-navigation--insert-node
             "Favorites" (lambda ()
                           (bitwarden-list-open-buffer
                            'items "Favorites" '(:favorite t))))
            (dolist (entry bitwarden-ui--item-types)
              (let ((type (car entry)) (label (cdr entry)))
                (bitwarden-navigation--insert-node
                 label
                 (lambda ()
                   (bitwarden-list-open-buffer
                    'items label (list :type type)))))))
          (magit-insert-section (bitwarden-group-section 'folders)
            (magit-insert-heading "Folders")
            (bitwarden-navigation--insert-node
             "Manage Folders" (lambda ()
                                (bitwarden-list-open-buffer
                                 'folders "Folders" nil)))
            (dolist (folder (append
                             (gethash 'folders bitwarden--metadata-cache) nil))
              (let ((id (bitwarden-json-get 'id folder))
                    (name (bitwarden-json-get 'name folder "Unnamed Folder")))
                (bitwarden-navigation--insert-node
                 name
                 (lambda ()
                   (bitwarden-list-open-buffer
                    'items (format "Folder: %s" name)
                    (list :folder-id id)))
                 2))))
          (magit-insert-section (bitwarden-group-section 'organizations)
            (magit-insert-heading "Organizations and Collections")
            (dolist (organization
                     (append
                      (gethash 'organizations bitwarden--metadata-cache) nil))
              (let ((org-id (bitwarden-json-get 'id organization))
                    (org-name
                     (bitwarden-json-get 'name organization "Organization")))
                (bitwarden-navigation--insert-node
                 org-name
                 (lambda ()
                   (bitwarden-list-open-buffer
                    'items (format "Organization: %s" org-name)
                    (list :organization-id org-id))))
                (dolist (collection
                         (bitwarden-navigation--collections-for org-id))
                  (let ((collection-id (bitwarden-json-get 'id collection))
                        (collection-name
                         (bitwarden-json-get 'name collection "Collection")))
                    (bitwarden-navigation--insert-node
                     collection-name
                     (lambda ()
                       (bitwarden-list-open-buffer
                        'items (format "Collection: %s" collection-name)
                        (list :collection-id collection-id)))
                     2))))))
          (magit-insert-section (bitwarden-group-section 'lifecycle)
            (magit-insert-heading "Lifecycle")
            (bitwarden-navigation--insert-node
             "Archive" (lambda ()
                         (bitwarden-list-open-buffer
                          'items "Archive" '(:archived t))))
            (bitwarden-navigation--insert-node
             "Trash" (lambda ()
                       (bitwarden-list-open-buffer
                        'items "Trash" '(:trash t)))))
          (magit-insert-section (bitwarden-group-section 'send)
            (magit-insert-heading "Send")
            (bitwarden-navigation--insert-node
             "Owned Sends" (lambda ()
                             (bitwarden-list-open-buffer
                              'sends "Sends" nil))))
          (magit-insert-section (bitwarden-group-section 'tools)
            (magit-insert-heading "Tools")
            (bitwarden-navigation--insert-node "Generator" #'bitwarden-generate)
            (bitwarden-navigation--insert-node "Import" #'bitwarden-import)
            (bitwarden-navigation--insert-node "Export" #'bitwarden-export)
            (bitwarden-navigation--insert-node
             "Configure server" #'bitwarden-configure-server))))
      (goto-char (point-min))
      (forward-line (max 0 (1- point-line))))))

(defun bitwarden-navigation--insert-node (label action &optional indent)
  "Insert navigator LABEL invoking ACTION, indented by INDENT spaces."
  (magit-insert-section (bitwarden-navigation-entry-section action)
    (magit-insert-heading
      (propertize (concat (make-string (or indent 0) ?\s) label)
                  'face 'default))))

(defun bitwarden-navigation-open-at-point ()
  "Invoke the navigator entry at point."
  (interactive)
  (let ((section (magit-current-section)))
    (if (cl-typep section 'bitwarden-navigation-entry-section)
        (funcall (oref section value))
      (user-error "No Bitwarden entry at point"))))

(defun bitwarden-navigation--collections ()
  "Return the combined cached collection list."
  (seq-uniq
   (append (gethash 'collections bitwarden--metadata-cache)
           (gethash 'org-collections bitwarden--metadata-cache))
   (lambda (left right)
     (equal (bitwarden-json-get 'id left)
            (bitwarden-json-get 'id right)))))

(defun bitwarden-navigation--collections-for (organization-id)
  "Return cached collections belonging to ORGANIZATION-ID."
  (seq-filter
   (lambda (collection)
     (equal (bitwarden-json-get 'organizationId collection) organization-id))
   (bitwarden-navigation--collections)))

(defun bitwarden-navigation-refresh ()
  "Refresh folders, organizations, and collections."
  (interactive)
  (unless (bitwarden-session-active-p)
    (user-error "Unlock Bitwarden first"))
  (dolist (spec '(("folders" . folders)
                  ("organizations" . organizations)
                  ("collections" . collections)
                  ("org-collections" . org-collections)))
    (let ((object (car spec)) (cache-key (cdr spec)))
      (bitwarden-api-list
       object
       :on-success
       (lambda (data _job)
         (puthash cache-key data bitwarden--metadata-cache)
         (when-let* ((buffer (get-buffer bitwarden-ui--navigator-buffer)))
           (with-current-buffer buffer (bitwarden-navigation-render))))
       :on-error
       (lambda (error-info _job)
         (message "Bitwarden could not list %s: %s"
                  object (bitwarden-cli-error-message error-info)))))))

(defun bitwarden-ui--configure-list-columns ()
  "Set list columns for the current `bitwarden-list-kind'."
  (setq tabulated-list-format
        (pcase bitwarden-list-kind
          ('items
           [("Name" 32 t)
            ("Type" 14 t)
            ("Folder" 20 t)
            ("Owner" 18 t)
            ("Fav" 4 t)
            ("Updated" 20 t)])
          ('folders
           [("Name" 42 t)
            ("ID" 38 t)])
          ('sends
           [("Name" 32 t)
            ("Type" 10 t)
            ("Accesses" 10 t)
            ("Expires" 20 t)
            ("Deletes" 20 t)])
          (_ [("Name" 40 t)])))
  (setq tabulated-list-sort-key '("Name" . nil))
  (tabulated-list-init-header))

(defun bitwarden-list-open-buffer (kind title filter)
  "Open a KIND list named TITLE using FILTER plist."
  (let* ((name (format "*Bitwarden %s*" title))
         (buffer (get-buffer-create name)))
    (with-current-buffer buffer
      (bitwarden-list-mode)
      (setq-local bitwarden-list-kind kind
                  bitwarden-list-title title
                  bitwarden-list-filter (copy-sequence filter)
                  bitwarden-list-records (make-hash-table :test #'equal))
      (bitwarden-ui--configure-list-columns)
      (setq-local header-line-format
                  (format " %s   Loading…" title)))
    (bitwarden-ui--display-buffer buffer)
    (with-current-buffer buffer (bitwarden-list-refresh))))

(defun bitwarden-ui--item-type-name (type)
  "Return a display name for numeric item TYPE."
  (or (alist-get type bitwarden-ui--item-types)
      (format "Unknown (%s)" type)))

(defun bitwarden-ui--name-by-id (cache-key id)
  "Find ID's name in cached CACHE-KEY objects."
  (when id
    (let ((object
           (seq-find
            (lambda (candidate)
              (equal id (bitwarden-json-get 'id candidate)))
            (append (gethash cache-key bitwarden--metadata-cache) nil))))
      (and object (bitwarden-json-get 'name object)))))

(defun bitwarden-ui--folder-name (id)
  "Return the cached folder name for ID."
  (or (bitwarden-ui--name-by-id 'folders id) ""))

(defun bitwarden-ui--organization-name (id)
  "Return the cached organization name for ID."
  (or (bitwarden-ui--name-by-id 'organizations id)
      (and id "Organization")
      "Personal"))

(defun bitwarden-ui--short-date (value)
  "Return a compact rendering of ISO date VALUE."
  (if (null value)
      ""
    (replace-regexp-in-string
     "\\.[0-9]+Z\\'" "Z"
     (replace-regexp-in-string "T" " " value))))

(defun bitwarden-list--record-at-point ()
  "Return the metadata object at point."
  (let ((id (tabulated-list-get-id)))
    (and id (gethash id bitwarden-list-records))))

(defun bitwarden-list--item-matches-local-filter-p (item)
  "Return non-nil when metadata ITEM matches local filters."
  (and
   (let ((type (plist-get bitwarden-list-filter :type)))
     (or (null type) (= type (or (bitwarden-json-get 'type item) -1))))
   (let ((favorite (plist-get bitwarden-list-filter :favorite)))
     (or (null favorite)
         (and favorite (eq (bitwarden-json-get 'favorite item :false) t))))))

(defun bitwarden-list--set-entries (records)
  "Install sanitized RECORDS in the current list buffer."
  (clrhash bitwarden-list-records)
  (setq tabulated-list-entries
          (mapcar
           (lambda (record)
             (let ((id (bitwarden-json-get 'id record)))
               (puthash id record bitwarden-list-records)
               (pcase bitwarden-list-kind
                 ('items
                  (list
                   id
                   (vector
                    (or (bitwarden-json-get 'name record) "")
                    (bitwarden-ui--item-type-name
                     (bitwarden-json-get 'type record))
                    (bitwarden-ui--folder-name
                     (bitwarden-json-get 'folderId record))
                    (bitwarden-ui--organization-name
                     (bitwarden-json-get 'organizationId record))
                    (if (eq (bitwarden-json-get 'favorite record :false) t)
                        "★" "")
                    (bitwarden-ui--short-date
                     (bitwarden-json-get 'revisionDate record)))))
                 ('folders
                  (list id
                        (vector (or (bitwarden-json-get 'name record) "")
                                (or id ""))))
                 ('sends
                  (list
                   id
                   (vector
                    (or (bitwarden-json-get 'name record) "")
                    (if (= (or (bitwarden-json-get 'type record) 0) 0)
                        "Text" "File")
                    (format "%s/%s"
                            (or (bitwarden-json-get 'accessCount record) 0)
                            (or (bitwarden-json-get 'maxAccessCount record) "∞"))
                    (bitwarden-ui--short-date
                     (bitwarden-json-get 'expirationDate record))
                    (bitwarden-ui--short-date
                     (bitwarden-json-get 'deletionDate record))))))))
           records))
  ;; A non-nil REMEMBER-POS lets `tabulated-list-print' restore by entry ID.
  (tabulated-list-print t)
  (setq header-line-format
        (format " %s   %d entries   / search   g refresh   s sync"
                bitwarden-list-title (length records))))

(defun bitwarden-list-refresh ()
  "Refresh the current Bitwarden list."
  (interactive)
  (unless (bitwarden-session-active-p)
    (setq tabulated-list-entries nil
          header-line-format " Bitwarden is locked")
    (tabulated-list-print t)
    (user-error "Unlock Bitwarden first"))
  (setq header-line-format (format " %s   Loading…" bitwarden-list-title))
  (pcase bitwarden-list-kind
    ('items
     (let ((buffer (current-buffer)))
       (bitwarden-api-list
        "items"
        :search (plist-get bitwarden-list-filter :search)
        :folder-id (plist-get bitwarden-list-filter :folder-id)
        :collection-id (plist-get bitwarden-list-filter :collection-id)
        :organization-id (plist-get bitwarden-list-filter :organization-id)
        :trash (plist-get bitwarden-list-filter :trash)
        :archived (plist-get bitwarden-list-filter :archived)
        :on-success
        (lambda (data _job)
          (when (buffer-live-p buffer)
            (with-current-buffer buffer
              (bitwarden-list--set-entries
               (seq-filter
                #'bitwarden-list--item-matches-local-filter-p
                (mapcar #'bitwarden-item-metadata
                        (append data nil)))))))
        :on-error #'bitwarden-ui--error)))
    ('folders
     (let ((buffer (current-buffer)))
       (bitwarden-api-list
        "folders" :search (plist-get bitwarden-list-filter :search)
        :on-success
        (lambda (data _job)
          (puthash 'folders data bitwarden--metadata-cache)
          (when (buffer-live-p buffer)
            (with-current-buffer buffer
              (bitwarden-list--set-entries (append data nil)))))
        :on-error #'bitwarden-ui--error)))
    ('sends
     (let ((buffer (current-buffer)))
       (bitwarden-api-send-list
        :on-success
        (lambda (data _job)
          (when (buffer-live-p buffer)
            (with-current-buffer buffer
              (let ((metadata (mapcar #'bitwarden-send-metadata
                                      (append data nil)))
                    (search (plist-get bitwarden-list-filter :search)))
                (when search
                  (setq metadata
                        (seq-filter
                         (lambda (send)
                           (string-match-p
                            (regexp-quote (downcase search))
                            (downcase (or (bitwarden-json-get 'name send) ""))))
                         metadata)))
                (bitwarden-list--set-entries metadata)))))
        :on-error #'bitwarden-ui--error)))))

(defun bitwarden-list-search ()
  "Set the current list's CLI search term."
  (interactive)
  (let ((search (read-string
                 "Search (empty clears): "
                 (or (plist-get bitwarden-list-filter :search) ""))))
    (setq bitwarden-list-filter
          (plist-put bitwarden-list-filter :search
                     (and (not (string-empty-p search)) search)))
    (bitwarden-list-refresh)))

(defun bitwarden-list-sync ()
  "Synchronize then refresh the current list."
  (interactive)
  (bitwarden-sync))

(defun bitwarden-list-open ()
  "Open the object at point."
  (interactive)
  (let ((record (or (bitwarden-list--record-at-point)
                    (user-error "No Bitwarden object at point"))))
    (pcase bitwarden-list-kind
      ('items (bitwarden-detail-open-item record))
      ('folders
       (let ((id (bitwarden-json-get 'id record))
             (name (bitwarden-json-get 'name record "Folder")))
         (bitwarden-list-open-buffer
          'items (format "Folder: %s" name) (list :folder-id id))))
      ('sends (bitwarden-detail-open-send record)))))

(defun bitwarden-list-create ()
  "Create an object appropriate for the current list."
  (interactive)
  (pcase bitwarden-list-kind
    ('items (bitwarden-create-item))
    ('folders (bitwarden-create-folder))
    ('sends (bitwarden-create-send))
    (_ (user-error "Creation is not available here"))))

(defun bitwarden-list-edit ()
  "Edit the object at point."
  (interactive)
  (let ((record (or (bitwarden-list--record-at-point)
                    (user-error "No Bitwarden object at point"))))
    (pcase bitwarden-list-kind
      ('items (bitwarden-edit-item record))
      ('folders (bitwarden-edit-folder record))
      ('sends (bitwarden-edit-send record))
      (_ (user-error "Editing is not available here")))))

(defun bitwarden-list-delete ()
  "Delete the object at point, soft-deleting vault items."
  (interactive)
  (let* ((record (or (bitwarden-list--record-at-point)
                     (user-error "No Bitwarden object at point")))
         (id (bitwarden-json-get 'id record))
         (name (bitwarden-json-get 'name record "object"))
         (buffer (current-buffer)))
    (when (yes-or-no-p (format "Delete %s? " name))
      (pcase bitwarden-list-kind
        ('items
         (bitwarden-api-delete
          "item" id
          :on-success (lambda (_data _job)
                        (message "Moved %s to trash" name)
                        (when (buffer-live-p buffer)
                          (with-current-buffer buffer
                            (bitwarden-list-refresh))))
          :on-error #'bitwarden-ui--error))
        ('folders
         (bitwarden-api-delete
          "folder" id
          :on-success (lambda (_data _job)
                        (message "Deleted folder %s" name)
                        (when (buffer-live-p buffer)
                          (with-current-buffer buffer
                            (bitwarden-list-refresh))))
          :on-error #'bitwarden-ui--error))
        ('sends
         (bitwarden-api-send-delete
          id
          :on-success (lambda (_data _job)
                        (message "Deleted Send %s" name)
                        (when (buffer-live-p buffer)
                          (with-current-buffer buffer
                            (bitwarden-list-refresh))))
          :on-error #'bitwarden-ui--error))))))

(defun bitwarden-list-delete-permanently ()
  "Permanently delete the trash item at point."
  (interactive)
  (unless (and (eq bitwarden-list-kind 'items)
               (plist-get bitwarden-list-filter :trash))
    (user-error "Permanent deletion is only available from Trash"))
  (let* ((record (or (bitwarden-list--record-at-point)
                     (user-error "No Bitwarden item at point")))
         (id (bitwarden-json-get 'id record))
         (name (bitwarden-json-get 'name record "item"))
         (confirmation (read-string
                        (format "Type %s to permanently delete: " name))))
    (unless (string= confirmation name)
      (user-error "Name did not match; deletion cancelled"))
    (let ((buffer (current-buffer)))
      (bitwarden-api-delete
       "item" id :permanent t
       :on-success (lambda (_data _job)
                     (message "Permanently deleted %s" name)
                     (when (buffer-live-p buffer)
                       (with-current-buffer buffer
                         (bitwarden-list-refresh))))
       :on-error #'bitwarden-ui--error))))

(defun bitwarden-list-archive ()
  "Archive the item at point."
  (interactive)
  (unless (eq bitwarden-list-kind 'items)
    (user-error "Only vault items can be archived"))
  (let* ((record (or (bitwarden-list--record-at-point)
                     (user-error "No Bitwarden item at point")))
         (id (bitwarden-json-get 'id record))
         (name (bitwarden-json-get 'name record "item"))
         (buffer (current-buffer)))
    (bitwarden-api-archive
     id
     :on-success (lambda (_data _job)
                   (message "Archived %s" name)
                   (when (buffer-live-p buffer)
                     (with-current-buffer buffer (bitwarden-list-refresh))))
     :on-error #'bitwarden-ui--error)))

(defun bitwarden-list-restore ()
  "Restore the trash or archive item at point."
  (interactive)
  (unless (and (eq bitwarden-list-kind 'items)
               (or (plist-get bitwarden-list-filter :trash)
                   (plist-get bitwarden-list-filter :archived)))
    (user-error "Restore is only available from Archive or Trash"))
  (let* ((record (or (bitwarden-list--record-at-point)
                     (user-error "No Bitwarden item at point")))
         (id (bitwarden-json-get 'id record))
         (name (bitwarden-json-get 'name record "item"))
         (buffer (current-buffer)))
    (bitwarden-api-restore
     id
     :on-success (lambda (_data _job)
                   (message "Restored %s" name)
                   (when (buffer-live-p buffer)
                     (with-current-buffer buffer (bitwarden-list-refresh))))
     :on-error #'bitwarden-ui--error)))

(defun bitwarden-list-copy ()
  "Copy a selected field from the item at point."
  (interactive)
  (unless (eq bitwarden-list-kind 'items)
    (user-error "Copy is only available for vault items"))
  (let ((record (or (bitwarden-list--record-at-point)
                    (user-error "No Bitwarden item at point"))))
    (bitwarden-ui--with-reprompt
     record
     (lambda ()
       (bitwarden-api-get
        "item" (bitwarden-json-get 'id record)
        :on-success (lambda (item _job)
                      (bitwarden-ui--choose-and-copy item))
        :on-error #'bitwarden-ui--error)))))

;;; Detail buffers

(defvar-keymap bitwarden-detail-mode-map
  :doc "Keymap for `bitwarden-detail-mode'."
  :parent magit-section-mode-map
  "v" #'bitwarden-detail-toggle-secret
  "y" #'bitwarden-detail-copy
  "i" #'bitwarden-detail-insert
  "o" #'bitwarden-detail-open-uri
  "t" #'bitwarden-detail-show-totp
  "e" #'bitwarden-detail-edit
  "C" #'bitwarden-detail-clone
  "M" #'bitwarden-detail-move
  "d" #'bitwarden-detail-delete
  "a" #'bitwarden-detail-archive
  "r" #'bitwarden-detail-restore
  "A" #'bitwarden-detail-add-attachment
  "w" #'bitwarden-detail-download-attachment
  "x" #'bitwarden-detail-delete-attachment
  "g" #'bitwarden-detail-refresh
  "s" #'bitwarden-sync
  "q" #'quit-window)

(define-derived-mode bitwarden-detail-mode magit-section-mode "Bitwarden-Detail"
  "Major mode for a decrypted Bitwarden object."
  (setq-local truncate-lines nil)
  (setq-local bitwarden-detail-revealed (make-hash-table :test #'equal))
  (buffer-disable-undo)
  (cl-pushnew (current-buffer) bitwarden--sensitive-buffers)
  (add-hook 'post-command-hook #'bitwarden-ui--touch nil t)
  (add-hook 'kill-buffer-hook #'bitwarden-detail--cleanup nil t))

(defun bitwarden-detail--cleanup ()
  "Release state owned by the current detail buffer."
  (when (timerp bitwarden-detail-totp-timer)
    (cancel-timer bitwarden-detail-totp-timer))
  (setq bitwarden-detail-totp-timer nil)
  (setq bitwarden-detail-object nil
        bitwarden-detail-totp nil)
  (setq bitwarden--sensitive-buffers
        (delq (current-buffer) bitwarden--sensitive-buffers)))

(defun bitwarden-ui--with-reprompt (metadata callback)
  "Invoke CALLBACK after honoring METADATA's master-password reprompt flag."
  (if (= (or (bitwarden-json-get 'reprompt metadata) 0) 1)
      (let ((password (read-passwd "Master password required for this item: ")))
        (bitwarden-api-unlock
         password
         :on-success (lambda (_session _job) (funcall callback))
         :on-error #'bitwarden-ui--error))
    (funcall callback)))

(defun bitwarden-detail-open-item (metadata)
  "Fetch and open the item represented by METADATA."
  (bitwarden-ui--with-reprompt
   metadata
   (lambda ()
     (bitwarden-api-get
      "item" (bitwarden-json-get 'id metadata)
      :on-success
      (lambda (item _job)
        (bitwarden-detail--open 'item item))
      :on-error #'bitwarden-ui--error))))

(defun bitwarden-detail-open-send (metadata)
  "Fetch and open the Send represented by METADATA."
  (bitwarden-api-send-get
   (bitwarden-json-get 'id metadata)
   :on-success (lambda (send _job)
                 (bitwarden-detail--open 'send send))
   :on-error #'bitwarden-ui--error))

(defun bitwarden-detail--open (kind object)
  "Open decrypted OBJECT of KIND in a sensitive detail buffer."
  (let* ((name (or (bitwarden-json-get 'name object) "Object"))
         (buffer (get-buffer-create
                  (format "*Bitwarden %s: %s*"
                          (capitalize (symbol-name kind)) name))))
    (with-current-buffer buffer
      (bitwarden-detail-mode)
      (setq-local bitwarden-detail-kind kind
                  bitwarden-detail-object object)
      (bitwarden-detail-render))
    (bitwarden-ui--display-buffer buffer)))

(defun bitwarden-detail--stringify (value)
  "Return a human-readable string for JSON VALUE."
  (cond
   ((null value) "")
   ((eq value :false) "No")
   ((eq value t) "Yes")
   ((stringp value) value)
   ((numberp value) (number-to-string value))
   ((vectorp value)
    (mapconcat #'bitwarden-detail--stringify (append value nil) ", "))
   (t (format "%s" value))))

(defun bitwarden-detail--insert-field (label value &optional secret path)
  "Insert a LABEL and VALUE line, marking SECRET at PATH when supplied."
  (let* ((path (or path (list (intern (downcase label)))))
         (revealed (gethash (prin1-to-string path)
                            bitwarden-detail-revealed))
         (start (point))
         (rendered (if (and secret (not revealed))
                       bitwarden-mask-string
                     (bitwarden-detail--stringify value))))
    (insert (propertize (format "%-18s " (concat label ":")) 'face 'bold))
    (insert (if (string-empty-p rendered) "(empty)" rendered) "\n")
    (add-text-properties
     start (point)
     `(bitwarden-field-path ,path
       bitwarden-field-secret ,secret
       bitwarden-field-literal ,(and (not secret) value)
       mouse-face highlight
       help-echo ,(if secret "v: reveal/hide, y: copy" "y: copy")))))

(defun bitwarden-detail--collection-names (ids)
  "Return comma-separated cached collection names for IDS."
  (mapconcat
   (lambda (id)
     (or (let ((collection
                (seq-find
                 (lambda (candidate)
                   (equal id (bitwarden-json-get 'id candidate)))
                 (bitwarden-navigation--collections))))
           (and collection (bitwarden-json-get 'name collection)))
         id))
   (append ids nil) ", "))

(defun bitwarden-detail--render-common (item)
  "Render common ITEM fields."
  (bitwarden-detail--insert-field "Name" (bitwarden-json-get 'name item))
  (bitwarden-detail--insert-field
   "Type" (bitwarden-ui--item-type-name (bitwarden-json-get 'type item)))
  (bitwarden-detail--insert-field
   "Favorite" (if (eq (bitwarden-json-get 'favorite item :false) t) "Yes" "No"))
  (bitwarden-detail--insert-field
   "Folder" (or (bitwarden-ui--folder-name
                 (bitwarden-json-get 'folderId item)) ""))
  (bitwarden-detail--insert-field
   "Owner" (bitwarden-ui--organization-name
            (bitwarden-json-get 'organizationId item)))
  (bitwarden-detail--insert-field
   "Collections"
   (bitwarden-detail--collection-names
    (bitwarden-json-get 'collectionIds item)))
  (bitwarden-detail--insert-field
   "Reprompt" (if (= (or (bitwarden-json-get 'reprompt item) 0) 1)
                    "Required" "No"))
  (let ((notes (bitwarden-json-get 'notes item)))
    (when (and notes (not (string-empty-p notes)))
      (magit-insert-section (bitwarden-group-section 'notes)
        (magit-insert-heading "Notes")
        (bitwarden-detail--insert-field "Notes" notes nil '(notes))))))

(defun bitwarden-detail--render-login (item)
  "Render login-specific fields from ITEM."
  (let ((login (bitwarden-json-get 'login item)))
    (magit-insert-section (bitwarden-group-section 'login)
      (magit-insert-heading "Login")
      (bitwarden-detail--insert-field
       "Username" (bitwarden-json-get 'username login) nil '(login username))
      (bitwarden-detail--insert-field
       "Password" (bitwarden-json-get 'password login) t '(login password))
      (let ((uris (append (bitwarden-json-get 'uris login) nil)))
        (cl-loop for uri in uris
                 for index from 0
                 do (bitwarden-detail--insert-field
                     (format "URI %d" (1+ index))
                     (format "%s  [%s]"
                             (or (bitwarden-json-get 'uri uri) "")
                             (or (alist-get
                                  (bitwarden-json-get 'match uri)
                                  bitwarden-ui--login-match-types)
                                 "Default"))
                     nil (list 'login 'uris index 'uri))))
      (when (bitwarden-json-get 'totp login)
        (bitwarden-detail--insert-field
         "TOTP" (or bitwarden-detail-totp "Press t to generate")
         t '(:totp))))))

(defun bitwarden-detail--render-card (item)
  "Render card-specific fields from ITEM."
  (let ((card (bitwarden-json-get 'card item)))
    (magit-insert-section (bitwarden-group-section 'card)
      (magit-insert-heading "Card")
      (dolist (entry '(("Cardholder" cardholderName nil)
                       ("Brand" brand nil)
                       ("Number" number t)
                       ("Expiry month" expMonth nil)
                       ("Expiry year" expYear nil)
                       ("Security code" code t)))
        (bitwarden-detail--insert-field
         (nth 0 entry) (bitwarden-json-get (nth 1 entry) card)
         (nth 2 entry) (list 'card (nth 1 entry)))))))

(defun bitwarden-detail--render-identity (item)
  "Render identity-specific fields from ITEM."
  (let ((identity (bitwarden-json-get 'identity item)))
    (magit-insert-section (bitwarden-group-section 'identity)
      (magit-insert-heading "Identity")
      (dolist
          (entry
           '(("Title" title nil)
             ("First name" firstName nil)
             ("Middle name" middleName nil)
             ("Last name" lastName nil)
             ("Company" company nil)
             ("Email" email nil)
             ("Phone" phone nil)
             ("Username" username nil)
             ("Address 1" address1 nil)
             ("Address 2" address2 nil)
             ("Address 3" address3 nil)
             ("City" city nil)
             ("State" state nil)
             ("Postal code" postalCode nil)
             ("Country" country nil)
             ("SSN" ssn t)
             ("Passport" passportNumber t)
             ("License" licenseNumber t)))
        (bitwarden-detail--insert-field
         (nth 0 entry) (bitwarden-json-get (nth 1 entry) identity)
         (nth 2 entry) (list 'identity (nth 1 entry)))))))

(defun bitwarden-detail--render-ssh-key (item)
  "Render SSH-key-specific fields from ITEM."
  (let ((ssh-key (bitwarden-json-get 'sshKey item)))
    (magit-insert-section (bitwarden-group-section 'ssh-key)
      (magit-insert-heading "SSH Key")
      (bitwarden-detail--insert-field
       "Fingerprint" (bitwarden-json-get 'keyFingerprint ssh-key)
       nil '(sshKey keyFingerprint))
      (bitwarden-detail--insert-field
       "Public key" (bitwarden-json-get 'publicKey ssh-key)
       nil '(sshKey publicKey))
      (bitwarden-detail--insert-field
       "Private key" (bitwarden-json-get 'privateKey ssh-key)
       t '(sshKey privateKey)))))

(defun bitwarden-detail--render-custom-fields (item)
  "Render custom fields from ITEM."
  (let ((fields (append (bitwarden-json-get 'fields item) nil)))
    (when fields
      (magit-insert-section (bitwarden-group-section 'custom-fields)
        (magit-insert-heading "Custom Fields")
        (cl-loop for field in fields
                 for index from 0
                 do (let ((name (or (bitwarden-json-get 'name field)
                                    (format "Field %d" (1+ index))))
                          (type (or (bitwarden-json-get 'type field) 0)))
                      (bitwarden-detail--insert-field
                       name (bitwarden-json-get 'value field)
                       (= type 1) (list 'fields index 'value))))))))

(defun bitwarden-detail--render-attachments (item)
  "Render attachment metadata from ITEM."
  (let ((attachments (append (bitwarden-json-get 'attachments item) nil)))
    (when attachments
      (magit-insert-section (bitwarden-group-section 'attachments)
        (magit-insert-heading "Attachments")
        (dolist (attachment attachments)
          (let ((start (point)))
            (insert (format "%-18s %s bytes\n"
                            (or (bitwarden-json-get 'fileName attachment)
                                (bitwarden-json-get 'name attachment)
                                "Attachment")
                            (or (bitwarden-json-get 'size attachment) "?")))
            (add-text-properties
             start (point)
             `(bitwarden-attachment ,attachment
               mouse-face highlight
               help-echo "w: download, x: delete"))))))))

(defun bitwarden-detail--render-history (item)
  "Render password history from ITEM."
  (let ((history (append (bitwarden-json-get 'passwordHistory item) nil)))
    (when history
      (magit-insert-section (bitwarden-group-section 'password-history)
        (magit-insert-heading "Password History")
        (cl-loop for entry in history
                 for index from 0
                 do (bitwarden-detail--insert-field
                     (or (bitwarden-json-get 'lastUsedDate entry)
                         (format "Previous %d" (1+ index)))
                     (bitwarden-json-get 'password entry)
                     t (list 'passwordHistory index 'password)))))))

(defun bitwarden-detail--render-unknown (item)
  "Render top-level fields for an unknown ITEM type conservatively."
  (magit-insert-section (bitwarden-group-section 'unsupported)
    (magit-insert-heading "Unsupported Item Type (read-only)")
    (dolist (entry item)
      (unless (memq (car entry) '(id name type notes fields attachments))
        (bitwarden-detail--insert-field
         (symbol-name (car entry)) (cdr entry)
         (or (string-match-p
              (rx (or "password" "secret" "private" "totp" "number"
                      "code" "ssn"))
              (downcase (symbol-name (car entry))))
             (consp (cdr entry)) (vectorp (cdr entry)))
         (list (car entry)))))))

(defun bitwarden-detail--render-item ()
  "Render `bitwarden-detail-object' as a vault item."
  (let ((item bitwarden-detail-object))
    (magit-insert-section (bitwarden-group-section 'summary)
      (magit-insert-heading "Summary")
      (bitwarden-detail--render-common item))
    (pcase (bitwarden-json-get 'type item)
      (1 (bitwarden-detail--render-login item))
      (2 nil)
      (3 (bitwarden-detail--render-card item))
      (4 (bitwarden-detail--render-identity item))
      (5 (bitwarden-detail--render-ssh-key item))
      (_ (bitwarden-detail--render-unknown item)))
    (bitwarden-detail--render-custom-fields item)
    (bitwarden-detail--render-attachments item)
    (bitwarden-detail--render-history item)
    (magit-insert-section (bitwarden-group-section 'metadata)
      (magit-insert-heading "Metadata")
      (dolist (entry '(("Created" creationDate)
                       ("Updated" revisionDate)
                       ("Deleted" deletedDate)
                       ("Archived" archivedDate)))
        (when (bitwarden-json-get (nth 1 entry) item)
          (bitwarden-detail--insert-field
           (nth 0 entry) (bitwarden-json-get (nth 1 entry) item)))))))

(defun bitwarden-detail--render-send ()
  "Render `bitwarden-detail-object' as a Send."
  (let ((send bitwarden-detail-object))
    (magit-insert-section (bitwarden-group-section 'summary)
      (magit-insert-heading "Summary")
      (dolist (entry '(("Name" name nil)
                       ("URL" url nil)
                       ("Access count" accessCount nil)
                       ("Maximum access" maxAccessCount nil)
                       ("Expiration" expirationDate nil)
                       ("Deletion" deletionDate nil)
                       ("Notes" notes nil)
                       ("Password" password t)))
        (when (assq (nth 1 entry) send)
          (bitwarden-detail--insert-field
           (nth 0 entry) (bitwarden-json-get (nth 1 entry) send)
           (nth 2 entry) (list (nth 1 entry)))))
      (bitwarden-detail--insert-field
       "Type"
       (if (= (or (bitwarden-json-get 'type send) 0) 0) "Text" "File")))
    (when-let* ((text (map-nested-elt send '(text text))))
      (magit-insert-section (bitwarden-group-section 'text)
        (magit-insert-heading "Text")
        (bitwarden-detail--insert-field "Content" text t '(text text))))
    (when-let* ((file (bitwarden-json-get 'file send)))
      (magit-insert-section (bitwarden-group-section 'file)
        (magit-insert-heading "File")
        (bitwarden-detail--insert-field
         "Filename" (bitwarden-json-get 'fileName file)
         nil '(file fileName))))))

(defun bitwarden-detail-render ()
  "Render the current detail buffer."
  (let ((inhibit-read-only t)
        (line (line-number-at-pos)))
    (erase-buffer)
    (magit-insert-section (bitwarden-root-section)
      (insert (propertize
               (format "%s\n"
                       (or (bitwarden-json-get 'name bitwarden-detail-object)
                           "Bitwarden Object"))
               'face '(:height 1.35 :weight bold)))
      (insert "v reveal/hide   y copy   i insert   e edit   g refresh   q quit\n")
      (pcase bitwarden-detail-kind
        ('item (bitwarden-detail--render-item))
        ('send (bitwarden-detail--render-send))
        ('generated
         (magit-insert-section (bitwarden-group-section 'generated)
           (magit-insert-heading "Generated Value")
           (bitwarden-detail--insert-field
            "Generated value" (bitwarden-json-get 'value bitwarden-detail-object)
            t '(value))))))
    (goto-char (point-min))
    (forward-line (max 0 (1- line)))
    (set-buffer-modified-p nil)))

(defun bitwarden-detail--property-at-point (property)
  "Return PROPERTY at point or just before point."
  (or (get-text-property (point) property)
      (and (> (point) (point-min))
           (get-text-property (1- (point)) property))))

(defun bitwarden-detail-toggle-secret ()
  "Reveal or hide the sensitive field at point."
  (interactive)
  (let ((path (bitwarden-detail--property-at-point 'bitwarden-field-path))
        (secret (bitwarden-detail--property-at-point 'bitwarden-field-secret)))
    (unless (and path secret)
      (user-error "No hidden Bitwarden field at point"))
    (let ((key (prin1-to-string path)))
      (if (gethash key bitwarden-detail-revealed)
          (remhash key bitwarden-detail-revealed)
        (puthash key t bitwarden-detail-revealed)))
    (bitwarden-detail-render)))

(defun bitwarden-detail--copy-or-insert (insert-p)
  "Copy the field at point, or insert it when INSERT-P is non-nil."
  (let ((path (bitwarden-detail--property-at-point 'bitwarden-field-path)))
    (unless path (user-error "No Bitwarden field at point"))
    (if (equal path '(:totp))
        (bitwarden-detail--fetch-totp
         (lambda (value)
           (if insert-p
               (bitwarden-detail--insert-into-buffer value)
             (bitwarden-copy-value value))))
      (let ((value (or (map-nested-elt bitwarden-detail-object path)
                       (bitwarden-detail--property-at-point
                        'bitwarden-field-literal))))
        (when (null value)
          (user-error "This field is empty"))
        (setq value (bitwarden-detail--stringify value))
        (if insert-p
            (bitwarden-detail--insert-into-buffer value)
          (bitwarden-copy-value value))))))

(defun bitwarden-detail-copy ()
  "Copy the field at point according to `bitwarden-copy-policy'."
  (interactive)
  (bitwarden-detail--copy-or-insert nil))

(defun bitwarden-detail--insert-into-buffer (value)
  "Prompt for an editable buffer and insert VALUE there."
  (let* ((candidates
          (mapcar #'buffer-name
                  (seq-filter
                   (lambda (buffer)
                     (with-current-buffer buffer
                       (and (not buffer-read-only)
                            (not (string-prefix-p " " (buffer-name buffer)))
                            (not (derived-mode-p 'bitwarden-detail-mode
                                                 'bitwarden-list-mode
                                                 'bitwarden-navigation-mode
                                                 'bitwarden-form-mode)))))
                   (buffer-list))))
         (name (completing-read "Insert into buffer: " candidates nil t))
         (buffer (get-buffer name)))
    (with-current-buffer buffer (insert value))
    (message "Inserted Bitwarden value into %s" name)))

(defun bitwarden-detail-insert ()
  "Insert the field at point into a selected editable buffer."
  (interactive)
  (bitwarden-detail--copy-or-insert t))

(defun bitwarden-detail-open-uri ()
  "Open the URI at point, or the first login URI."
  (interactive)
  (let* ((path (bitwarden-detail--property-at-point 'bitwarden-field-path))
         (value (and path (map-nested-elt bitwarden-detail-object path)))
         (uri (if (and (stringp value)
                       (string-match-p (rx string-start (or "http" "ssh")) value))
                  value
                (map-nested-elt
                 bitwarden-detail-object '(login uris 0 uri)))))
    (unless (and (stringp uri) (not (string-empty-p uri)))
      (user-error "This object has no URI"))
    (browse-url uri)))

(defun bitwarden-detail--fetch-totp (callback)
  "Fetch a fresh TOTP and invoke CALLBACK with it."
  (unless (eq bitwarden-detail-kind 'item)
    (user-error "TOTP is only available for vault items"))
  (bitwarden-api-get
   "totp" (bitwarden-json-get 'id bitwarden-detail-object) :raw t
   :on-success (lambda (value _job) (funcall callback value))
   :on-error #'bitwarden-ui--error))

(defun bitwarden-detail--expire-totp (buffer)
  "Clear a displayed TOTP from BUFFER."
  (when (buffer-live-p buffer)
    (with-current-buffer buffer
      (setq bitwarden-detail-totp nil
            bitwarden-detail-totp-timer nil)
      (remhash (prin1-to-string '(:totp))
               bitwarden-detail-revealed)
      (bitwarden-detail-render))))

(defun bitwarden-detail-show-totp ()
  "Fetch and temporarily reveal this item's TOTP."
  (interactive)
  (let ((buffer (current-buffer)))
    (bitwarden-detail--fetch-totp
     (lambda (value)
       (when (buffer-live-p buffer)
         (with-current-buffer buffer
           (when (timerp bitwarden-detail-totp-timer)
             (cancel-timer bitwarden-detail-totp-timer))
           (setq bitwarden-detail-totp value
                 bitwarden-detail-totp-timer
                 (run-at-time 30 nil #'bitwarden-detail--expire-totp buffer))
           (puthash (prin1-to-string '(:totp)) t
                    bitwarden-detail-revealed)
           (bitwarden-detail-render)))))))

(defun bitwarden-detail-refresh ()
  "Refetch the current detail object."
  (interactive)
  (let ((id (bitwarden-json-get 'id bitwarden-detail-object))
        (buffer (current-buffer)))
    (pcase bitwarden-detail-kind
      ('item
       (bitwarden-api-get
        "item" id
        :on-success
        (lambda (object _job)
          (when (buffer-live-p buffer)
            (with-current-buffer buffer
              (setq bitwarden-detail-object object)
              (clrhash bitwarden-detail-revealed)
              (bitwarden-detail-render))))
        :on-error #'bitwarden-ui--error))
      ('send
       (bitwarden-api-send-get
        id
        :on-success
        (lambda (object _job)
          (when (buffer-live-p buffer)
            (with-current-buffer buffer
              (setq bitwarden-detail-object object)
              (clrhash bitwarden-detail-revealed)
              (bitwarden-detail-render))))
        :on-error #'bitwarden-ui--error)))))

(defun bitwarden-detail-edit ()
  "Edit the current detail object."
  (interactive)
  (pcase bitwarden-detail-kind
    ('item
     (if (alist-get (bitwarden-json-get 'type bitwarden-detail-object)
                    bitwarden-ui--item-types)
         (bitwarden-form--open 'item bitwarden-detail-object nil)
       (user-error "Unknown item types are read-only")))
    ('send (bitwarden-form--open 'send bitwarden-detail-object nil))))

(defun bitwarden-detail-delete ()
  "Delete the current detail object."
  (interactive)
  (let ((id (bitwarden-json-get 'id bitwarden-detail-object))
        (name (bitwarden-json-get 'name bitwarden-detail-object "object"))
        (buffer (current-buffer)))
    (when (yes-or-no-p (format "Delete %s? " name))
      (pcase bitwarden-detail-kind
        ('item
         (bitwarden-api-delete
          "item" id
          :on-success (lambda (_data _job)
                        (when (buffer-live-p buffer) (kill-buffer buffer))
                        (message "Moved %s to trash" name))
          :on-error #'bitwarden-ui--error))
        ('send
         (bitwarden-api-send-delete
          id
          :on-success (lambda (_data _job)
                        (when (buffer-live-p buffer) (kill-buffer buffer))
                        (message "Deleted Send %s" name))
          :on-error #'bitwarden-ui--error))))))

(defun bitwarden-detail-archive ()
  "Archive the current item."
  (interactive)
  (unless (eq bitwarden-detail-kind 'item)
    (user-error "Only vault items can be archived"))
  (let ((id (bitwarden-json-get 'id bitwarden-detail-object))
        (buffer (current-buffer)))
    (bitwarden-api-archive
     id
     :on-success (lambda (_data _job)
                   (when (buffer-live-p buffer) (kill-buffer buffer))
                   (message "Bitwarden item archived"))
     :on-error #'bitwarden-ui--error)))

(defun bitwarden-detail-restore ()
  "Restore the current deleted or archived item."
  (interactive)
  (unless (eq bitwarden-detail-kind 'item)
    (user-error "Only vault items can be restored"))
  (let ((id (bitwarden-json-get 'id bitwarden-detail-object))
        (buffer (current-buffer)))
    (unless (or (bitwarden-json-get 'deletedDate bitwarden-detail-object)
                (bitwarden-json-get 'archivedDate bitwarden-detail-object))
      (user-error "This item is neither deleted nor archived"))
    (bitwarden-api-restore
     id
     :on-success (lambda (_data _job)
                   (message "Bitwarden item restored")
                   (when (buffer-live-p buffer)
                     (with-current-buffer buffer
                       (bitwarden-detail-refresh))))
     :on-error #'bitwarden-ui--error)))

(defun bitwarden-detail--attachment-at-point ()
  "Return attachment metadata at point."
  (or (bitwarden-detail--property-at-point 'bitwarden-attachment)
      (user-error "No attachment at point")))

(defun bitwarden-detail-add-attachment ()
  "Attach a local file to the current item."
  (interactive)
  (unless (eq bitwarden-detail-kind 'item)
    (user-error "Attachments belong to vault items"))
  (let ((file (read-file-name "Attach file: " nil nil t))
        (item-id (bitwarden-json-get 'id bitwarden-detail-object))
        (buffer (current-buffer)))
    (unless (file-regular-p file)
      (user-error "Choose a regular file to attach"))
    (bitwarden-api-attachment-create
     item-id file
     :on-success (lambda (_data _job)
                   (message "Attachment uploaded")
                   (when (buffer-live-p buffer)
                     (with-current-buffer buffer
                       (bitwarden-detail-refresh))))
     :on-error #'bitwarden-ui--error)))

(defun bitwarden-detail-download-attachment ()
  "Download the attachment at point."
  (interactive)
  (if (eq bitwarden-detail-kind 'send)
      (let* ((filename (or (map-nested-elt
                            bitwarden-detail-object '(file fileName))
                           "send-file"))
             (output (read-file-name "Save Send file as: " nil filename nil))
             (id (bitwarden-json-get 'id bitwarden-detail-object)))
        (when (file-directory-p output)
          (user-error "Choose a filename, not a directory"))
        (when (and (file-exists-p output)
                   (not (yes-or-no-p (format "Overwrite %s? " output))))
          (user-error "Download cancelled"))
        (bitwarden-api-send-get
         id :output output :raw t
         :on-success (lambda (_data _job)
                       (set-file-modes output #o600)
                       (message "Saved Send file to %s" output))
         :on-error #'bitwarden-ui--error))
    (let* ((attachment (bitwarden-detail--attachment-at-point))
           (attachment-id (bitwarden-json-get 'id attachment))
           (filename (or (bitwarden-json-get 'fileName attachment)
                         (bitwarden-json-get 'name attachment)
                         "attachment"))
           (output (read-file-name "Save attachment as: " nil filename nil))
           (item-id (bitwarden-json-get 'id bitwarden-detail-object)))
      (when (file-directory-p output)
        (user-error "Choose a filename, not a directory"))
      (when (and (file-exists-p output)
                 (not (yes-or-no-p (format "Overwrite %s? " output))))
        (user-error "Download cancelled"))
      (bitwarden-api-attachment-get
       item-id attachment-id output
       :on-success (lambda (_data _job)
                     (set-file-modes output #o600)
                     (message "Saved attachment to %s" output))
       :on-error #'bitwarden-ui--error))))

(defun bitwarden-detail-delete-attachment ()
  "Delete the attachment at point."
  (interactive)
  (when (eq bitwarden-detail-kind 'send)
    (user-error "Delete and recreate a file Send to replace its file"))
  (let* ((attachment (bitwarden-detail--attachment-at-point))
         (attachment-id (bitwarden-json-get 'id attachment))
         (filename (or (bitwarden-json-get 'fileName attachment)
                       (bitwarden-json-get 'name attachment)
                       "attachment"))
         (item-id (bitwarden-json-get 'id bitwarden-detail-object))
         (buffer (current-buffer)))
    (when (yes-or-no-p (format "Delete attachment %s? " filename))
      (bitwarden-api-attachment-delete
       item-id attachment-id
       :on-success (lambda (_data _job)
                     (message "Attachment deleted")
                     (when (buffer-live-p buffer)
                       (with-current-buffer buffer
                         (bitwarden-detail-refresh))))
       :on-error #'bitwarden-ui--error))))

(defun bitwarden-ui--copy-options (item)
  "Return an alist of copy labels and values for ITEM."
  (let ((type (bitwarden-json-get 'type item)) result)
    (pcase type
      (1
       (let ((login (bitwarden-json-get 'login item)))
         (push (cons "Username" (bitwarden-json-get 'username login)) result)
         (push (cons "Password" (bitwarden-json-get 'password login)) result)
         (when (bitwarden-json-get 'totp login)
           (push (cons "TOTP" :totp) result))
         (cl-loop for uri in (append (bitwarden-json-get 'uris login) nil)
                  for index from 1
                  do (push (cons (format "URI %d" index)
                                 (bitwarden-json-get 'uri uri)) result))))
      (3
       (let ((card (bitwarden-json-get 'card item)))
         (dolist (entry '(("Card number" . number)
                          ("Security code" . code)
                          ("Cardholder" . cardholderName)))
           (push (cons (car entry) (bitwarden-json-get (cdr entry) card))
                 result))))
      (4
       (let ((identity (bitwarden-json-get 'identity item)))
         (dolist (entry '(("Email" . email) ("Phone" . phone)
                          ("Username" . username) ("SSN" . ssn)
                          ("Passport" . passportNumber)
                          ("License" . licenseNumber)))
           (push (cons (car entry) (bitwarden-json-get (cdr entry) identity))
                 result))))
      (5
       (let ((ssh (bitwarden-json-get 'sshKey item)))
         (dolist (entry '(("Public key" . publicKey)
                          ("Private key" . privateKey)
                          ("Fingerprint" . keyFingerprint)))
           (push (cons (car entry) (bitwarden-json-get (cdr entry) ssh))
                 result)))))
    (cl-loop for field in (append (bitwarden-json-get 'fields item) nil)
             for index from 1
             do (push (cons (format "Custom: %s"
                                    (or (bitwarden-json-get 'name field)
                                        index))
                            (bitwarden-json-get 'value field)) result))
    (seq-filter (lambda (entry) (cdr entry))
                (nreverse result))))

(defun bitwarden-ui--choose-and-copy (item)
  "Prompt for a field from ITEM and copy it."
  (let* ((item-id (or (bitwarden-json-get 'id item) ""))
         (options (bitwarden-ui--copy-options item))
         (label (completing-read "Copy field: " options nil t))
         (value (alist-get label options nil nil #'string=)))
    (if (eq value :totp)
        (bitwarden-api-get
         "totp" item-id :raw t
         :on-success (lambda (code _job) (bitwarden-copy-value code))
         :on-error #'bitwarden-ui--error)
      (bitwarden-copy-value (bitwarden-detail--stringify value)))))

;;; Widget forms

(defvar-keymap bitwarden-form-mode-map
  :doc "Keymap for `bitwarden-form-mode'."
  :parent widget-keymap
  "C-c C-c" #'bitwarden-form-save
  "C-c C-k" #'bitwarden-form-cancel)

(define-derived-mode bitwarden-form-mode special-mode "Bitwarden-Form"
  "Major mode for editing Bitwarden objects with widgets."
  (setq-local buffer-read-only nil)
  (setq-local truncate-lines nil)
  (setq-local bitwarden-form-widgets nil)
  (buffer-disable-undo)
  (cl-pushnew (current-buffer) bitwarden--sensitive-buffers)
  (add-hook 'post-command-hook #'bitwarden-ui--touch nil t)
  (add-hook 'kill-buffer-hook #'bitwarden-form--cleanup nil t))

(defun bitwarden-form--cleanup ()
  "Release data owned by the current form buffer."
  (setq bitwarden-form-original nil
        bitwarden-form-unknown-fields nil
        bitwarden-form-widgets nil)
  (setq bitwarden--sensitive-buffers
        (delq (current-buffer) bitwarden--sensitive-buffers)))

(defun bitwarden-form--remember (key widget)
  "Remember WIDGET under KEY and return it."
  (push (cons key widget) bitwarden-form-widgets)
  widget)

(defun bitwarden-form--widget (key)
  "Return the form widget registered under KEY."
  (cdr (assoc key bitwarden-form-widgets)))

(defun bitwarden-form--value (key &optional default)
  "Return the current widget value under KEY, or DEFAULT."
  (if-let* ((widget (bitwarden-form--widget key)))
      (widget-value widget)
    default))

(defun bitwarden-form--field
    (key label value &optional secret multiline size)
  "Create a form field under KEY with LABEL and VALUE."
  (let ((widget
         (widget-create
          (if multiline 'text 'editable-field)
          :tag label
          :format "%{%t%}: %v"
          :value (or value "")
          :size size
          :secret (and secret ?*))))
    (bitwarden-form--remember key widget)
    (unless multiline (insert "\n"))
    widget))

(defun bitwarden-form--checkbox (key label value)
  "Create a checkbox under KEY with LABEL and VALUE."
  (insert (format "%-20s " (concat label ":")))
  (let ((widget (widget-create 'checkbox :value (eq value t))))
    (bitwarden-form--remember key widget)
    (insert "\n")
    widget))

(defun bitwarden-form--menu (key label value choices)
  "Create a menu under KEY, LABEL, VALUE, and widget CHOICES."
  (let ((widget
         (apply #'widget-create
                'menu-choice
                (append (list :tag label :value value) choices))))
    (bitwarden-form--remember key widget)
    (insert "\n")
    widget))

(defun bitwarden-form--section (title)
  "Insert form section TITLE."
  (insert "\n" (propertize title 'face '(:weight bold :underline t)) "\n"))

(defun bitwarden-form--const-choices (entries &optional none-label)
  "Convert ENTRIES of (VALUE . LABEL) into widget choices."
  (append
   (when none-label (list `(const :tag ,none-label :value nil)))
   (mapcar (lambda (entry)
             `(const :tag ,(cdr entry) :value ,(car entry)))
           entries)))

(defun bitwarden-form--folder-choices ()
  "Return widget choices for cached folders."
  (bitwarden-form--const-choices
   (mapcar
    (lambda (folder)
      (cons (bitwarden-json-get 'id folder)
            (bitwarden-json-get 'name folder "Folder")))
    (append (gethash 'folders bitwarden--metadata-cache) nil))
   "None"))

(defun bitwarden-form--organization-choices ()
  "Return widget choices for cached organizations."
  (bitwarden-form--const-choices
   (mapcar
    (lambda (organization)
      (cons (bitwarden-json-get 'id organization)
            (bitwarden-json-get 'name organization "Organization")))
    (append (gethash 'organizations bitwarden--metadata-cache) nil))
   "Personal"))

(defun bitwarden-form--empty-null (value)
  "Return JSON null for empty string VALUE."
  (and value (not (string-empty-p value)) value))

(defun bitwarden-form--render-common-item (item)
  "Create widgets for common ITEM fields."
  (bitwarden-form--section "Item")
  (bitwarden-form--field 'name "Name" (bitwarden-json-get 'name item) nil nil 55)
  (bitwarden-form--checkbox
   'favorite "Favorite" (bitwarden-json-get 'favorite item :false))
  (bitwarden-form--checkbox
   'reprompt "Master password reprompt"
   (= (or (bitwarden-json-get 'reprompt item) 0) 1))
  (bitwarden-form--menu
   'folderId "Folder" (bitwarden-json-get 'folderId item)
   (bitwarden-form--folder-choices))
  (if bitwarden-form-new-p
      (bitwarden-form--menu
       'organizationId "Owner"
       (bitwarden-json-get 'organizationId item)
       (bitwarden-form--organization-choices))
    (insert (format "%-20s %s\n"
                    "Owner:"
                    (bitwarden-ui--organization-name
                     (bitwarden-json-get 'organizationId item)))))
  (bitwarden-form--field
   'notes "Notes" (bitwarden-json-get 'notes item) nil t)
  (bitwarden-form--render-collections item)
  (bitwarden-form--render-custom-fields item))

(defun bitwarden-form--render-collections (item)
  "Create collection checkboxes for ITEM."
  (let ((selected (append (bitwarden-json-get 'collectionIds item) nil)))
    (when (bitwarden-navigation--collections)
      (bitwarden-form--section "Collections")
      (dolist (collection (bitwarden-navigation--collections))
        (let* ((id (bitwarden-json-get 'id collection))
               (org-id (bitwarden-json-get 'organizationId collection))
               (label (format "%s / %s"
                              (bitwarden-ui--organization-name org-id)
                              (bitwarden-json-get 'name collection "Collection"))))
          (bitwarden-form--checkbox
           (cons 'collection id) label (and (member id selected) t)))))))

(defun bitwarden-form--render-custom-fields (item)
  "Create repeatable custom-field widgets for ITEM."
  (let* ((all-fields (append (bitwarden-json-get 'fields item) nil))
         (known (seq-filter
                 (lambda (field)
                   (memq (or (bitwarden-json-get 'type field) 0) '(0 1 2)))
                 all-fields))
         (unknown (seq-remove
                   (lambda (field)
                     (memq (or (bitwarden-json-get 'type field) 0) '(0 1 2)))
                   all-fields)))
    (setq bitwarden-form-unknown-fields
          (mapcar (lambda (field) (copy-tree field t)) unknown))
    (bitwarden-form--section "Custom Fields")
    (insert "Use Insert/Delete buttons to manage fields.\n")
    (bitwarden-form--remember
     'fields
     (widget-create
      'editable-list
      :entry-format "%i %d %v\n"
      :value
      (mapcar (lambda (field)
                (list (or (bitwarden-json-get 'type field) 0)
                      (or (bitwarden-json-get 'name field) "")
                      (or (bitwarden-json-get 'value field) "")))
              known)
      '(group
        :inline t
        (menu-choice
         :tag "Type"
         (const :tag "Text" 0)
         (const :tag "Hidden" 1)
         (const :tag "Boolean" 2))
        (editable-field :tag "Name" :size 18)
        (editable-field :tag "Value" :size 28))))))

(defun bitwarden-form--generate-password (&rest _ignore)
  "Generate a password and place it in the current login form."
  (let ((buffer (current-buffer)))
    (bitwarden-generate
     (lambda (value)
       (when (buffer-live-p buffer)
         (with-current-buffer buffer
           (when-let* ((widget (bitwarden-form--widget 'login.password)))
             (widget-value-set widget value))))))))

(defun bitwarden-form--render-login (item)
  "Create login widgets for ITEM."
  (let ((login (bitwarden-json-get 'login item)))
    (bitwarden-form--section "Login")
    (bitwarden-form--field
     'login.username "Username" (bitwarden-json-get 'username login) nil nil 55)
    (bitwarden-form--field
     'login.password "Password" (bitwarden-json-get 'password login) t nil 55)
    (widget-create
     'push-button :tag "Generate password"
     :notify #'bitwarden-form--generate-password)
    (insert "\n")
    (bitwarden-form--field
     'login.totp "Authenticator key / otpauth URI"
     (bitwarden-json-get 'totp login) t nil 55)
    (bitwarden-form--section "Login URIs")
    (bitwarden-form--remember
     'login.uris
     (widget-create
      'editable-list
      :entry-format "%i %d %v\n"
      :value
      (mapcar
       (lambda (uri)
         (list (or (bitwarden-json-get 'uri uri) "")
               (bitwarden-json-get 'match uri)))
       (append (bitwarden-json-get 'uris login) nil))
      '(group
        :inline t
        (editable-field :tag "URI" :size 48)
        (menu-choice
         :tag "Match"
         (const :tag "Default" nil)
         (const :tag "Domain" 0)
         (const :tag "Host" 1)
         (const :tag "Starts With" 2)
         (const :tag "Exact" 3)
         (const :tag "Regular Expression" 4)
         (const :tag "Never" 5)))))))

(defun bitwarden-form--render-card (item)
  "Create card widgets for ITEM."
  (let ((card (bitwarden-json-get 'card item)))
    (bitwarden-form--section "Card")
    (dolist (entry '((card.cardholderName "Cardholder" cardholderName nil)
                     (card.brand "Brand" brand nil)
                     (card.number "Number" number t)
                     (card.expMonth "Expiry month" expMonth nil)
                     (card.expYear "Expiry year" expYear nil)
                     (card.code "Security code" code t)))
      (bitwarden-form--field
       (nth 0 entry) (nth 1 entry) (bitwarden-json-get (nth 2 entry) card)
       (nth 3 entry) nil 45))))

(defun bitwarden-form--render-identity (item)
  "Create identity widgets for ITEM."
  (let ((identity (bitwarden-json-get 'identity item)))
    (bitwarden-form--section "Identity")
    (dolist
        (entry
         '((identity.title "Title" title nil)
           (identity.firstName "First name" firstName nil)
           (identity.middleName "Middle name" middleName nil)
           (identity.lastName "Last name" lastName nil)
           (identity.company "Company" company nil)
           (identity.email "Email" email nil)
           (identity.phone "Phone" phone nil)
           (identity.username "Username" username nil)
           (identity.address1 "Address 1" address1 nil)
           (identity.address2 "Address 2" address2 nil)
           (identity.address3 "Address 3" address3 nil)
           (identity.city "City" city nil)
           (identity.state "State" state nil)
           (identity.postalCode "Postal code" postalCode nil)
           (identity.country "Country" country nil)
           (identity.ssn "SSN" ssn t)
           (identity.passportNumber "Passport" passportNumber t)
           (identity.licenseNumber "License" licenseNumber t)))
      (bitwarden-form--field
       (nth 0 entry) (nth 1 entry)
       (bitwarden-json-get (nth 2 entry) identity)
       (nth 3 entry) nil 50))))

(defun bitwarden-form--render-ssh-key (item)
  "Create SSH key widgets for ITEM."
  (let ((ssh-key (bitwarden-json-get 'sshKey item)))
    (bitwarden-form--section "SSH Key")
    (if bitwarden-form-new-p
        (progn
          (bitwarden-form--field
           'sshKey.privateKey "Private key" (bitwarden-json-get 'privateKey ssh-key)
           t t)
          (bitwarden-form--field
           'sshKey.publicKey "Public key" (bitwarden-json-get 'publicKey ssh-key)
           nil t)
          (bitwarden-form--field
           'sshKey.keyFingerprint "Fingerprint"
           (bitwarden-json-get 'keyFingerprint ssh-key) nil nil 55))
      (insert "Key material is immutable after creation.\n")
      (insert (format "Fingerprint: %s\n"
                      (or (bitwarden-json-get 'keyFingerprint ssh-key) "")))
      (insert (format "Public key: %s\n"
                      (or (bitwarden-json-get 'publicKey ssh-key) ""))))))

(defun bitwarden-form--open (kind object new-p &optional source)
  "Open a form for KIND OBJECT; NEW-P means creation.
SOURCE is refreshed after a successful save."
  (let* ((source (or source (current-buffer)))
         (copy (copy-tree object t))
         (name (or (bitwarden-json-get 'name copy) "New"))
         (buffer (generate-new-buffer
                  (format "*Bitwarden %s %s*"
                          (if new-p "New" "Edit") name))))
    (with-current-buffer buffer
      (bitwarden-form-mode)
      (setq-local bitwarden-form-kind kind
                  bitwarden-form-original copy
                  bitwarden-form-new-p new-p
                  bitwarden-form-source-buffer source)
      (bitwarden-form-render))
    (bitwarden-ui--display-buffer buffer)))

(defun bitwarden-form--render-item ()
  "Render the current item form."
  (let ((item bitwarden-form-original))
    (insert (propertize
             (format "%s %s\n"
                     (if bitwarden-form-new-p "New" "Edit")
                     (bitwarden-ui--item-type-name
                      (bitwarden-json-get 'type item)))
             'face '(:height 1.3 :weight bold)))
    (insert "C-c C-c save   C-c C-k cancel\n")
    (bitwarden-form--render-common-item item)
    (pcase (bitwarden-json-get 'type item)
      (1 (bitwarden-form--render-login item))
      (2 nil)
      (3 (bitwarden-form--render-card item))
      (4 (bitwarden-form--render-identity item))
      (5 (bitwarden-form--render-ssh-key item)))))

(defun bitwarden-form--render-folder ()
  "Render the current folder form."
  (insert (propertize
           (if bitwarden-form-new-p "New Folder\n" "Edit Folder\n")
           'face '(:height 1.3 :weight bold)))
  (insert "C-c C-c save   C-c C-k cancel\n\n")
  (bitwarden-form--field
   'name "Name" (bitwarden-json-get 'name bitwarden-form-original) nil nil 55))

(defun bitwarden-form--render-send ()
  "Render the current Send form."
  (let* ((send bitwarden-form-original)
         (type (or (bitwarden-json-get 'type send) 0)))
    (insert (propertize
             (format "%s %s Send\n"
                     (if bitwarden-form-new-p "New" "Edit")
                     (if (= type 0) "Text" "File"))
             'face '(:height 1.3 :weight bold)))
    (insert "C-c C-c save   C-c C-k cancel\n")
    (bitwarden-form--section "Send")
    (bitwarden-form--field 'name "Name" (bitwarden-json-get 'name send) nil nil 55)
    (bitwarden-form--field 'notes "Private notes" (bitwarden-json-get 'notes send) nil t)
    (bitwarden-form--field
     'maxAccessCount "Maximum access count"
     (let ((value (bitwarden-json-get 'maxAccessCount send)))
       (if value (format "%s" value) "")) nil nil 12)
    (bitwarden-form--field
     'expirationDate "Expiration date (ISO, optional)"
     (bitwarden-json-get 'expirationDate send) nil nil 32)
    (bitwarden-form--field
     'deletionDate "Deletion date (ISO)"
     (bitwarden-json-get 'deletionDate send) nil nil 32)
    (bitwarden-form--checkbox
     'disabled "Disabled" (bitwarden-json-get 'disabled send :false))
    (bitwarden-form--field 'password "New access password" "" t nil 40)
    (unless bitwarden-form-new-p
      (bitwarden-form--checkbox 'remove-password "Remove current password" nil))
    (bitwarden-form--section (if (= type 0) "Text" "File"))
    (if (= type 0)
        (progn
          (bitwarden-form--field
           'send.text "Text" (map-nested-elt send '(text text)) t t)
          (bitwarden-form--checkbox
           'send.hidden "Hide text by default"
           (map-nested-elt send '(text hidden))))
      (if bitwarden-form-new-p
          (bitwarden-form--field
           'send.file "File to upload" "" nil nil 60)
        (insert (format "File: %s (file content cannot be edited)\n"
                        (or (map-nested-elt send '(file fileName)) "")))))))

(defun bitwarden-form-render ()
  "Render widgets in the current form buffer."
  (let ((inhibit-read-only t))
    (erase-buffer)
    (remove-overlays)
    (setq bitwarden-form-widgets nil)
    (pcase bitwarden-form-kind
      ('item (bitwarden-form--render-item))
      ('folder (bitwarden-form--render-folder))
      ('send (bitwarden-form--render-send)))
    (insert "\n")
    (widget-create 'push-button :tag "Save"
                   :notify (lambda (&rest _ignore) (bitwarden-form-save)))
    (insert "   ")
    (widget-create 'push-button :tag "Cancel"
                   :notify (lambda (&rest _ignore) (bitwarden-form-cancel)))
    (widget-setup)
    (goto-char (point-min))
    (widget-forward 1)
    (set-buffer-modified-p nil)))

(defun bitwarden-form--set-common-item (item)
  "Apply common form widget values to ITEM."
  (setf (alist-get 'name item) (bitwarden-form--value 'name)
        (alist-get 'favorite item)
        (if (bitwarden-form--value 'favorite) t :false)
        (alist-get 'reprompt item) (if (bitwarden-form--value 'reprompt) 1 0)
        (alist-get 'folderId item) (bitwarden-form--value 'folderId))
  (when bitwarden-form-new-p
    (setf (alist-get 'organizationId item)
          (bitwarden-form--value 'organizationId)))
  (setf (alist-get 'notes item)
        (bitwarden-form--empty-null (bitwarden-form--value 'notes))
        (alist-get 'collectionIds item)
        (vconcat (bitwarden-form--selected-collections))
        (alist-get 'fields item) (bitwarden-form--collect-fields))
  item)

(defun bitwarden-form--selected-collections ()
  "Return collection IDs selected in the current form."
  (let ((owner (if bitwarden-form-new-p
                   (bitwarden-form--value 'organizationId)
                 (bitwarden-json-get 'organizationId bitwarden-form-original)))
        (original (unless bitwarden-form-new-p
                    (append (bitwarden-json-get 'collectionIds
                                                bitwarden-form-original)
                            nil)))
        known-ids
        result)
    (dolist (entry bitwarden-form-widgets)
      (when (and (consp (car entry))
                 (eq (caar entry) 'collection))
        (push (cdar entry) known-ids)))
    ;; Preserve memberships the CLI returned but this account cannot currently
    ;; enumerate.  The visible checkboxes remain authoritative for known IDs.
    (dolist (id original)
      (unless (member id known-ids)
        (push id result)))
    (dolist (entry bitwarden-form-widgets)
      (when (and (consp (car entry))
                 (eq (caar entry) 'collection)
                 (widget-value (cdr entry)))
        (let* ((id (cdar entry))
               (collection
                (seq-find
                 (lambda (candidate)
                   (equal id (bitwarden-json-get 'id candidate)))
                 (bitwarden-navigation--collections))))
          (when (and collection
                     (equal owner
                            (bitwarden-json-get 'organizationId collection)))
            (cl-pushnew id result :test #'equal)))))
    (nreverse result)))

(defun bitwarden-form--collect-fields ()
  "Return custom fields from the repeatable field widget."
  (vconcat
   (mapcar
    (lambda (value)
      `((type . ,(or (nth 0 value) 0))
        (name . ,(bitwarden-form--empty-null (nth 1 value)))
        (value . ,(bitwarden-form--empty-null (nth 2 value)))))
    (bitwarden-form--value 'fields nil))
   bitwarden-form-unknown-fields))

(defun bitwarden-form--collect-login (item)
  "Apply login widget values to ITEM."
  (let ((login (bitwarden-json-get 'login item)))
    (setf (alist-get 'username login)
          (bitwarden-form--empty-null
           (bitwarden-form--value 'login.username))
          (alist-get 'password login)
          (bitwarden-form--empty-null
           (bitwarden-form--value 'login.password))
          (alist-get 'totp login)
          (bitwarden-form--empty-null (bitwarden-form--value 'login.totp))
          (alist-get 'uris login)
          (vconcat
           (mapcar
            (lambda (value)
              `((match . ,(nth 1 value))
                (uri . ,(or (nth 0 value) ""))))
            (bitwarden-form--value 'login.uris nil)))
          (alist-get 'login item) login)
    item))

(defun bitwarden-form--collect-card (item)
  "Apply card widget values to ITEM."
  (let ((card (bitwarden-json-get 'card item)))
    (dolist (entry '((card.cardholderName . cardholderName)
                     (card.brand . brand)
                     (card.number . number)
                     (card.expMonth . expMonth)
                     (card.expYear . expYear)
                     (card.code . code)))
      (setf (alist-get (cdr entry) card)
            (bitwarden-form--empty-null
             (bitwarden-form--value (car entry)))))
    (setf (alist-get 'card item) card)
    item))

(defun bitwarden-form--collect-identity (item)
  "Apply identity widget values to ITEM."
  (let ((identity (bitwarden-json-get 'identity item)))
    (dolist
        (entry
         '((identity.title . title)
           (identity.firstName . firstName)
           (identity.middleName . middleName)
           (identity.lastName . lastName)
           (identity.company . company)
           (identity.email . email)
           (identity.phone . phone)
           (identity.username . username)
           (identity.address1 . address1)
           (identity.address2 . address2)
           (identity.address3 . address3)
           (identity.city . city)
           (identity.state . state)
           (identity.postalCode . postalCode)
           (identity.country . country)
           (identity.ssn . ssn)
           (identity.passportNumber . passportNumber)
           (identity.licenseNumber . licenseNumber)))
      (setf (alist-get (cdr entry) identity)
            (bitwarden-form--empty-null
             (bitwarden-form--value (car entry)))))
    (setf (alist-get 'identity item) identity)
    item))

(defun bitwarden-form--collect-ssh-key (item)
  "Apply new SSH-key widget values to ITEM."
  (if (not bitwarden-form-new-p)
      item
    (let ((ssh-key (bitwarden-json-get 'sshKey item)))
      (dolist (entry '((sshKey.privateKey . privateKey)
                       (sshKey.publicKey . publicKey)
                       (sshKey.keyFingerprint . keyFingerprint)))
        (setf (alist-get (cdr entry) ssh-key)
              (bitwarden-form--value (car entry))))
      (setf (alist-get 'sshKey item) ssh-key)
      item)))

(defun bitwarden-form--collect-item ()
  "Return complete item JSON represented by the current form."
  (let* ((item (bitwarden-form--set-common-item bitwarden-form-original))
         (name (bitwarden-json-get 'name item))
         (type (bitwarden-json-get 'type item)))
    (when (string-empty-p (string-trim (or name "")))
      (user-error "Item name is required"))
    (setq item
          (pcase type
            (1 (bitwarden-form--collect-login item))
            (3 (bitwarden-form--collect-card item))
            (4 (bitwarden-form--collect-identity item))
            (5 (bitwarden-form--collect-ssh-key item))
            (_ item)))
    (when (and (= type 5) bitwarden-form-new-p)
      (dolist (key '(privateKey publicKey keyFingerprint))
        (when (string-empty-p
               (or (map-nested-elt item (list 'sshKey key)) ""))
          (user-error "SSH %s is required" key))))
    item))

(defun bitwarden-form--collect-folder ()
  "Return complete folder JSON represented by the current form."
  (let ((name (string-trim (bitwarden-form--value 'name))))
    (when (string-empty-p name) (user-error "Folder name is required"))
    (setf (alist-get 'name bitwarden-form-original) name)
    bitwarden-form-original))

(defun bitwarden-form--collect-send ()
  "Return complete Send JSON represented by the current form."
  (let* ((send bitwarden-form-original)
         (name (string-trim (bitwarden-form--value 'name)))
         (type (or (bitwarden-json-get 'type send) 0))
         (max-access (string-trim (bitwarden-form--value 'maxAccessCount)))
         (password (bitwarden-form--value 'password)))
    (when (string-empty-p name) (user-error "Send name is required"))
    (setf (alist-get 'name send) name
          (alist-get 'notes send)
          (bitwarden-form--empty-null (bitwarden-form--value 'notes))
          (alist-get 'maxAccessCount send)
          (and (not (string-empty-p max-access)) (string-to-number max-access))
          (alist-get 'expirationDate send)
          (bitwarden-form--empty-null
           (bitwarden-form--value 'expirationDate))
          (alist-get 'deletionDate send)
          (bitwarden-form--empty-null
           (bitwarden-form--value 'deletionDate))
          (alist-get 'disabled send)
          (if (bitwarden-form--value 'disabled) t :false))
    (unless (string-empty-p password)
      (setf (alist-get 'password send) password))
    (when (= type 0)
      (let ((text (bitwarden-json-get 'text send)))
        (setf (alist-get 'text text) (bitwarden-form--value 'send.text)
              (alist-get 'hidden text)
              (if (bitwarden-form--value 'send.hidden) t :false)
              (alist-get 'text send) text)))
    (when (and bitwarden-form-new-p (= type 1))
      (let ((file (bitwarden-form--value 'send.file)))
        (when (string-empty-p file)
          (user-error "A file is required for a file Send"))
        (unless (file-regular-p file)
          (user-error "Choose a regular file for the file Send"))))
    send))

(defun bitwarden-form--saved (message-text)
  "Close the current form and show MESSAGE-TEXT."
  (let ((source bitwarden-form-source-buffer))
    (set-buffer-modified-p nil)
    (kill-buffer (current-buffer))
    (message "%s" message-text)
    (when (buffer-live-p source)
      (with-current-buffer source
        (cond
         ((eq major-mode 'bitwarden-list-mode) (bitwarden-list-refresh))
         ((eq major-mode 'bitwarden-detail-mode) (bitwarden-detail-refresh))
         ((eq major-mode 'bitwarden-navigation-mode)
          (bitwarden-navigation-refresh)))))))

(defun bitwarden-form--save-item-now (payload)
  "Persist item PAYLOAD from the current form."
  (let ((buffer (current-buffer))
        (new-p bitwarden-form-new-p)
        (id (bitwarden-json-get 'id bitwarden-form-original))
        (collections (bitwarden-form--selected-collections))
        (old-collections
         (append (bitwarden-json-get 'collectionIds bitwarden-form-original)
                 nil)))
    (if new-p
        (bitwarden-api-create
         "item" payload
         :on-success
         (lambda (_data _job)
           (when (buffer-live-p buffer)
             (with-current-buffer buffer
               (bitwarden-form--saved "Bitwarden item created"))))
         :on-error #'bitwarden-ui--error)
      (bitwarden-api-edit
       "item" id payload
       :on-success
       (lambda (_data _job)
         (if (seq-set-equal-p collections old-collections)
             (when (buffer-live-p buffer)
               (with-current-buffer buffer
                 (bitwarden-form--saved "Bitwarden item saved")))
           (bitwarden-api-edit
            "item-collections" id (vconcat collections)
            :on-success
            (lambda (_collection-data _collection-job)
              (when (buffer-live-p buffer)
                (with-current-buffer buffer
                  (bitwarden-form--saved "Bitwarden item saved"))))
            :on-error #'bitwarden-ui--error)))
       :on-error #'bitwarden-ui--error))))

(defun bitwarden-form--resolve-conflict (payload current)
  "Resolve a conflict between form PAYLOAD and CURRENT server item."
  (let ((choice
         (completing-read
          "Item changed elsewhere: " '("Reload" "Force Save" "Cancel")
          nil t nil nil "Reload")))
    (pcase choice
      ("Reload"
       (let ((buffer (current-buffer))
             (source bitwarden-form-source-buffer))
         (set-buffer-modified-p nil)
         (kill-buffer buffer)
         (bitwarden-form--open 'item current nil source)))
      ("Force Save" (bitwarden-form--save-item-now payload))
      (_ (message "Bitwarden save cancelled")))))

(defun bitwarden-form--save-item (payload)
  "Sync, conflict-check, and save item PAYLOAD."
  (if bitwarden-form-new-p
      (bitwarden-form--save-item-now payload)
    (let ((buffer (current-buffer))
          (id (bitwarden-json-get 'id bitwarden-form-original))
          (original-revision
           (bitwarden-json-get 'revisionDate bitwarden-form-original)))
      (bitwarden-api-sync
       :on-success
       (lambda (_data _job)
         (bitwarden-api-get
          "item" id
          :on-success
          (lambda (current _get-job)
            (when (buffer-live-p buffer)
              (with-current-buffer buffer
                (if (equal original-revision
                           (bitwarden-json-get 'revisionDate current))
                    (bitwarden-form--save-item-now payload)
                  (bitwarden-form--resolve-conflict payload current)))))
          :on-error #'bitwarden-ui--error))
       :on-error #'bitwarden-ui--error))))

(defun bitwarden-form--save-send-now (payload)
  "Persist Send PAYLOAD from the current form."
  (let* ((buffer (current-buffer))
         (id (bitwarden-json-get 'id bitwarden-form-original))
         (file (and bitwarden-form-new-p
                    (= (or (bitwarden-json-get 'type payload) 0) 1)
                    (bitwarden-form--value 'send.file)))
         (remove-password (bitwarden-form--value 'remove-password)))
    (if bitwarden-form-new-p
        (bitwarden-api-send-create
         payload :file file
         :on-success
         (lambda (_data _job)
           (when (buffer-live-p buffer)
             (with-current-buffer buffer
               (bitwarden-form--saved "Bitwarden Send created"))))
         :on-error #'bitwarden-ui--error)
      (bitwarden-api-send-edit
       payload
       :on-success
       (lambda (_data _job)
         (if remove-password
             (bitwarden-api-send-remove-password
              id
              :on-success
              (lambda (_remove-data _remove-job)
                (when (buffer-live-p buffer)
                  (with-current-buffer buffer
                    (bitwarden-form--saved "Bitwarden Send saved"))))
              :on-error #'bitwarden-ui--error)
           (when (buffer-live-p buffer)
             (with-current-buffer buffer
               (bitwarden-form--saved "Bitwarden Send saved")))))
       :on-error #'bitwarden-ui--error))))

(defun bitwarden-form--save-send (payload)
  "Sync, conflict-check, and save Send PAYLOAD."
  (if bitwarden-form-new-p
      (bitwarden-form--save-send-now payload)
    (let ((buffer (current-buffer))
          (id (bitwarden-json-get 'id bitwarden-form-original))
          (original-revision
           (bitwarden-json-get 'revisionDate bitwarden-form-original)))
      (bitwarden-api-sync
       :on-success
       (lambda (_data _job)
         (bitwarden-api-send-get
          id
          :on-success
          (lambda (current _get-job)
            (when (buffer-live-p buffer)
              (with-current-buffer buffer
                (if (equal original-revision
                           (bitwarden-json-get 'revisionDate current))
                    (bitwarden-form--save-send-now payload)
                  (pcase (completing-read
                          "Send changed elsewhere: "
                          '("Reload" "Force Save" "Cancel")
                          nil t nil nil "Reload")
                    ("Reload"
                     (let ((source bitwarden-form-source-buffer))
                       (set-buffer-modified-p nil)
                       (kill-buffer buffer)
                       (bitwarden-form--open 'send current nil source)))
                    ("Force Save" (bitwarden-form--save-send-now payload))
                    (_ (message "Bitwarden save cancelled")))))))
          :on-error #'bitwarden-ui--error))
       :on-error #'bitwarden-ui--error))))

(defun bitwarden-form-save ()
  "Validate and save the current Bitwarden form."
  (interactive)
  (pcase bitwarden-form-kind
    ('item
     (bitwarden-form--save-item (bitwarden-form--collect-item)))
    ('folder
     (let ((payload (bitwarden-form--collect-folder))
           (buffer (current-buffer))
           (id (bitwarden-json-get 'id bitwarden-form-original)))
       (if bitwarden-form-new-p
           (bitwarden-api-create
            "folder" payload
            :on-success
            (lambda (_data _job)
              (when (buffer-live-p buffer)
                (with-current-buffer buffer
                  (bitwarden-form--saved "Bitwarden folder created"))))
            :on-error #'bitwarden-ui--error)
         (bitwarden-api-edit
          "folder" id payload
          :on-success
          (lambda (_data _job)
            (when (buffer-live-p buffer)
              (with-current-buffer buffer
                (bitwarden-form--saved "Bitwarden folder saved"))))
          :on-error #'bitwarden-ui--error))))
    ('send
     (bitwarden-form--save-send (bitwarden-form--collect-send)))))

(defun bitwarden-form-cancel ()
  "Cancel and destroy the current form."
  (interactive)
  (when (or (not (buffer-modified-p))
            (yes-or-no-p "Discard this Bitwarden form? "))
    (set-buffer-modified-p nil)
    (kill-buffer (current-buffer))))

(defun bitwarden-create-item ()
  "Create a vault item using current CLI templates."
  (interactive)
  (let* ((source (current-buffer))
         (label (completing-read
                 "Item type: " (mapcar #'cdr bitwarden-ui--item-types)
                 nil t nil nil "Login"))
         (type (car (rassoc label bitwarden-ui--item-types))))
    (bitwarden-api-get
     "template" "item"
     :on-success
     (lambda (template _job)
       (setf (alist-get 'type template) type)
       (let ((sub-template
              (pcase type
                (1 "item.login") (2 "item.securenote")
                (3 "item.card") (4 "item.identity"))))
         (if sub-template
             (bitwarden-api-get
              "template" sub-template
              :on-success
              (lambda (sub _sub-job)
                (setf (alist-get
                       (pcase type
                         (1 'login) (2 'secureNote)
                         (3 'card) (4 'identity))
                       template)
                      sub)
                (bitwarden-form--open 'item template t source))
              :on-error #'bitwarden-ui--error)
           (setf (alist-get 'sshKey template)
                 '((privateKey . "")
                   (publicKey . "")
                   (keyFingerprint . "")))
           (bitwarden-form--open 'item template t source))))
     :on-error #'bitwarden-ui--error)))

(defun bitwarden-edit-item (metadata)
  "Fetch and edit the item represented by METADATA."
  (unless (alist-get (bitwarden-json-get 'type metadata)
                     bitwarden-ui--item-types)
    (user-error "Unknown item types are read-only"))
  (let ((source (current-buffer)))
    (bitwarden-ui--with-reprompt
     metadata
     (lambda ()
       (bitwarden-api-get
        "item" (bitwarden-json-get 'id metadata)
        :on-success
        (lambda (item _job)
          (bitwarden-form--open 'item item nil source))
        :on-error #'bitwarden-ui--error)))))

(defun bitwarden-create-folder ()
  "Create a personal vault folder."
  (interactive)
  (let ((source (current-buffer)))
    (bitwarden-api-get
     "template" "folder"
     :on-success (lambda (folder _job)
                   (bitwarden-form--open 'folder folder t source))
     :on-error #'bitwarden-ui--error)))

(defun bitwarden-edit-folder (metadata)
  "Fetch and edit the folder represented by METADATA."
  (let ((source (current-buffer)))
    (bitwarden-api-get
     "folder" (bitwarden-json-get 'id metadata)
     :on-success (lambda (folder _job)
                   (bitwarden-form--open 'folder folder nil source))
     :on-error #'bitwarden-ui--error)))

(defun bitwarden-create-send ()
  "Create a text or file Send using the installed CLI template."
  (interactive)
  (let* ((source (current-buffer))
         (kind (completing-read "Send type: " '("Text" "File") nil t))
         (template-name (if (string= kind "Text") "send.text" "send.file")))
    (bitwarden-api-send-template
     template-name
     :on-success (lambda (send _job)
                   (bitwarden-form--open 'send send t source))
     :on-error #'bitwarden-ui--error)))

(defun bitwarden-edit-send (metadata)
  "Fetch and edit the Send represented by METADATA."
  (let ((source (current-buffer)))
    (bitwarden-api-send-get
     (bitwarden-json-get 'id metadata)
     :on-success
     (lambda (send _job)
       (bitwarden-form--open 'send send nil source))
     :on-error #'bitwarden-ui--error)))

(defun bitwarden-ui--clone-payload (item)
  "Return ITEM prepared for creation as an independent clone."
  (let ((copy (copy-tree item t)))
    (dolist (key '(id creationDate revisionDate deletedDate archivedDate
                      passwordHistory attachments key))
      (setq copy (assq-delete-all key copy)))
    (setf (alist-get 'name copy)
          (concat (or (bitwarden-json-get 'name copy) "Item") " (Copy)"))
    copy))

(defun bitwarden-list-clone ()
  "Clone the item at point into a new-item form."
  (interactive)
  (unless (eq bitwarden-list-kind 'items)
    (user-error "Only vault items can be cloned"))
  (let ((metadata (or (bitwarden-list--record-at-point)
                      (user-error "No Bitwarden item at point")))
        (source (current-buffer)))
    (unless (alist-get (bitwarden-json-get 'type metadata)
                       bitwarden-ui--item-types)
      (user-error "Unknown item types cannot be cloned safely"))
    (bitwarden-ui--with-reprompt
     metadata
     (lambda ()
       (bitwarden-api-get
        "item" (bitwarden-json-get 'id metadata)
        :on-success
        (lambda (item _job)
          (bitwarden-form--open
           'item (bitwarden-ui--clone-payload item) t source))
        :on-error #'bitwarden-ui--error)))))

(defun bitwarden-detail-clone ()
  "Clone the current item into a new-item form."
  (interactive)
  (unless (eq bitwarden-detail-kind 'item)
    (user-error "Only vault items can be cloned"))
  (unless (alist-get (bitwarden-json-get 'type bitwarden-detail-object)
                     bitwarden-ui--item-types)
    (user-error "Unknown item types cannot be cloned safely"))
  (bitwarden-form--open
   'item (bitwarden-ui--clone-payload bitwarden-detail-object) t))

(defun bitwarden-ui--choose-organization-and-collections (callback)
  "Prompt for an organization and collections, then invoke CALLBACK."
  (let ((organizations
         (mapcar
          (lambda (organization)
            (cons (bitwarden-json-get 'name organization "Organization")
                  (bitwarden-json-get 'id organization)))
          (append (gethash 'organizations bitwarden--metadata-cache) nil))))
    (unless organizations
      (user-error "No writable organizations are available"))
    (let* ((org-name
            (completing-read "Move to organization: " organizations nil t))
           (org-id (alist-get org-name organizations nil nil #'string=))
           (collections
            (mapcar
             (lambda (collection)
               (cons (bitwarden-json-get 'name collection "Collection")
                     (bitwarden-json-get 'id collection)))
             (bitwarden-navigation--collections-for org-id)))
           (chosen
            (completing-read-multiple
             "Collections (comma-separated): " collections nil t))
           (ids (mapcar (lambda (name)
                          (alist-get name collections nil nil #'string=))
                        chosen)))
      (funcall callback org-id ids))))

(defun bitwarden-list-move ()
  "Move the personal item at point to an organization."
  (interactive)
  (unless (eq bitwarden-list-kind 'items)
    (user-error "Only vault items can be moved"))
  (let* ((metadata (or (bitwarden-list--record-at-point)
                       (user-error "No Bitwarden item at point")))
         (id (bitwarden-json-get 'id metadata))
         (buffer (current-buffer)))
    (when (bitwarden-json-get 'organizationId metadata)
      (user-error "This item already belongs to an organization"))
    (bitwarden-ui--choose-organization-and-collections
     (lambda (org-id collection-ids)
       (bitwarden-api-move
        id org-id collection-ids
        :on-success
        (lambda (_data _job)
          (message "Bitwarden item moved")
          (when (buffer-live-p buffer)
            (with-current-buffer buffer (bitwarden-list-refresh))))
        :on-error #'bitwarden-ui--error)))))

(defun bitwarden-detail-move ()
  "Move the current personal item to an organization."
  (interactive)
  (unless (eq bitwarden-detail-kind 'item)
    (user-error "Only vault items can be moved"))
  (when (bitwarden-json-get 'organizationId bitwarden-detail-object)
    (user-error "This item already belongs to an organization"))
  (let ((id (bitwarden-json-get 'id bitwarden-detail-object))
        (buffer (current-buffer)))
    (bitwarden-ui--choose-organization-and-collections
     (lambda (org-id collection-ids)
       (bitwarden-api-move
        id org-id collection-ids
        :on-success (lambda (_data _job)
                      (message "Bitwarden item moved")
                      (when (buffer-live-p buffer)
                        (with-current-buffer buffer
                          (bitwarden-detail-refresh))))
        :on-error #'bitwarden-ui--error)))))

;;; Generator, import, and export

(defun bitwarden-generate (&optional callback)
  "Generate a password or passphrase.
When CALLBACK is non-nil, pass the generated value to it instead of opening a
result buffer."
  (interactive)
  (let ((kind (completing-read
               "Generate: " '("Password" "Passphrase") nil t nil nil
               "Password")))
    (if (string= kind "Passphrase")
        (let ((words (read-number "Words: " 5))
              (separator (read-string "Separator (space/empty/string): " "-"))
              (capitalize (y-or-n-p "Capitalize words? "))
              (include-number (y-or-n-p "Include a number? ")))
          (bitwarden-api-generate
           :passphrase t :words words :separator separator
           :capitalize capitalize :include-number include-number
           :on-success
           (lambda (value _job)
             (if callback (funcall callback value)
               (bitwarden-detail--open
                'generated `((name . "Generated Secret") (value . ,value)))))
           :on-error #'bitwarden-ui--error))
      (let ((length (read-number "Password length: " 20))
            (uppercase (y-or-n-p "Include uppercase letters? "))
            (lowercase (y-or-n-p "Include lowercase letters? "))
            (number (y-or-n-p "Include numbers? "))
            (special (y-or-n-p "Include special characters? "))
            (ambiguous (y-or-n-p "Avoid ambiguous characters? ")))
        (bitwarden-api-generate
         :length length :uppercase uppercase :lowercase lowercase
         :number number :special special :ambiguous ambiguous
         :on-success
         (lambda (value _job)
           (if callback (funcall callback value)
             (bitwarden-detail--open
              'generated `((name . "Generated Secret") (value . ,value)))))
         :on-error #'bitwarden-ui--error)))))

(defun bitwarden-ui--organization-prompt ()
  "Return a selected organization ID, or nil for the personal vault."
  (let* ((choices
          (cons
           '("Personal")
           (mapcar
            (lambda (organization)
              (cons (bitwarden-json-get 'name organization "Organization")
                    (bitwarden-json-get 'id organization)))
            (append (gethash 'organizations bitwarden--metadata-cache) nil))))
         (name (completing-read "Owner: " choices nil t nil nil "Personal")))
    (alist-get name choices nil nil #'string=)))

(defun bitwarden-import ()
  "Import a supported password-manager export into Bitwarden."
  (interactive)
  (bitwarden-api-import-formats
   :on-success
   (lambda (output _job)
     (let* ((formats (split-string output "\n" t "[[:space:]]+"))
            (format (completing-read "Import format: " formats nil t))
            (input (read-file-name "Import file: " nil nil t))
            (organization-id (bitwarden-ui--organization-prompt))
            (keyfile (and (y-or-n-p "Use a key file? ")
                          (read-file-name "Key file: " nil nil t)))
            (password (and (y-or-n-p "Import file requires a password? ")
                           (read-passwd "Import password: "))))
       (unless (file-regular-p input)
         (user-error "Choose a regular import file"))
       (when (yes-or-no-p
              (format "Import %s using format %s? " input format))
         (bitwarden-api-import
          format input :organization-id organization-id
          :keyfile keyfile :password password
          :on-success (lambda (_data _import-job)
                        (message "Bitwarden import completed"))
          :on-error #'bitwarden-ui--error))))
   :on-error #'bitwarden-ui--error))

(defun bitwarden-export ()
  "Export the personal or selected organization vault to a protected file."
  (interactive)
  (let* ((format (completing-read
                  "Export format: " '("encrypted_json" "json" "csv" "zip")
                  nil t nil nil "encrypted_json"))
         (default-name
          (format "bitwarden-export-%s.%s"
                  (format-time-string "%Y%m%d")
                  (if (string= format "encrypted_json") "json" format)))
         (output (expand-file-name
                  (read-file-name "Export to: " nil default-name nil)))
         (organization-id (bitwarden-ui--organization-prompt))
         password)
    (when (file-directory-p output)
      (user-error "Choose an export filename, not a directory"))
    (when (and (file-exists-p output)
               (not (yes-or-no-p (format "Overwrite %s? " output))))
      (user-error "Export cancelled"))
    (when (member format '("json" "csv" "zip"))
      (unless (yes-or-no-p
               "This format may contain unencrypted secrets. Continue? ")
        (user-error "Export cancelled")))
    (when (and (string= format "encrypted_json")
               (string= (completing-read
                         "Encryption: " '("Account protected" "Password protected")
                         nil t nil nil "Account protected")
                        "Password protected"))
      (let ((first (read-passwd "Export password: "))
            (second (read-passwd "Confirm export password: ")))
        (unless (string= first second)
          (user-error "Passwords do not match"))
        (setq password first)))
    (bitwarden-api-export
     format output :organization-id organization-id :password password
     :on-success
     (lambda (_data _job)
       (set-file-modes output #o600)
       (message "Bitwarden export saved to %s" output))
     :on-error #'bitwarden-ui--error)))

(defun bitwarden-ui-refresh-open-buffers ()
  "Refresh navigator and list buffers after a completed sync."
  (when (bitwarden-session-active-p)
    (when-let* ((navigator (get-buffer bitwarden-ui--navigator-buffer)))
      (with-current-buffer navigator (bitwarden-navigation-refresh)))
    (dolist (buffer (buffer-list))
      (with-current-buffer buffer
        (pcase major-mode
          ('bitwarden-list-mode (bitwarden-list-refresh))
          ('bitwarden-detail-mode
           (unless (eq bitwarden-detail-kind 'generated)
             (bitwarden-detail-refresh))))))))

(defun bitwarden-ui--clear-lists-on-lock ()
  "Remove cached rows from list buffers after lock or logout."
  (dolist (buffer (buffer-list))
    (with-current-buffer buffer
      (cond
       ((eq major-mode 'bitwarden-navigation-mode)
        (bitwarden-navigation-render))
       ((and (eq major-mode 'bitwarden-list-mode)
             (not (bitwarden-session-active-p)))
        (clrhash bitwarden-list-records)
        (setq tabulated-list-entries nil
              header-line-format " Bitwarden is locked")
        (tabulated-list-print t))))))

(add-hook 'bitwarden-after-state-change-hook
          #'bitwarden-ui--clear-lists-on-lock)
(add-hook 'bitwarden-after-sync-hook #'bitwarden-ui-refresh-open-buffers)

(provide 'bitwarden-ui)

;;; bitwarden-ui.el ends here
