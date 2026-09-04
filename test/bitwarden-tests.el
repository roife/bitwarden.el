;;; bitwarden-tests.el --- Tests for bitwarden.el -*- lexical-binding: t; -*-

;;; Code:

(require 'ert)
(require 'cl-lib)

(let ((root (expand-file-name ".." (file-name-directory
                                     (or load-file-name buffer-file-name)))))
  (add-to-list 'load-path root))

(require 'bitwarden)

(defconst bitwarden-test--root
  (expand-file-name ".." (file-name-directory
                          (or load-file-name buffer-file-name))))

(defconst bitwarden-test--fake-cli
  (expand-file-name "test/fake-bw" bitwarden-test--root))

(defun bitwarden-test--wait (predicate &optional timeout)
  "Wait until PREDICATE returns non-nil, failing after TIMEOUT seconds."
  (let ((deadline (+ (float-time) (or timeout 5))))
    (while (and (not (funcall predicate))
                (< (float-time) deadline))
      (accept-process-output nil 0.02))
    (should (funcall predicate))))

(defun bitwarden-test--reset-state (existing-buffers)
  "Return package globals to a clean test state."
  (when (and bitwarden--active-job
             (process-live-p (bitwarden-job-process bitwarden--active-job)))
    (delete-process (bitwarden-job-process bitwarden--active-job)))
  (setq bitwarden--active-job nil)
  (dolist (job bitwarden--queue)
    (bitwarden--destroy-job-buffers job))
  (setq bitwarden--queue nil)
  (when (timerp bitwarden--idle-timer)
    (cancel-timer bitwarden--idle-timer))
  (setq bitwarden--idle-timer nil)
  (bitwarden--clear-sensitive-state 'unknown)
  (setq bitwarden--status-data nil)
  (dolist (buffer (buffer-list))
    (when (and (not (memq buffer existing-buffers))
               (string-prefix-p "*Bitwarden" (buffer-name buffer)))
      (with-current-buffer buffer (set-buffer-modified-p nil))
      (kill-buffer buffer))))

(defmacro bitwarden-test--with-fake (&rest body)
  "Run BODY against the fake CLI with isolated state."
  (declare (indent 0) (debug t))
  `(let* ((bitwarden-executable bitwarden-test--fake-cli)
          (bitwarden-sync-policy 'manual)
          (bitwarden-idle-lock-seconds nil)
          (bitwarden-after-state-change-hook nil)
          (bitwarden-after-sync-hook nil)
          (bitwarden-after-change-hook nil)
          (bitwarden--queue nil)
          (bitwarden--active-job nil)
          (bitwarden--job-counter 0)
          (bitwarden--session nil)
          (bitwarden--status (quote unknown))
          (bitwarden--status-data nil)
          (bitwarden--metadata-cache (make-hash-table :test (quote equal)))
          (bitwarden--last-activity nil)
          (bitwarden--idle-timer nil)
          (bitwarden--sensitive-buffers nil)
          (bitwarden-ui--navigator-buffer "*Bitwarden Test Navigator*")
          (existing-buffers (buffer-list))
          (test-log (make-temp-file "bitwarden-test-log-"))
          (process-environment (copy-sequence process-environment)))
     (setenv "FAKE_BW_LOG" test-log)
     (setenv "FAKE_BW_STATUS_JSON"
             "{\"serverUrl\":\"https://example.test\",\"lastSync\":null,\"userEmail\":\"tester@example.test\",\"userId\":\"user-1\",\"status\":\"locked\"}")
     (unwind-protect
         (progn
           (bitwarden-test--reset-state existing-buffers)
           ,@body)
       (bitwarden-test--reset-state existing-buffers)
       (when (file-exists-p test-log) (delete-file test-log)))))

(ert-deftest bitwarden-test-status ()
  (bitwarden-test--with-fake
    (let (status failure)
      (bitwarden-api-status
       :on-success (lambda (value _job) (setq status value))
       :on-error (lambda (error-info _job) (setq failure error-info)))
      (bitwarden-test--wait (lambda () (or status failure)))
      (should-not failure)
      (should (equal (bitwarden-json-get 'status status) "locked"))
      (should (eq bitwarden--status 'locked)))))

(ert-deftest bitwarden-test-open-shows-loading-before-status ()
  (bitwarden-test--with-fake
    (let (loading-content)
      (cl-letf (((symbol-function 'bitwarden-api-status)
                 (lambda (&rest _args)
                   (setq loading-content
                         (with-current-buffer bitwarden-ui--navigator-buffer
                           (buffer-string))))))
        (save-window-excursion
          (bitwarden-ui-open)
          (let ((buffer (get-buffer bitwarden-ui--navigator-buffer)))
            (should (string-match-p "Loading Bitwarden" loading-content))
            (should (eq (buffer-local-value 'major-mode buffer)
                        'bitwarden-navigation-mode))
            (should (buffer-local-value 'header-line-format buffer))
            (bitwarden--set-session "fake-session-key")
            (cl-letf (((symbol-function 'bitwarden-navigation-refresh)
                       #'ignore))
              (bitwarden-navigation-open))
            (should (eq buffer (get-buffer bitwarden-ui--navigator-buffer)))
            (with-current-buffer buffer
              (should (string-match-p "Vault" (buffer-string)))
              (should-not (string-match-p "Loading Bitwarden"
                                          (buffer-string))))))))))

(ert-deftest bitwarden-test-unlock-keeps-session-out-of-argv ()
  (bitwarden-test--with-fake
    (let ((password "master-secret") result failure)
      (bitwarden-api-unlock
       password
       :on-success (lambda (value _job) (setq result value))
       :on-error (lambda (error-info _job) (setq failure error-info)))
      (bitwarden-test--wait (lambda () (or result failure)))
      (should-not failure)
      (should (equal result "fake-session-key"))
      (should (bitwarden-session-active-p))
      (should (eq bitwarden--status 'unlocked))
      (let ((log (with-temp-buffer
                   (insert-file-contents test-log)
                   (buffer-string))))
        (should (string-match-p "unlock-password:set" log))
        (should-not (string-match-p "master-secret" log))))))

(ert-deftest bitwarden-test-login-answers-two-consecutive-prompts ()
  (bitwarden-test--with-fake
    (setenv "FAKE_BW_TWO_PROMPTS" "1")
    (let ((password "master-secret")
          (two-step "123456")
          result failure prompts)
      (bitwarden-api-login
       'password :email "tester@example.test" :password password
       :two-step-method 0 :two-step-code two-step
       :prompt-handler
       (lambda (prompt)
         (push prompt prompts)
         "device-code")
       :on-success (lambda (value _job) (setq result value))
       :on-error (lambda (error-info _job) (setq failure error-info)))
      (bitwarden-test--wait (lambda () (or result failure)) 8)
      (should-not failure)
      (should (equal result "fake-session-key"))
      (should (= (length prompts) 1))
      (should (string-match-p "New device" (car prompts)))
      (let ((log (with-temp-buffer
                   (insert-file-contents test-log)
                   (buffer-string))))
        (should (string-match-p "two-step:set" log))
        (should (string-match-p "new-device:set" log))
        (should-not (string-match-p "123456\|device-code\|master-secret" log))))))

(ert-deftest bitwarden-test-global-session-is-not-inherited ()
  (bitwarden-test--with-fake
    (setenv "BW_SESSION" "must-not-leak")
    (let (done failure)
      (bitwarden-api-status
       :on-success (lambda (_value _job) (setq done t))
       :on-error (lambda (error-info _job) (setq failure error-info)))
      (bitwarden-test--wait (lambda () (or done failure)))
      (should-not failure)
      (let ((log (with-temp-buffer
                   (insert-file-contents test-log)
                   (buffer-string))))
        (should (string-match-p "command:status" log))
        (should-not (string-match-p "must-not-leak" log))
        (should (string-match-p "session:$" (string-trim log)))))))

(ert-deftest bitwarden-test-queue-is-serialized-and-cancellable ()
  (bitwarden-test--with-fake
    (let (first-done second-done)
      (bitwarden-request
       '("slow" "0.15") :requires-session nil :parser 'string
       :on-success (lambda (_value _job) (setq first-done t)))
      (let ((second
             (bitwarden-request
              '("status") :requires-session nil
              :on-success (lambda (_value _job) (setq second-done t)))))
        (should (eq (bitwarden-job-state second) 'queued))
        (should (bitwarden-cancel-job second))
        (should (eq (bitwarden-job-state second) 'cancelled)))
      (bitwarden-test--wait (lambda () first-done))
      (should-not second-done)
      (let ((log (with-temp-buffer
                   (insert-file-contents test-log)
                   (buffer-string))))
        (should (string-match-p "command:slow" log))
        (should-not (string-match-p "command:status" log))))))

(ert-deftest bitwarden-test-locked-error-clears-session ()
  (bitwarden-test--with-fake
    (bitwarden--set-session "temporary-session")
    (let (failure)
      (bitwarden-request
       '("fail-locked") :parser 'string
       :on-error (lambda (error-info _job) (setq failure error-info)))
      (bitwarden-test--wait (lambda () failure))
      (should (eq (bitwarden-cli-error-kind failure) 'locked))
      (should-not (bitwarden-session-active-p))
      (should (eq bitwarden--status 'locked)))))

(ert-deftest bitwarden-test-json-payload-preserves-false-null-and-arrays ()
  (let* ((payload '((favorite . :false)
                    (notes)
                    (collectionIds . [])
                    (fields . [((type . 0) (name . "x") (value . "y"))])))
         (encoded (bitwarden--encode-payload payload))
         (decoded (decode-coding-string
                   (base64-decode-string encoded) 'utf-8-unix))
         (parsed (json-parse-string decoded
                                    :object-type 'alist
                                    :array-type 'array
                                    :null-object nil
                                    :false-object :false)))
    (should (eq (bitwarden-json-get 'favorite parsed) :false))
    (should-not (alist-get 'notes parsed))
    (should (equal (bitwarden-json-get 'collectionIds parsed) []))
    (should (= (length (bitwarden-json-get 'fields parsed)) 1))))

(ert-deftest bitwarden-test-metadata-drops-decrypted-fields ()
  (let* ((item '((id . "id") (type . 1) (name . "Name")
                 (favorite . t) (login . ((password . "secret")))
                 (notes . "also secret") (revisionDate . "date")))
         (metadata (bitwarden-item-metadata item)))
    (should (equal (bitwarden-json-get 'id metadata) "id"))
    (should-not (assq 'login metadata))
    (should-not (assq 'notes metadata))))

(ert-deftest bitwarden-test-create-payload-travels-on-stdin ()
  (bitwarden-test--with-fake
    (setenv "FAKE_BW_CAPTURE_STDIN" "1")
    (bitwarden--set-session "fake-session-key")
    (let (result failure)
      (bitwarden-api-create
       "item" '((type . 1) (name . "Secret fixture")
                (favorite . :false) (fields . []))
       :on-success (lambda (value _job) (setq result value))
       :on-error (lambda (error-info _job) (setq failure error-info)))
      (bitwarden-test--wait (lambda () (or result failure)))
      (should-not failure)
      (let ((log (with-temp-buffer
                   (insert-file-contents test-log)
                   (buffer-string))))
        (should (string-match-p "stdin:" log))
        (should-not (string-match-p "Secret fixture" log))
        (should-not (string-match-p "fake-session-key" log))))))

(ert-deftest bitwarden-test-detail-masks-and-reveals-password ()
  (bitwarden-test--with-fake
    (with-temp-buffer
      (bitwarden-detail-mode)
      (setq-local bitwarden-detail-kind 'item
                  bitwarden-detail-object
                  (copy-tree
                   '((id . "id") (type . 1) (name . "Login")
                     (favorite . :false) (reprompt . 0)
                     (login . ((username . "alice")
                               (password . "visible-only-on-demand")
                               (uris . [])))) t))
      (bitwarden-detail-render)
      (should (object-of-class-p magit-root-section 'bitwarden-root-section))
      (should (seq-some
               (lambda (section)
                 (object-of-class-p section 'bitwarden-group-section))
               (oref magit-root-section children)))
      (let ((summary (seq-find
                      (lambda (section) (eq (oref section value) 'summary))
                      (oref magit-root-section children))))
        (magit-section-hide summary)
        (should (oref summary hidden))
        (magit-section-show summary))
      (should (string-match-p (regexp-quote bitwarden-mask-string)
                              (buffer-string)))
      (should-not (string-match-p "visible-only-on-demand" (buffer-string)))
      (goto-char (point-min))
      (search-forward bitwarden-mask-string)
      (should (eq (get-text-property (1- (point)) 'face)
                  'bitwarden-secret))
      (goto-char (point-min))
      (search-forward "Password:")
      (bitwarden-detail-toggle-secret)
      (goto-char (point-min))
      (search-forward "visible-only-on-demand")
      (should (eq (get-text-property (1- (point)) 'face)
                  'bitwarden-revealed-secret)))))

(ert-deftest bitwarden-test-item-form-preserves-unknown-fields ()
  (bitwarden-test--with-fake
    (with-temp-buffer
      (bitwarden-form-mode)
      (setq-local bitwarden-form-kind 'item
                  bitwarden-form-new-p nil
                  bitwarden-form-original
                  (copy-tree
                   '((id . "item-1") (type . 1) (name . "Login")
                     (favorite . :false) (reprompt . 0)
                     (folderId) (organizationId)
                     (collectionIds . []) (notes)
                     (login . ((username . "alice") (password . "pw")
                               (totp) (uris . [])))
                     (fields . [((type . 3) (name . "linked")
                                 (value . "username"))])
                     (futureField . ((enabled . t)))) t))
      (bitwarden-form-render)
      (let ((payload (bitwarden-form--collect-item)))
        (should (equal (map-nested-elt payload '(futureField enabled)) t))
        (should (= (length (bitwarden-json-get 'fields payload)) 1))
        (should (= (bitwarden-json-get
                    'type (aref (bitwarden-json-get 'fields payload) 0))
                   3))))))

(ert-deftest bitwarden-test-form-preserves-unlisted-collection-membership ()
  (bitwarden-test--with-fake
    (puthash 'organizations [((id . "org-1") (name . "Org"))]
             bitwarden--metadata-cache)
    (puthash 'collections
             [((id . "visible") (name . "Visible")
               (organizationId . "org-1"))]
             bitwarden--metadata-cache)
    (with-temp-buffer
      (bitwarden-form-mode)
      (setq-local bitwarden-form-kind 'item
                  bitwarden-form-new-p nil
                  bitwarden-form-original
                  (copy-tree
                   '((id . "item-1") (type . 2) (name . "Note")
                     (favorite . :false) (reprompt . 0)
                     (organizationId . "org-1")
                     (collectionIds . ["not-enumerated"])
                     (fields . []) (secureNote . ((type . 0)))) t))
      (bitwarden-form-render)
      (should (equal (bitwarden-form--selected-collections)
                     '("not-enumerated"))))))

(ert-deftest bitwarden-test-all-five-item-forms-round-trip ()
  (bitwarden-test--with-fake
    (dolist
        (item
         '(((type . 1) (name . "Login") (favorite . :false) (reprompt . 0)
            (fields . []) (collectionIds . [])
            (login . ((username . "alice") (password . "pw")
                      (totp) (uris . []))))
           ((type . 2) (name . "Note") (favorite . :false) (reprompt . 0)
            (fields . []) (collectionIds . []) (notes . "body")
            (secureNote . ((type . 0))))
           ((type . 3) (name . "Card") (favorite . :false) (reprompt . 0)
            (fields . []) (collectionIds . [])
            (card . ((cardholderName . "Alice") (number . "4111")
                     (expMonth . "12") (expYear . "2030") (code . "123"))))
           ((type . 4) (name . "Identity") (favorite . :false) (reprompt . 0)
            (fields . []) (collectionIds . [])
            (identity . ((firstName . "Alice") (lastName . "Example")
                         (email . "alice@example.test"))))
           ((type . 5) (name . "SSH") (favorite . :false) (reprompt . 0)
            (fields . []) (collectionIds . [])
            (sshKey . ((privateKey . "PRIVATE") (publicKey . "PUBLIC")
                       (keyFingerprint . "SHA256:fixture"))))))
      (with-temp-buffer
        (bitwarden-form-mode)
        (setq-local bitwarden-form-kind 'item
                    bitwarden-form-new-p t
                    bitwarden-form-original
                    (copy-tree item t))
        (bitwarden-form-render)
        (let ((payload (bitwarden-form--collect-item)))
          (should (= (bitwarden-json-get 'type payload)
                     (bitwarden-json-get 'type item)))
          (should (equal (bitwarden-json-get 'name payload)
                         (bitwarden-json-get 'name item)))
          (pcase (bitwarden-json-get 'type item)
            (1 (should (equal (map-nested-elt
                               payload '(login username)) "alice")))
            (2 (should (equal (map-nested-elt
                               payload '(secureNote type)) 0)))
            (3 (should (equal (map-nested-elt
                               payload '(card number)) "4111")))
            (4 (should (equal (map-nested-elt
                               payload '(identity firstName)) "Alice")))
            (5 (should (equal (map-nested-elt
                               payload '(sshKey privateKey)) "PRIVATE")))))))))

(ert-deftest bitwarden-test-folder-and-send-forms-round-trip ()
  (bitwarden-test--with-fake
    (with-temp-buffer
      (bitwarden-form-mode)
      (setq-local bitwarden-form-kind 'folder
                  bitwarden-form-new-p t
                  bitwarden-form-original '((name . "Work")))
      (bitwarden-form-render)
      (should (equal (bitwarden-json-get
                      'name (bitwarden-form--collect-folder)) "Work")))
    (with-temp-buffer
      (bitwarden-form-mode)
      (setq-local bitwarden-form-kind 'send
                  bitwarden-form-new-p t
                  bitwarden-form-original
                  (copy-tree
                   '((type . 0) (name . "Text Send") (notes)
                     (maxAccessCount . 3) (expirationDate)
                     (deletionDate . "2026-09-11T00:00:00.000Z")
                     (disabled . :false)
                     (text . ((text . "send body") (hidden . t)))) t))
      (bitwarden-form-render)
      (let ((payload (bitwarden-form--collect-send)))
        (should (equal (map-nested-elt payload '(text text))
                       "send body"))
        (should (eq (map-nested-elt payload '(text hidden)) t))))))

(ert-deftest bitwarden-test-list-render-contains-metadata-only ()
  (bitwarden-test--with-fake
    (bitwarden--set-session "fake-session-key")
    (puthash 'folders [((id . "folder-1") (name . "Work"))]
             bitwarden--metadata-cache)
    (with-temp-buffer
      (bitwarden-list-mode)
      (setq-local bitwarden-list-kind 'items
                  bitwarden-list-title "Test"
                  bitwarden-list-filter nil
                  bitwarden-list-records (make-hash-table :test #'equal))
      (bitwarden-ui--configure-list-columns)
      (bitwarden-list--set-entries
       (list (bitwarden-item-metadata
              '((id . "item-1") (type . 1) (name . "Example")
                (folderId . "folder-1") (favorite . t)
                (login . ((password . "must-not-render")))))))
      (should (string-match-p "Example" (buffer-string)))
      (goto-char (point-min))
      (search-forward "Example")
      (should (eq (get-text-property (1- (point)) 'face) 'bold))
      (should-not (string-match-p "must-not-render" (buffer-string))))))

(ert-deftest bitwarden-test-async-navigation-list-and-form-flow ()
  (bitwarden-test--with-fake
    (bitwarden--set-session "fake-session-key")
    (save-window-excursion
      (bitwarden-navigation-open)
      (bitwarden-test--wait
       (lambda () (and (null bitwarden--active-job)
                       (null bitwarden--queue))))
      (let ((navigator (get-buffer bitwarden-ui--navigator-buffer)))
        (should (buffer-live-p navigator))
        (with-current-buffer navigator
          (should (object-of-class-p magit-root-section
                                     'bitwarden-root-section))
          (should (seq-some
                   (lambda (group)
                     (seq-some
                      (lambda (section)
                        (object-of-class-p
                         section 'bitwarden-navigation-entry-section))
                      (oref group children)))
                   (oref magit-root-section children)))
          (let* ((group (car (oref magit-root-section children)))
                 (entry (car (oref group children))))
            (should (eq (keymap-lookup (symbol-value (oref entry keymap))
                                       "RET")
                        'bitwarden-navigation-open-at-point)))
          (should (string-match-p "Work" (buffer-string)))
          (should (string-match-p "Example Org" (buffer-string)))))
      (bitwarden-list-open-buffer 'items "Async Test" nil)
      (bitwarden-test--wait
       (lambda () (and (null bitwarden--active-job)
                       (null bitwarden--queue))))
      (let ((list-buffer (get-buffer "*Bitwarden Async Test*")))
        (should (buffer-live-p list-buffer))
        (with-current-buffer list-buffer
          (should (string-match-p "Example Login" (buffer-string)))
          (should-not (string-match-p "correct horse" (buffer-string)))
          (goto-char (point-min))
          (let ((metadata (bitwarden-list--record-at-point)))
            (bitwarden-edit-item metadata)))
        (bitwarden-test--wait
         (lambda ()
           (seq-find
            (lambda (buffer)
              (with-current-buffer buffer
                (eq major-mode 'bitwarden-form-mode)))
            (buffer-list))))
        (let ((form
               (seq-find
                (lambda (buffer)
                  (with-current-buffer buffer
                    (eq major-mode 'bitwarden-form-mode)))
                (buffer-list))))
          (with-current-buffer form
            (should (eq bitwarden-form-source-buffer list-buffer))))))))

(ert-deftest bitwarden-test-password-export-uses-pty-prompt ()
  (bitwarden-test--with-fake
    (bitwarden--set-session "fake-session-key")
    (let ((output (make-temp-file "bitwarden-export-test-"))
          (password "export-secret")
          result failure)
      (delete-file output)
      (unwind-protect
          (progn
            (bitwarden-api-export
             "encrypted_json" output :password password
             :on-success (lambda (value _job) (setq result value))
             :on-error (lambda (error-info _job) (setq failure error-info)))
            (bitwarden-test--wait (lambda () (or result failure)) 8)
            (should-not failure)
            (should (file-exists-p output))
            (let ((log (with-temp-buffer
                         (insert-file-contents test-log)
                         (buffer-string))))
              (should (string-match-p "export-password:set" log))
              (should-not (string-match-p "export-secret" log))))
        (when (file-exists-p output) (delete-file output))))))

(ert-deftest bitwarden-test-idle-check-requests-lock ()
  (bitwarden-test--with-fake
    (let ((bitwarden-idle-lock-seconds 1)
          requested)
      (bitwarden--set-session "fake-session-key")
      (setq bitwarden--last-activity (- (float-time) 10))
      (cl-letf (((symbol-function 'bitwarden-api-lock)
                 (lambda (&rest _args) (setq requested t))))
        (bitwarden--idle-check))
      (should requested))))

(provide 'bitwarden-tests)

;;; bitwarden-tests.el ends here
