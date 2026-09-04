;;; bitwarden-core.el --- Async Bitwarden CLI integration -*- lexical-binding: t; -*-

;; Version: 0.1.0
;; Package-Requires: ((emacs "31.1"))
;; Keywords: tools, password, bitwarden

;;; Commentary:

;; This file contains the asynchronous, shell-free process layer used by
;; bitwarden.el.  It deliberately keeps the BW_SESSION value in memory and
;; passes secrets to child processes through a scoped environment or a PTY.

;;; Code:

(require 'cl-lib)
(require 'ansi-color)
(require 'json)
(require 'map)
(require 'seq)
(require 'subr-x)

(defgroup bitwarden nil
  "A user interface for the Bitwarden command-line client."
  :group 'applications
  :prefix "bitwarden-")

(defcustom bitwarden-executable
  (or (executable-find "bw") "bw")
  "Path or command name of the Bitwarden CLI executable."
  :type '(choice file string)
  :group 'bitwarden)

(defcustom bitwarden-idle-lock-seconds 900
  "Seconds without Bitwarden activity before the vault is locked.
Set this to nil or zero to disable automatic locking."
  :type '(choice (const :tag "Disabled" nil) integer)
  :group 'bitwarden)

(defcustom bitwarden-sync-policy 'open-and-after-write
  "When Bitwarden should synchronize its local vault.
`open-and-after-write' synchronizes when the UI opens and after mutations.
`manual' only synchronizes when explicitly requested."
  :type '(choice
          (const :tag "On open and after writes" open-and-after-write)
          (const :tag "Manual only" manual))
  :group 'bitwarden)

(defcustom bitwarden-copy-policy 'kill-ring
  "Where copied Bitwarden values are placed.
The default intentionally uses the normal kill ring and does not expire
values.  `system-clipboard' avoids adding values to `kill-ring'."
  :type '(choice
          (const :tag "Normal kill ring" kill-ring)
          (const :tag "System clipboard only" system-clipboard))
  :group 'bitwarden)

(defcustom bitwarden-display-buffer-action nil
  "Optional display action used for Bitwarden buffers.
When nil, Bitwarden uses `pop-to-buffer' and respects normal Emacs display
rules.  Otherwise this value is passed to `display-buffer'."
  :type '(choice (const :tag "Use normal display rules" nil) sexp)
  :group 'bitwarden)

(defcustom bitwarden-mask-string "••••••••"
  "Text used in place of sensitive values in detail buffers."
  :type 'string
  :group 'bitwarden)

(cl-defstruct (bitwarden-job
               (:constructor bitwarden--make-job))
  "An opaque asynchronous Bitwarden request."
  id
  argv
  input
  parser
  requires-session
  on-success
  on-error
  environment
  allow-interaction
  interactive-input
  prompt-handler
  prompt-regexp
  prompt-offset
  prompt-timer
  mutation
  state
  process
  stdout-buffer
  stderr-buffer)

(cl-defstruct (bitwarden-cli-error
               (:constructor bitwarden--make-cli-error))
  "A structured failure returned to asynchronous error callbacks."
  kind
  message
  exit-code
  command
  stderr)

(defvar bitwarden-after-state-change-hook nil
  "Hook run whenever login or lock state changes.")

(defvar bitwarden-after-sync-hook nil
  "Hook run after a successful sync or after-write sync failure.")

(defvar bitwarden-after-change-hook nil
  "Hook run immediately after a successful vault mutation.")

(defvar bitwarden--queue nil)
(defvar bitwarden--active-job nil)
(defvar bitwarden--job-counter 0)
(defvar bitwarden--session nil)
(defvar bitwarden--status 'unknown)
(defvar bitwarden--status-data nil)
(defvar bitwarden--metadata-cache (make-hash-table :test #'equal))
(defvar bitwarden--last-activity nil)
(defvar bitwarden--idle-timer nil)
(defvar bitwarden--sensitive-buffers nil)

(defun bitwarden-session-active-p ()
  "Return non-nil when this Emacs process owns a session key."
  (and (stringp bitwarden--session)
       (not (string-empty-p bitwarden--session))))

(defsubst bitwarden-json-get (key object &optional default)
  "Return KEY from JSON alist OBJECT, or DEFAULT when absent."
  (map-elt object key default))

(defun bitwarden-item-metadata (item)
  "Return a sanitized metadata-only copy of ITEM."
  (map-filter
   (lambda (key _value)
     (memq key '(id type name folderId organizationId collectionIds
                    favorite reprompt revisionDate creationDate
                    deletedDate archivedDate edit viewPassword)))
   item))

(defun bitwarden-send-metadata (send)
  "Return a sanitized metadata-only copy of SEND."
  (map-filter
   (lambda (key _value)
     (memq key '(id name type accessCount maxAccessCount revisionDate
                    expirationDate deletionDate disabled hideEmail url)))
   send))

(defun bitwarden--set-session (session)
  "Replace the in-memory session key with SESSION."
  (setq bitwarden--session
        (and session (string-trim session)))
  (when (bitwarden-session-active-p)
    (setq bitwarden--status 'unlocked)
    (bitwarden-touch))
  (run-hooks 'bitwarden-after-state-change-hook))

(defun bitwarden--set-status-from-data (data)
  "Update local state using parsed `bw status' DATA."
  (setq bitwarden--status-data data)
  (let ((status (bitwarden-json-get 'status data "unknown")))
    (setq bitwarden--status (intern (downcase status))))
  (unless (eq bitwarden--status 'unlocked)
    (setq bitwarden--session nil))
  (run-hooks 'bitwarden-after-state-change-hook)
  data)

(defun bitwarden-touch ()
  "Record activity and ensure the idle-lock timer is running."
  (setq bitwarden--last-activity (float-time))
  (when (and (bitwarden-session-active-p)
             bitwarden-idle-lock-seconds
             (> bitwarden-idle-lock-seconds 0)
             (not (timerp bitwarden--idle-timer)))
    (setq bitwarden--idle-timer
          (run-at-time 60 60 #'bitwarden--idle-check))))

(defun bitwarden--idle-check ()
  "Lock the vault if the configured inactivity period has elapsed."
  (when (and (bitwarden-session-active-p)
             bitwarden-idle-lock-seconds
             (> bitwarden-idle-lock-seconds 0)
             bitwarden--last-activity
             (>= (- (float-time) bitwarden--last-activity)
                 bitwarden-idle-lock-seconds))
    (setq bitwarden--last-activity (float-time))
    (bitwarden-api-lock
     :on-success (lambda (_data _job)
                   (message "Bitwarden locked after inactivity"))
     :on-error #'ignore)))

(defun bitwarden--clear-sensitive-state (&optional status)
  "Clear session data and sensitive buffers, setting STATUS when given."
  (when (timerp bitwarden--idle-timer)
    (cancel-timer bitwarden--idle-timer))
  (setq bitwarden--idle-timer nil
        bitwarden--last-activity nil)
  (setq bitwarden--session nil)
  (clrhash bitwarden--metadata-cache)
  (let ((buffers bitwarden--sensitive-buffers))
    (setq bitwarden--sensitive-buffers nil)
    (dolist (buffer buffers)
      (when (buffer-live-p buffer)
        (with-current-buffer buffer
          (set-buffer-modified-p nil))
        (kill-buffer buffer))))
  (when status
    (setq bitwarden--status status))
  (run-hooks 'bitwarden-after-state-change-hook))

(defun bitwarden--classify-error (exit-code stdout stderr argv)
  "Build a `bitwarden-cli-error' for a failed command."
  (let* ((combined (string-trim
                    (ansi-color-filter-apply (concat stderr "\n" stdout))))
         (kind
          (cond
           ((string-match-p
             (rx (or "Vault is locked" "vault is locked"
                     "session key is invalid" "Invalid session"))
             combined)
            'locked)
           ((string-match-p
             (rx (or "not logged in" "unauthenticated" "You are not logged"))
             combined)
            'unauthenticated)
           (t 'cli)))
         (message (if (string-empty-p combined)
                      (format "bw exited with status %s" exit-code)
                    combined)))
    (bitwarden--make-cli-error
     :kind kind
     :message message
     :exit-code exit-code
     :command argv
     :stderr (string-trim (ansi-color-filter-apply stderr)))))

(defun bitwarden--parse-output (parser output)
  "Parse OUTPUT according to PARSER."
  (let ((output (ansi-color-filter-apply output)))
    (pcase parser
      ('none nil)
      ('string (string-trim output))
      ('json
       (json-parse-string output
                          :object-type 'alist
                          :array-type 'array
                          :null-object nil
                          :false-object :false))
      ((pred functionp) (funcall parser output))
      (_ (error "Unknown Bitwarden parser: %S" parser)))))

(defun bitwarden--call-callback (callback &rest arguments)
  "Invoke CALLBACK with ARGUMENTS without breaking the process queue."
  (when callback
    (condition-case error-data
        (apply callback arguments)
      (error
       (message "Bitwarden callback failed: %s"
                (error-message-string error-data))))))

(defun bitwarden--destroy-job-buffers (job)
  "Kill the temporary output buffers owned by JOB."
  (dolist (buffer (list (bitwarden-job-stdout-buffer job)
                        (bitwarden-job-stderr-buffer job)))
    (when (buffer-live-p buffer)
      (with-current-buffer buffer
        (set-buffer-modified-p nil))
      (kill-buffer buffer)))
  (setf (bitwarden-job-stdout-buffer job) nil
        (bitwarden-job-stderr-buffer job) nil))

(defun bitwarden--cancel-prompt-timer (job)
  "Cancel JOB's prompt polling timer."
  (when (timerp (bitwarden-job-prompt-timer job))
    (cancel-timer (bitwarden-job-prompt-timer job)))
  (setf (bitwarden-job-prompt-timer job) nil))

(defun bitwarden--maybe-answer-prompt (process)
  "Send a pending secret to PROCESS once its expected prompt appears."
  (let* ((job (process-get process 'bitwarden-job))
         (text (and job
                    (concat
                     (with-current-buffer (bitwarden-job-stderr-buffer job)
                       (buffer-string))
                     "\n"
                     (with-current-buffer (bitwarden-job-stdout-buffer job)
                       (buffer-string)))))
         (fresh (and text
                     (substring
                      text (min (or (bitwarden-job-prompt-offset job) 0)
                                (length text))))))
    (cond
     ((or (null job) (not (process-live-p process)))
      (when job (bitwarden--cancel-prompt-timer job)))
     ((string-match
       (or (bitwarden-job-prompt-regexp job) ".")
       fresh)
      (let ((response
             (or (bitwarden-job-interactive-input job)
                 (funcall (bitwarden-job-prompt-handler job)
                          (match-string 0 fresh)))))
        (setf (bitwarden-job-prompt-offset job) (length text)
              (bitwarden-job-interactive-input job) nil)
        (if response
            (progn
              (process-send-string process (concat response "\n"))
              (unless (bitwarden-job-prompt-handler job)
                (bitwarden--cancel-prompt-timer job)))
          (bitwarden--cancel-prompt-timer job)
          (delete-process process)))))))

(defun bitwarden--start-job (job)
  "Start asynchronous JOB."
  (let ((executable (executable-find bitwarden-executable)))
    (if (not executable)
        (bitwarden--finish-with-start-error
         job
         (bitwarden--make-cli-error
          :kind 'missing-executable
          :message (format "Cannot find Bitwarden CLI: %s"
                           bitwarden-executable)
          :exit-code nil
          :command (bitwarden-job-argv job)
          :stderr ""))
      (let* ((stdout (generate-new-buffer " *bitwarden stdout*"))
             (stderr (generate-new-buffer " *bitwarden stderr*"))
             (process-environment (copy-sequence process-environment))
             (command
              (append
               (list executable)
               (unless (bitwarden-job-allow-interaction job)
                 '("--nointeraction"))
               (bitwarden-job-argv job))))
        (setenv "BW_SESSION" nil)
        (when (bitwarden-job-requires-session job)
          (setenv "BW_SESSION" bitwarden--session))
        (dolist (entry (bitwarden-job-environment job))
          (setenv (car entry) (cdr entry)))
        (with-current-buffer stdout (buffer-disable-undo))
        (with-current-buffer stderr (buffer-disable-undo))
        (setf (bitwarden-job-stdout-buffer job) stdout
              (bitwarden-job-stderr-buffer job) stderr
              (bitwarden-job-state job) 'running)
        (condition-case error-data
            (let ((process
                   (make-process
                    :name (format "bitwarden-%d" (bitwarden-job-id job))
                    :command command
                    :buffer stdout
                    :stderr stderr
                    :connection-type
                    (if (or (bitwarden-job-interactive-input job)
                            (bitwarden-job-prompt-handler job))
                        'pty 'pipe)
                    :coding 'utf-8-unix
                    :noquery t
                    :sentinel #'bitwarden--process-sentinel)))
              (setf (bitwarden-job-process job) process)
              (process-put process 'bitwarden-job job)
              (setf (bitwarden-job-environment job) nil)
              (when (bitwarden-job-input job)
                (process-send-string process (bitwarden-job-input job))
                (process-send-eof process)
                (setf (bitwarden-job-input job) nil))
              (when (or (bitwarden-job-interactive-input job)
                        (bitwarden-job-prompt-handler job))
                (setf (bitwarden-job-prompt-timer job)
                      (run-at-time 0.05 0.05
                                   #'bitwarden--maybe-answer-prompt process))))
          (error
           (bitwarden--destroy-job-buffers job)
           (bitwarden--finish-with-start-error
            job
            (bitwarden--make-cli-error
             :kind 'process
             :message (error-message-string error-data)
             :exit-code nil
             :command (bitwarden-job-argv job)
             :stderr ""))))))))

(defun bitwarden--finish-with-start-error (job error-info)
  "Finish JOB immediately with ERROR-INFO."
  (setf (bitwarden-job-state job) 'failed)
  (setf (bitwarden-job-input job) nil
        (bitwarden-job-environment job) nil
        (bitwarden-job-interactive-input job) nil)
  (setq bitwarden--active-job nil)
  (bitwarden--call-callback (bitwarden-job-on-error job) error-info job)
  (bitwarden--dispatch-next))

(defun bitwarden--finish-job (job process)
  "Finish JOB after PROCESS exits."
  (bitwarden--cancel-prompt-timer job)
  (let* ((stdout (with-current-buffer (bitwarden-job-stdout-buffer job)
                   (buffer-string)))
         (stderr (with-current-buffer (bitwarden-job-stderr-buffer job)
                   (buffer-string)))
         (exit-code (process-exit-status process))
         (cancelled (eq (bitwarden-job-state job) 'cancelled))
         success-value
         failure)
    (unless cancelled
      (if (= exit-code 0)
          (condition-case error-data
              (setq success-value
                    (bitwarden--parse-output
                     (bitwarden-job-parser job) stdout))
            (error
             (setq failure
                   (bitwarden--make-cli-error
                    :kind 'json
                    :message (format "Could not parse bw output: %s"
                                     (error-message-string error-data))
                    :exit-code exit-code
                    :command (bitwarden-job-argv job)
                    :stderr (string-trim
                             (ansi-color-filter-apply stderr))))))
        (setq failure
              (bitwarden--classify-error
               exit-code stdout stderr (bitwarden-job-argv job)))))
    (bitwarden--destroy-job-buffers job)
    (setf (bitwarden-job-input job) nil
          (bitwarden-job-environment job) nil
          (bitwarden-job-interactive-input job) nil)
    (cond
     (cancelled)
     (failure
      (setf (bitwarden-job-state job) 'failed)
      (when (memq (bitwarden-cli-error-kind failure)
                  '(locked unauthenticated))
        (bitwarden--clear-sensitive-state
         (bitwarden-cli-error-kind failure)))
      (bitwarden--call-callback (bitwarden-job-on-error job) failure job))
     (t
      (setf (bitwarden-job-state job) 'succeeded)
      (bitwarden-touch)
      (bitwarden--call-callback
       (bitwarden-job-on-success job) success-value job)))
    (setq bitwarden--active-job nil)
    (when (and (bitwarden-job-mutation job)
               (eq (bitwarden-job-state job) 'succeeded))
      (clrhash bitwarden--metadata-cache)
      (run-hooks 'bitwarden-after-change-hook)
      (when (eq bitwarden-sync-policy 'open-and-after-write)
        (bitwarden-api-sync
         :on-success
         (lambda (_data _sync-job)
           (run-hooks 'bitwarden-after-sync-hook))
         :on-error
         (lambda (error-info _sync-job)
           (message "Bitwarden saved, but sync failed: %s"
                    (bitwarden-cli-error-message error-info))
           (run-hooks 'bitwarden-after-sync-hook)))))
    (bitwarden--dispatch-next)))

(defun bitwarden--process-sentinel (process _event)
  "Handle completion of a Bitwarden PROCESS."
  (when (memq (process-status process) '(exit signal failed))
    (let ((job (process-get process 'bitwarden-job)))
      (when (and job (eq job bitwarden--active-job))
        (bitwarden--finish-job job process)))))

(defun bitwarden--dispatch-next ()
  "Start the next queued Bitwarden job."
  (unless bitwarden--active-job
    (while (and bitwarden--queue
                (eq (bitwarden-job-state (car bitwarden--queue)) 'cancelled))
      (pop bitwarden--queue))
    (when bitwarden--queue
      (setq bitwarden--active-job (pop bitwarden--queue))
      (bitwarden--start-job bitwarden--active-job))))

(defun bitwarden--failed-request (argv kind message on-error)
  "Return a failed job for ARGV and invoke ON-ERROR asynchronously."
  (let* ((job (bitwarden--make-job
               :id (cl-incf bitwarden--job-counter)
               :argv argv
               :state 'failed))
         (error-info
          (bitwarden--make-cli-error
           :kind kind
           :message message
           :exit-code nil
           :command argv
           :stderr "")))
    (run-at-time 0 nil #'bitwarden--call-callback on-error error-info job)
    job))

(cl-defun bitwarden-request
    (argv &key input (parser 'json) (requires-session t)
          on-success on-error environment allow-interaction
          interactive-input prompt-handler prompt-regexp mutation)
  "Queue an asynchronous Bitwarden request.

ARGV is a list of individual command arguments; no shell is used.  INPUT is
written to stdin.  PARSER is `json', `string', `none', or a
function.  When REQUIRES-SESSION is non-nil, the request fails without an
in-memory session.  ON-SUCCESS receives (VALUE JOB), and ON-ERROR receives
(ERROR-INFO JOB).  ENVIRONMENT is an alist of scoped environment variables.
ALLOW-INTERACTION omits `--nointeraction'.  INTERACTIVE-INPUT is sent only
after PROMPT-REGEXP appears on a PTY.  PROMPT-HANDLER may return additional
responses for later prompts.  MUTATION marks vault-changing jobs.

The return value is a `bitwarden-job'."
  (unless (and (listp argv) (seq-every-p #'stringp argv))
    (signal 'wrong-type-argument (list 'list-of-strings-p argv)))
  (cond
   ((and requires-session (not (bitwarden-session-active-p)))
    (bitwarden--failed-request
     argv 'locked "Bitwarden vault is not unlocked" on-error))
   (t
    (let ((job
           (bitwarden--make-job
            :id (cl-incf bitwarden--job-counter)
            :argv argv
            :input input
            :parser parser
            :requires-session requires-session
            :on-success on-success
            :on-error on-error
            :environment environment
            :allow-interaction allow-interaction
            :interactive-input interactive-input
            :prompt-handler prompt-handler
            :prompt-regexp prompt-regexp
            :mutation mutation
            :state 'queued)))
      (setq bitwarden--queue (nconc bitwarden--queue (list job)))
      (bitwarden--dispatch-next)
      job))))

(defun bitwarden-cancel-job (job)
  "Cancel queued or running read JOB.
Mutations cannot be cancelled after they start."
  (interactive)
  (unless (bitwarden-job-p job)
    (user-error "Not a Bitwarden job"))
  (pcase (bitwarden-job-state job)
    ('queued
     (setq bitwarden--queue (delq job bitwarden--queue))
     (setf (bitwarden-job-state job) 'cancelled)
     (setf (bitwarden-job-input job) nil
           (bitwarden-job-environment job) nil
           (bitwarden-job-interactive-input job) nil)
     t)
    ('running
     (when (bitwarden-job-mutation job)
       (user-error "A running Bitwarden mutation cannot be cancelled"))
     (setf (bitwarden-job-state job) 'cancelled)
     (when (process-live-p (bitwarden-job-process job))
       (delete-process (bitwarden-job-process job)))
     t)
    (_ nil)))

(defun bitwarden--encode-payload (payload)
  "Return PAYLOAD as base64-encoded UTF-8 JSON."
  (let* ((json (if (stringp payload)
                   payload
                 (json-serialize payload
                                 :null-object nil
                                 :false-object :false)))
         (bytes (encode-coding-string json 'utf-8-unix))
         (encoded (base64-encode-string bytes t)))
    encoded))

(defun bitwarden--append-option (arguments flag value)
  "Append FLAG and VALUE to ARGUMENTS when VALUE is non-nil."
  (if (null value)
      arguments
    (append arguments (list flag (format "%s" value)))))

(defun bitwarden--mutation-request
    (argv &rest keywords)
  "Call `bitwarden-request' with ARGV, KEYWORDS, and mutation semantics."
  (apply #'bitwarden-request argv :mutation t keywords))

;;; Public asynchronous API

(cl-defun bitwarden-api-status (&key on-success on-error)
  "Return `bw status' asynchronously and update package state."
  (bitwarden-request
   '("status")
   :requires-session nil
   :on-success
   (lambda (data job)
     (bitwarden--set-status-from-data data)
     (bitwarden--call-callback on-success data job))
   :on-error on-error))

(cl-defun bitwarden-api-config-server
    (url &key web-vault api identity icons notifications events key-connector
         on-success on-error)
  "Configure the active CLI server URL and optional endpoint overrides."
  (let ((arguments (list "config" "server" url)))
    (dolist (entry `(("--web-vault" . ,web-vault)
                     ("--api" . ,api)
                     ("--identity" . ,identity)
                     ("--icons" . ,icons)
                     ("--notifications" . ,notifications)
                     ("--events" . ,events)
                     ("--key-connector" . ,key-connector)))
      (setq arguments
            (bitwarden--append-option arguments (car entry) (cdr entry))))
    (bitwarden-request
     arguments :parser 'string :requires-session nil
     :on-success on-success :on-error on-error)))

(cl-defun bitwarden-api-login
    (method &key email password two-step-method two-step-code
            client-id client-secret sso-identifier prompt-handler
            on-success on-error)
  "Log in using METHOD, one of `password', `api-key', or `sso'."
  (pcase method
    ('password
     (let ((arguments (list "login" email
                            "--passwordenv" "BITWARDEN_EL_PASSWORD"
                            "--raw")))
       (when two-step-method
         (setq arguments
               (append arguments
                       (list "--method" (format "%s" two-step-method)))))
       (bitwarden-request
        arguments
        :parser 'string
        :requires-session nil
        :environment `(("BITWARDEN_EL_PASSWORD" . ,password))
        :allow-interaction (not (null (or two-step-code prompt-handler)))
        :interactive-input two-step-code
        :prompt-handler prompt-handler
        :prompt-regexp
        (rx (or "Two-step login code"
                "New device verification required"))
        :on-success
        (lambda (session job)
          (bitwarden--set-session session)
          (bitwarden--call-callback on-success session job))
        :on-error on-error)))
    ('api-key
     (bitwarden-request
      '("login" "--apikey")
      :parser 'string
      :requires-session nil
      :environment `(("BW_CLIENTID" . ,client-id)
                     ("BW_CLIENTSECRET" . ,client-secret))
      :on-success
      (lambda (data job)
        (setq bitwarden--status 'locked)
        (run-hooks 'bitwarden-after-state-change-hook)
        (bitwarden--call-callback on-success data job))
      :on-error on-error))
    ('sso
     (let ((arguments
            (append '("login" "--sso")
                    (when (and sso-identifier
                               (not (string-empty-p sso-identifier)))
                      (list sso-identifier)))))
       (when two-step-method
         (setq arguments
               (append arguments
                       (list "--method" (format "%s" two-step-method)))))
       (bitwarden-request
      arguments
      :parser 'string
      :requires-session nil
      :allow-interaction t
      :interactive-input two-step-code
      :prompt-handler prompt-handler
      :prompt-regexp
      (rx (or "Two-step login code"
              "New device verification required"))
      :on-success
      (lambda (data job)
        (setq bitwarden--status 'locked)
        (run-hooks 'bitwarden-after-state-change-hook)
        (bitwarden--call-callback on-success data job))
      :on-error on-error)))
    (_ (user-error "Unknown Bitwarden login method: %S" method))))

(cl-defun bitwarden-api-unlock (password &key on-success on-error)
  "Unlock the vault with PASSWORD and retain the returned session in memory."
  (bitwarden-request
   '("unlock" "--passwordenv" "BITWARDEN_EL_MASTER_PASSWORD" "--raw")
   :parser 'string
   :requires-session nil
   :environment `(("BITWARDEN_EL_MASTER_PASSWORD" . ,password))
   :on-success
   (lambda (session job)
     (bitwarden--set-session session)
     (bitwarden--call-callback on-success session job))
   :on-error on-error))

(cl-defun bitwarden-api-lock (&key on-success on-error)
  "Lock the CLI vault and clear all local sensitive state."
  (bitwarden-request
   '("lock") :parser 'string :requires-session nil
   :on-success
   (lambda (data job)
     (bitwarden--clear-sensitive-state 'locked)
     (bitwarden--call-callback on-success data job))
   :on-error
   (lambda (error-info job)
     (bitwarden--clear-sensitive-state 'locked)
     (bitwarden--call-callback on-error error-info job))))

(cl-defun bitwarden-api-logout (&key on-success on-error)
  "Log out the CLI account and clear all local sensitive state."
  (bitwarden-request
   '("logout") :parser 'string :requires-session nil
   :on-success
   (lambda (data job)
     (setq bitwarden--status-data nil)
     (bitwarden--clear-sensitive-state 'unauthenticated)
     (bitwarden--call-callback on-success data job))
   :on-error
   (lambda (error-info job)
     (setq bitwarden--status-data nil)
     (bitwarden--clear-sensitive-state 'unauthenticated)
     (bitwarden--call-callback on-error error-info job))))

(cl-defun bitwarden-api-sync (&key force last on-success on-error)
  "Synchronize the vault, optionally FORCEing a full sync or returning LAST."
  (let ((arguments '("sync")))
    (when force (setq arguments (append arguments '("--force"))))
    (when last (setq arguments (append arguments '("--last"))))
    (bitwarden-request
     arguments :parser 'string
     :on-success on-success :on-error on-error)))

(cl-defun bitwarden-api-list
    (object &key search url folder-id collection-id organization-id trash
            archived on-success on-error)
  "List OBJECT using supported CLI filters."
  (let ((arguments (list "list" object)))
    (dolist (entry `(("--search" . ,search)
                     ("--url" . ,url)
                     ("--folderid" . ,folder-id)
                     ("--collectionid" . ,collection-id)
                     ("--organizationid" . ,organization-id)))
      (setq arguments
            (bitwarden--append-option arguments (car entry) (cdr entry))))
    (when trash (setq arguments (append arguments '("--trash"))))
    (when archived (setq arguments (append arguments '("--archived"))))
    (bitwarden-request
     arguments :on-success on-success :on-error on-error)))

(cl-defun bitwarden-api-get
    (object id &key item-id output organization-id raw on-success on-error)
  "Get OBJECT by ID, optionally downloading it to OUTPUT."
  (let ((arguments (list "get" object id)))
    (setq arguments (bitwarden--append-option arguments "--itemid" item-id))
    (setq arguments (bitwarden--append-option arguments "--output" output))
    (setq arguments
          (bitwarden--append-option arguments "--organizationid"
                                    organization-id))
    (when raw (setq arguments (append arguments '("--raw"))))
    (bitwarden-request
     arguments
     :parser (if (or raw output (string= object "attachment")
                     (member object '("username" "password" "uri" "totp"
                                      "notes" "exposed" "fingerprint")))
                 'string
               'json)
     :on-success on-success :on-error on-error)))

(cl-defun bitwarden-api-create
    (object payload &key file item-id organization-id on-success on-error)
  "Create OBJECT from PAYLOAD, or attach FILE to ITEM-ID."
  (let ((arguments (list "create" object))
        input)
    (setq arguments (bitwarden--append-option arguments "--file" file))
    (setq arguments (bitwarden--append-option arguments "--itemid" item-id))
    (setq arguments
          (bitwarden--append-option arguments "--organizationid"
                                    organization-id))
    (when payload (setq input (bitwarden--encode-payload payload)))
    (bitwarden--mutation-request
     arguments :input input :on-success on-success :on-error on-error)))

(cl-defun bitwarden-api-edit
    (object id payload &key organization-id on-success on-error)
  "Edit OBJECT identified by ID using complete JSON PAYLOAD."
  (let ((arguments (list "edit" object id)))
    (setq arguments
          (bitwarden--append-option arguments "--organizationid"
                                    organization-id))
    (bitwarden--mutation-request
     arguments
     :input (bitwarden--encode-payload payload)
     :on-success on-success :on-error on-error)))

(cl-defun bitwarden-api-delete
    (object id &key item-id organization-id permanent on-success on-error)
  "Delete OBJECT identified by ID."
  (let ((arguments (list "delete" object id)))
    (setq arguments (bitwarden--append-option arguments "--itemid" item-id))
    (setq arguments
          (bitwarden--append-option arguments "--organizationid"
                                    organization-id))
    (when permanent (setq arguments (append arguments '("--permanent"))))
    (bitwarden--mutation-request
     arguments :parser 'string
     :on-success on-success :on-error on-error)))

(cl-defun bitwarden-api-archive (id &key on-success on-error)
  "Archive the item identified by ID."
  (bitwarden--mutation-request
   (list "archive" "item" id) :parser 'json
   :on-success on-success :on-error on-error))

(cl-defun bitwarden-api-restore (id &key on-success on-error)
  "Restore the deleted or archived item identified by ID."
  (bitwarden--mutation-request
   (list "restore" "item" id) :parser 'json
   :on-success on-success :on-error on-error))

(cl-defun bitwarden-api-move
    (id organization-id collection-ids &key on-success on-error)
  "Move item ID to ORGANIZATION-ID and COLLECTION-IDS."
  (bitwarden--mutation-request
   (list "move" id organization-id)
   :input (bitwarden--encode-payload (vconcat collection-ids))
   :parser 'json :on-success on-success :on-error on-error))

(cl-defun bitwarden-api-attachment-create
    (item-id file &key on-success on-error)
  "Attach FILE to ITEM-ID."
  (bitwarden-api-create
   "attachment" nil :file file :item-id item-id
   :on-success on-success :on-error on-error))

(cl-defun bitwarden-api-attachment-get
    (item-id attachment-id output &key on-success on-error)
  "Download ATTACHMENT-ID belonging to ITEM-ID into OUTPUT."
  (bitwarden-api-get
   "attachment" attachment-id :item-id item-id :output output
   :on-success on-success :on-error on-error))

(cl-defun bitwarden-api-attachment-delete
    (item-id attachment-id &key on-success on-error)
  "Delete ATTACHMENT-ID belonging to ITEM-ID."
  (bitwarden-api-delete
   "attachment" attachment-id :item-id item-id
   :on-success on-success :on-error on-error))

(cl-defun bitwarden-api-send-list (&key on-success on-error)
  "List owned Bitwarden Sends."
  (bitwarden-request
   '("send" "list") :on-success on-success :on-error on-error))

(cl-defun bitwarden-api-send-get
    (id &key text output raw on-success on-error)
  "Get Send ID, optionally returning TEXT or downloading to OUTPUT."
  (let ((arguments (list "send" "get" id)))
    (when text (setq arguments (append arguments '("--text"))))
    (setq arguments (bitwarden--append-option arguments "--output" output))
    (when raw (setq arguments (append arguments '("--raw"))))
    (bitwarden-request
     arguments :parser (if (or text raw output) 'string 'json)
     :on-success on-success :on-error on-error)))

(cl-defun bitwarden-api-send-create
    (payload &key file hidden on-success on-error)
  "Create a Send from complete JSON PAYLOAD and optional FILE."
  (let ((arguments '("send" "create")))
    (setq arguments (bitwarden--append-option arguments "--file" file))
    (when hidden (setq arguments (append arguments '("--hidden"))))
    (bitwarden--mutation-request
     arguments :input (and payload (bitwarden--encode-payload payload))
     :on-success on-success :on-error on-error)))

(cl-defun bitwarden-api-send-edit
    (payload &key item-id on-success on-error)
  "Edit a Send using complete PAYLOAD."
  (let ((arguments '("send" "edit")))
    (setq arguments (bitwarden--append-option arguments "--itemid" item-id))
    (bitwarden--mutation-request
     arguments :input (bitwarden--encode-payload payload)
     :on-success on-success :on-error on-error)))

(cl-defun bitwarden-api-send-delete (id &key on-success on-error)
  "Delete owned Send ID."
  (bitwarden--mutation-request
   (list "send" "delete" id) :parser 'string
   :on-success on-success :on-error on-error))

(cl-defun bitwarden-api-send-remove-password (id &key on-success on-error)
  "Remove the access password from Send ID."
  (bitwarden--mutation-request
   (list "send" "remove-password" id) :parser 'string
   :on-success on-success :on-error on-error))

(cl-defun bitwarden-api-send-template (type &key on-success on-error)
  "Return Send template TYPE."
  (bitwarden-request
   (list "send" "template" type)
   :on-success on-success :on-error on-error))

(cl-defun bitwarden-api-generate
    (&key passphrase uppercase lowercase number special length words
          min-number min-special separator capitalize include-number ambiguous
          on-success on-error)
  "Generate a password or passphrase with the supplied options."
  (let ((arguments '("generate")))
    (when passphrase (setq arguments (append arguments '("--passphrase"))))
    (when uppercase (setq arguments (append arguments '("--uppercase"))))
    (when lowercase (setq arguments (append arguments '("--lowercase"))))
    (when number (setq arguments (append arguments '("--number"))))
    (when special (setq arguments (append arguments '("--special"))))
    (when capitalize (setq arguments (append arguments '("--capitalize"))))
    (when include-number
      (setq arguments (append arguments '("--includeNumber"))))
    (when ambiguous (setq arguments (append arguments '("--ambiguous"))))
    (dolist (entry `(("--length" . ,length)
                     ("--words" . ,words)
                     ("--minNumber" . ,min-number)
                     ("--minSpecial" . ,min-special)
                     ("--separator" . ,separator)))
      (setq arguments
            (bitwarden--append-option arguments (car entry) (cdr entry))))
    (bitwarden-request
     arguments :parser 'string :requires-session nil
     :on-success on-success :on-error on-error)))

(cl-defun bitwarden-api-import-formats (&key on-success on-error)
  "Return import formats supported by the installed CLI."
  (bitwarden-request
   '("import" "--formats" "--raw") :parser 'string
   :on-success on-success :on-error on-error))

(cl-defun bitwarden-api-import
    (format input &key organization-id keyfile password on-success on-error)
  "Import INPUT using FORMAT and optional decryption PASSWORD."
  (let ((arguments (list "import" format input))
        environment)
    (setq arguments
          (bitwarden--append-option arguments "--organizationid"
                                    organization-id))
    (setq arguments (bitwarden--append-option arguments "--keyfile" keyfile))
    (when password
      (setq arguments
            (append arguments
                    '("--passwordenv" "BITWARDEN_EL_IMPORT_PASSWORD")))
      (setq environment
            `(("BITWARDEN_EL_IMPORT_PASSWORD" . ,password))))
    (bitwarden--mutation-request
     arguments :parser 'string :environment environment
     :on-success on-success :on-error on-error)))

(cl-defun bitwarden-api-export
    (format output &key organization-id password on-success on-error)
  "Export vault data in FORMAT to OUTPUT.
When PASSWORD is non-nil, encrypted JSON uses the CLI's hidden PTY prompt."
  (let ((arguments (list "export" "--format" format "--output" output)))
    (setq arguments
          (bitwarden--append-option arguments "--organizationid"
                                    organization-id))
    (when password
      (setq arguments (append arguments '("--password"))))
    (bitwarden-request
     arguments :parser 'string
     :allow-interaction (not (null password))
     :interactive-input password
     :prompt-regexp (rx "Export file password:")
     :on-success on-success :on-error on-error)))

(defun bitwarden-copy-value (value)
  "Copy VALUE according to `bitwarden-copy-policy'."
  (pcase bitwarden-copy-policy
    ('system-clipboard
     (gui-set-selection 'CLIPBOARD value)
     (message "Copied to the system clipboard"))
    (_
     (kill-new value)
     (message "Copied to the kill ring"))))

(defun bitwarden--shutdown-lock ()
  "Best-effort synchronous CLI lock used from `kill-emacs-hook'."
  (when (bitwarden-session-active-p)
    (when-let* ((executable (executable-find bitwarden-executable)))
      (ignore-errors
        (call-process executable nil nil nil "--nointeraction" "lock")))))

(add-hook 'kill-emacs-hook #'bitwarden--shutdown-lock)

(provide 'bitwarden-core)

;;; bitwarden-core.el ends here
