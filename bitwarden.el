;;; bitwarden.el --- Full Bitwarden CLI client for Emacs -*- lexical-binding: t; -*-

;; Version: 0.1.0
;; Package-Requires: ((emacs "31.1") (magit-section "4.7.1"))
;; Keywords: tools, password, bitwarden
;; URL: https://github.com/roife/bitwarden.el
;;; Commentary:

;; bitwarden.el turns the official `bw' command-line client into an
;; asynchronous, multi-buffer Emacs password-vault interface.
;;
;; Install the Bitwarden CLI, ensure `bitwarden-executable' points at it, then
;; run `M-x bitwarden'.  Login, unlock, sync, CRUD, Sends, attachments,
;; generation, import, and export are available without starting a shell.

;;; Code:

(require 'bitwarden-core)
(require 'bitwarden-ui)

;;;###autoload
(defun bitwarden ()
  "Open the Bitwarden navigator, logging in or unlocking when necessary."
  (interactive)
  (bitwarden-ui-open))

(provide 'bitwarden)

;;; bitwarden.el ends here
