;;; mcp-http.el --- Streamable HTTP transport for MCP -*- lexical-binding: t; -*-

;; Copyright (C) 2026 cat-emacs
;; SPDX-License-Identifier: GPL-3.0-or-later

;;; Code:

(require 'json)
(require 'mcp)
(require 'mcp-oauth)
(require 'url)

(defvar url-http-end-of-headers)
(defvar url-max-redirections)

(defun mcp-http--url (connection)
  "Return the Streamable HTTP endpoint for CONNECTION."
  (format "%s://%s:%s%s" (if (mcp--tls connection) "https" "http")
          (mcp--host connection) (mcp--port connection)
          (or (mcp--endpoint connection) (mcp--path connection))))

(defun mcp-http--deliver (connection message)
  "Deliver MESSAGE only while CONNECTION remains running."
  (when (jsonrpc-running-p connection)
    (jsonrpc-connection-receive connection message)))

(defun mcp-http--body-json (connection content-type body)
  "Deliver each JSON or SSE event in BODY for CONNECTION."
  (when (jsonrpc-running-p connection)
    (let ((events (if (string-match-p "\\`text/event-stream" (or content-type ""))
                      (mapcar (lambda (event)
                                (mapconcat (lambda (line)
                                             (when (string-prefix-p "data:" line)
                                               (string-trim (substring line 5))))
                                           (delq nil (split-string event "\n")) "\n"))
                              (split-string (replace-regexp-in-string "\r" "" body) "\n\n"))
                    (list body))))
      (dolist (data events)
        (when (and (stringp data) (not (string-empty-p (string-trim data))))
          (condition-case err
              (mcp-http--deliver connection
                                 (json-parse-string data :object-type 'plist
                                                    :null-object nil :false-object :json-false))
            (json-parse-error (jsonrpc--warn "Invalid Streamable HTTP JSON: %s" (cdr err)))))))))

(defun mcp-http--http-error (connection id status body)
  "Deliver safe HTTP STATUS error for request ID on CONNECTION.
Notifications have no response channel and are only logged."
  (if id
      (mcp-http--deliver connection
                         `(:jsonrpc "2.0" :id ,id :error (:code -32000
                           :message ,(format "MCP HTTP request failed: %s" status)
                           :data ,(truncate-string-to-width (mcp-oauth--redact body) 512))))
    (jsonrpc--warn "MCP HTTP notification failed: %s" status)))

(defun mcp-http--header-end ()
  "Return the body start in the current Emacs URL response buffer."
  (or (and (boundp 'url-http-end-of-headers)
           (integer-or-marker-p url-http-end-of-headers)
           url-http-end-of-headers)
      (save-excursion
        (goto-char (point-min))
        (or (re-search-forward "\r?\n\r?\n" nil t)
            (search-forward "\n\n" nil t)))))

(defun mcp-http--post (connection json id retried)
  "POST JSON request ID for CONNECTION, retrying one OAuth 401 only."
  (when (jsonrpc-running-p connection)
    (let* ((request-session (mcp--session-id connection))
           (initialize-request
            (condition-case nil
                (equal "initialize" (plist-get (json-parse-string json :object-type 'plist) :method))
              (error nil)))
          (url-request-method "POST")
          (url-request-extra-headers
           (append '(("Content-Type" . "application/json")
                     ("Accept" . "application/json, text/event-stream"))
                   (when-let* ((version (mcp--protocol-version connection)))
                     `(("MCP-Protocol-Version" . ,version)))
                   (when request-session
                     `(("Mcp-Session-Id" . ,request-session)))
                   (when-let* ((token (or (and (mcp--oauth connection)
                                                (mcp-oauth-token (mcp--oauth connection)))
                                           (mcp--resolve-value (mcp--token connection)))))
                     `(("Authorization" . ,(concat "Bearer " token))))
                   (mcp--headers connection)))
          (url-request-data (encode-coding-string json 'utf-8))
          ;; Never forward static or OAuth bearer credentials to redirects.
          (url-max-redirections 0))
      (url-retrieve (mcp-http--url connection)
                    (lambda (_status)
                      (unwind-protect
                          (when (and (jsonrpc-running-p connection)
                                     (buffer-live-p (current-buffer)))
                            (let ((header-end (mcp-http--header-end)))
                              (if (not header-end)
                                  (mcp-http--http-error connection id "malformed response" "")
                                (goto-char header-end)
                                (let* ((headers (buffer-substring-no-properties
                                                 (point-min) header-end))
                                       (body (buffer-substring-no-properties
                                              header-end (point-max)))
                                     (parsed (mcp--parse-http-header headers))
                                     (code (string-to-number (or (plist-get parsed :response-code) "0"))))
                                ;; Session IDs are received only with a successful
                                ;; initialization response and contain visible ASCII.
                                (when (and (<= 200 code 299) initialize-request)
                                  (when-let* ((session (plist-get parsed :mcp-session-id)))
                                    (when (string-match-p "\\`[!-~]+\\'" session)
                                      (setf (mcp--session-id connection) session))))
                                (cond
                                 ((and (= code 401) (mcp--oauth connection) (not retried))
                                  (mcp-oauth-invalidate-access-token (mcp--oauth connection))
                                  (when (mcp-oauth-provider-p (mcp--oauth connection))
                                    (mcp-oauth-reset-discovery (mcp--oauth connection)))
                                  (mcp-oauth-ensure-token
                                   (mcp--oauth connection)
                                   (lambda (_token) (mcp-http--post connection json id t))
                                   (lambda (_message) (mcp-http--http-error connection id "authorization" ""))))
                                 ((and (= code 404) request-session
                                       (equal request-session (mcp--session-id connection)))
                                  ;; A request cannot safely be replayed after session expiry.
                                  ;; Ignore stale delayed failures for an older session.
                                  (setf (mcp--session-id connection) nil)
                                  (mcp-http--http-error connection id "session expired" "")
                                  (unless (mcp--session-reinitializing connection)
                                    (setf (mcp--session-reinitializing connection) t)
                                    (mcp--send-initial-message connection)))
                                 ((<= 200 code 299)
                                  (mcp-http--body-json connection (plist-get parsed :content-type) body))
                                 (t (mcp-http--http-error connection id code body)))))))
                        (when (buffer-live-p (current-buffer)) (kill-buffer))))))))

(cl-defmethod jsonrpc-connection-send ((connection mcp-http-process-connection)
                                       &rest args &key id method _params
                                       (_result nil result-supplied-p) error _partial)
  "Send Streamable HTTP messages, delegating legacy SSE to the base transport."
  (if (not (or (mcp--oauth connection) (eq (mcp--transport connection) 'streamable)))
      (cl-call-next-method)
    (when method
      (setq args (plist-put args :method
                            (cond ((keywordp method) (substring (symbol-name method) 1))
                                  ((symbolp method) (symbol-name method))
                                  ((stringp method) method)
                                  (t (error "[jsonrpc] invalid method %s" method))))))
    (let* ((kind (cond ((or result-supplied-p error) 'reply) (id 'request) (method 'notification)))
           (converted (jsonrpc-convert-to-endpoint connection args kind))
           (json (json-serialize converted :false-object :json-false :null-object :json-null))
           (request-id (plist-get converted :id)))
      (if-let* ((oauth (mcp--oauth connection)))
          (mcp-oauth-ensure-token oauth
                                  (lambda (_token) (mcp-http--post connection json request-id nil))
                                  (lambda (_message) (mcp-http--http-error connection request-id "authorization" "")))
        (mcp-http--post connection json request-id nil))
      (jsonrpc--event connection 'client :json json :kind kind :message args :foreign-message converted))))

(provide 'mcp-http)
;;; mcp-http.el ends here
