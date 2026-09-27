;;; mcp-oauth.el --- OAuth support for MCP clients -*- lexical-binding: t; -*-

;; Copyright (C) 2026 cat-emacs
;; SPDX-License-Identifier: GPL-3.0-or-later

;;; Commentary:
;; Provider-neutral OAuth 2.1 authorization-code S256 PKCE support for remote MCP.
;; RFC 8628 device authorization remains an explicit compatibility extension.

;;; Code:

(require 'cl-lib)
(require 'json)
(require 'rx)
(require 'seq)
(require 'subr-x)
(require 'url)
(require 'url-http)
(require 'url-util)

(defvar url-http-end-of-headers)
(defvar url-max-redirections)
(defvar url-http-response-status)

(defgroup mcp-oauth nil
  "OAuth support for MCP clients."
  :group 'mcp)

(defcustom mcp-oauth-storage-directory
  (locate-user-emacs-file "mcp-oauth/")
  "Directory containing per-resource OAuth state files."
  :type 'directory)

(defcustom mcp-oauth-expiry-skew 60
  "Seconds before expiry at which an access token is refreshed."
  :type 'integer)

(cl-defstruct (mcp-oauth-provider
               (:constructor mcp-oauth-provider-create))
  resource config metadata authorization-server client state poll-timer waiters
  authorization-process authorization-timer authorization-clients
  (authorization-generation 0))

(defun mcp-oauth--config (provider key)
  "Return KEY from PROVIDER configuration."
  (plist-get (mcp-oauth-provider-config provider) key))

(defun mcp-oauth--allow-http-p (provider)
  "Return whether PROVIDER explicitly permits insecure HTTP."
  (mcp-oauth--config provider :allow-http))

(defun mcp-oauth--https-url-p (provider url)
  "Return non-nil when URL is an allowed absolute HTTP URL."
  (let ((parsed (url-generic-parse-url url)))
    (and (url-host parsed)
         (or (string= (url-type parsed) "https")
             (and (mcp-oauth--allow-http-p provider)
                  (string= (url-type parsed) "http"))))))

(defun mcp-oauth--require-url (provider url label)
  "Validate PROVIDER URL labelled LABEL and return it."
  (unless (and (stringp url) (mcp-oauth--https-url-p provider url))
    (error "%s must be an absolute HTTPS URL" label))
  url)

(defun mcp-oauth--resource-uri (provider url)
  "Return canonical RFC 8707 resource URI for PROVIDER URL.
The path and query are preserved because they can identify distinct resources.
Fragments are not valid RFC 8707 resource indicators."
  (mcp-oauth--require-url provider url "OAuth resource")
  (let* ((parsed (url-generic-parse-url url))
         (scheme (downcase (url-type parsed)))
         (host (downcase (url-host parsed)))
         (port (url-port parsed))
         (path (or (url-filename parsed) "/"))
         (fragment (url-target parsed)))
    (when fragment
      (error "OAuth resource URI must not contain a fragment"))
    (format "%s://%s%s%s"
            scheme host
            (if (and port
                     (not (or (and (string= scheme "https") (= port 443))
                              (and (string= scheme "http") (= port 80)))))
                (format ":%d" port)
              "")
            (if (string-empty-p path) "/" path))))

(defun mcp-oauth--safe-id (string)
  "Return a stable file-safe identifier for STRING."
  (secure-hash 'sha256 string))

(defun mcp-oauth--state-file (provider)
  "Return PROVIDER state file path."
  (expand-file-name
   (concat (mcp-oauth--safe-id (mcp-oauth-provider-resource provider)) ".json")
   (or (mcp-oauth--config provider :storage-directory)
       mcp-oauth-storage-directory)))

(defun mcp-oauth--json (string label)
  "Parse STRING as JSON for LABEL, or signal a safe error."
  (condition-case err
      (json-parse-string string :object-type 'plist :array-type 'array
                         :null-object nil :false-object :json-false)
    (json-parse-error
     (error "Invalid OAuth JSON from %s: %s" label (error-message-string err)))))

(defun mcp-oauth--redact (value)
  "Redact OAuth secrets in VALUE for safe diagnostics."
  (let ((text (format "%s" value))
        (key "\\(?:access_token\\|refresh_token\\|client_secret\\|device_code\\|code\\)"))
    (setq text (replace-regexp-in-string
                (concat "\\([\"']?" key "[\"']?\\)[[:space:]]*[:=][[:space:]]*\\(?:[\"'][^\"']*[\"']\\|[^,[:space:]}]+\\)")
                "\\1=[REDACTED]" text t))
    (replace-regexp-in-string
     "\\(Authorization:[[:space:]]*Bearer[[:space:]]+\\)[^[:space:],]+"
     "\\1[REDACTED]" text t)))

(defun mcp-oauth--bearer-response-p ()
  "Return non-nil when the current HTTP response has a Bearer challenge."
  (let ((case-fold-search t))
    (cl-some
     (lambda (header)
       (string-match-p
        (rx (or string-start ",") (* blank) "Bearer" (or blank string-end))
        header))
     (mcp-oauth--headers
      (buffer-substring-no-properties
       (point-min)
       (or (and (boundp 'url-http-end-of-headers)
                (integer-or-marker-p url-http-end-of-headers)
                url-http-end-of-headers)
           (point-max)))
      "WWW-Authenticate"))))

(defun mcp-oauth--http (provider method url headers data)
  "Issue synchronous OAuth HTTP request and return (STATUS HEADERS BODY).
This narrow seam is intentionally easy to mock in ERT tests."
  (mcp-oauth--require-url provider url "OAuth endpoint")
  (let* ((url-request-method method)
         (url-request-extra-headers headers)
         (url-request-data data)
         ;; OAuth endpoints must never redirect credentials or device codes.
         (url-max-redirections 0)
         (original-auth-handler
          (symbol-function 'url-http-handle-authentication))
         (buffer
          (cl-letf (((symbol-function 'url-http-handle-authentication)
                     (lambda (proxy)
                       ;; Emacs treats every 401 as Basic/Digest authentication.
                       ;; Preserve Bearer challenges for OAuth discovery instead.
                       (if (and (not proxy) (mcp-oauth--bearer-response-p))
                           t
                         (funcall original-auth-handler proxy)))))
            (url-retrieve-synchronously url t t 30))))
    (unless buffer (error "OAuth request timed out"))
    (unwind-protect
        (with-current-buffer buffer
          (let ((status url-http-response-status)
                (end url-http-end-of-headers))
            (unless (and (integerp status) end) (error "Invalid OAuth HTTP response"))
            (list status
                  (buffer-substring-no-properties (point-min) end)
                  (buffer-substring-no-properties end (point-max)))))
      (kill-buffer buffer))))

(defun mcp-oauth--form (pairs)
  "Encode PAIRS as application/x-www-form-urlencoded data."
  (mapconcat (lambda (pair)
               (concat (url-hexify-string (car pair)) "="
                       (url-hexify-string (format "%s" (cdr pair)))))
             (cl-remove-if (lambda (pair) (null (cdr pair))) pairs) "&"))

(defun mcp-oauth--request-json (provider method url headers data label)
  "Request successful JSON from URL or signal a generic safe error."
  (pcase-let ((`(,status ,_headers ,body)
               (mcp-oauth--http provider method url headers data)))
    (unless (<= 200 status 299)
      (if (<= 300 status 399)
          (error "OAuth %s failed: redirect refused" label)
        (error "OAuth %s failed (%d)" label status)))
    (mcp-oauth--json body label)))

;;;###autoload
(defun mcp-oauth-create (resource &optional config)
  "Create an OAuth provider for MCP RESOURCE using CONFIG plist.
CONFIG accepts :client-name, :scopes, :metadata-url, :authorization-server,
:static-client, :storage-directory, :allow-http, :open-browser, :redirect-uri
and :grant-type.  Authorization-code S256 PKCE is default; :grant-type
`device-code' opts into the RFC 8628 extension."
  (let ((provider (mcp-oauth-provider-create
                   :resource nil :config config)))
    (setf (mcp-oauth-provider-resource provider)
          (mcp-oauth--resource-uri provider resource))
    provider))

(defun mcp-oauth--directory-safe-p (directory)
  "Return non-nil when DIRECTORY is safe for OAuth credentials."
  (and (not (file-symlink-p directory))
       (file-directory-p directory)
       (or (eq system-type 'windows-nt)
           (let ((modes (file-modes directory)))
             (and modes (= 0 (logand #o077 modes)))))))

(defun mcp-oauth--ensure-directory (directory)
  "Create DIRECTORY privately, never chmodding a pre-existing directory."
  (if (file-exists-p directory)
      (unless (mcp-oauth--directory-safe-p directory)
        (error "OAuth state directory is unsafe"))
    (make-directory directory t)
    (unless (eq system-type 'windows-nt) (set-file-modes directory #o700))
    (unless (mcp-oauth--directory-safe-p directory)
      (error "OAuth state directory is unsafe"))))

(defun mcp-oauth--state-file-safe-p (file)
  "Return non-nil when FILE passes portable OAuth state safety checks.
Native Windows does not expose meaningful POSIX mode bits, so retain the
regular-file and symlink checks there without rejecting its synthetic modes."
  (and (not (file-symlink-p file))
       (file-regular-p file)
       (or (eq system-type 'windows-nt)
           (let ((modes (file-modes file)))
             (and modes (= 0 (logand #o077 modes)))))))

(defun mcp-oauth--load-state (provider)
  "Load and validate persisted OAuth state for PROVIDER."
  (let* ((file (mcp-oauth--state-file provider))
         (directory (file-name-directory file)))
    (mcp-oauth--ensure-directory directory)
    (when (file-exists-p file)
      (unless (mcp-oauth--state-file-safe-p file)
        (error "OAuth state file is unsafe"))
      (let ((state (with-temp-buffer
                     (insert-file-contents file)
                     (mcp-oauth--json (buffer-string) "OAuth state"))))
        (unless (equal (plist-get state :resource)
                       (mcp-oauth-provider-resource provider))
          (error "OAuth state resource does not match this MCP server"))
        (setf (mcp-oauth-provider-state provider) state)
        state))))

(defun mcp-oauth--save-state (provider state)
  "Atomically persist PROVIDER STATE with private permissions."
  (let* ((file (mcp-oauth--state-file provider))
         (directory (file-name-directory file)))
    (mcp-oauth--ensure-directory directory)
    (let ((temporary
           (make-temp-file (expand-file-name ".mcp-oauth-" directory))))
      (unwind-protect
          (progn
            (with-temp-file temporary
              (insert (json-serialize state :false-object :json-false)))
            (set-file-modes temporary #o600)
            (rename-file temporary file t)
            (set-file-modes file #o600)
            (setf (mcp-oauth-provider-state provider) state))
        (when (file-exists-p temporary) (delete-file temporary))))))

(defun mcp-oauth--delete-state (provider)
  "Delete persisted credentials for PROVIDER."
  (let ((file (mcp-oauth--state-file provider)))
    (when (file-exists-p file) (delete-file file)))
  (setf (mcp-oauth-provider-state provider) nil))

(defun mcp-oauth--headers (headers name)
  "Return all case-insensitive NAME values from raw HTTP HEADERS."
  (let ((needle (downcase name)) values)
    (dolist (line (split-string headers "[\r\n]+" t))
      (when-let* ((colon (string-match ":" line))
                  (field (downcase (string-trim (substring line 0 colon))))
                  ((string= field needle)))
        (push (string-trim (substring line (1+ colon))) values)))
    (nreverse values)))

(defun mcp-oauth--header (headers name)
  "Return the first case-insensitive NAME from raw HTTP HEADERS."
  (car (mcp-oauth--headers headers name)))

(defun mcp-oauth--bearer-resource-metadata (headers)
  "Return a quoted Bearer resource_metadata URL from HEADERS, or nil."
  (cl-loop for value in (mcp-oauth--headers headers "WWW-Authenticate")
           thereis
           (let ((case-fold-search t))
             (when (string-match "\\(?:\\`\\|,[[:space:]]*\\)Bearer[[:space:]]+" value)
               (let ((challenge (substring value (match-end 0))))
                 (when (string-match "resource_metadata[[:space:]]*=[[:space:]]*\\\"\\([^\\\"]+\\)\\\"" challenge)
                   (match-string 1 challenge)))))))

(defun mcp-oauth--metadata-url (provider)
  "Return RFC 9728 protected-resource metadata URL for PROVIDER."
  (or (mcp-oauth--config provider :metadata-url)
      (let* ((resource (url-generic-parse-url
                        (mcp-oauth-provider-resource provider)))
             (path (car (split-string (or (url-filename resource) "/") "?"))))
        (format "%s://%s%s/.well-known/oauth-protected-resource%s"
                (url-type resource)
                (url-host resource)
                (let* ((scheme (url-type resource))
                       (port (url-port resource)))
                  (if (or (null port)
                          (and (string= scheme "https") (= port 443))
                          (and (string= scheme "http") (= port 80)))
                      ""
                    (format ":%d" port)))
                (if (string= path "/") "" path)))))

(defconst mcp-oauth--metadata-probe-body
  "{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{},\"clientInfo\":{\"name\":\"Emacs MCP\",\"version\":\"0\"}}}"
  "Minimal unauthenticated MCP request used only for OAuth challenges.")

(defun mcp-oauth--valid-resource-metadata-p (provider metadata)
  "Return non-nil when METADATA identifies PROVIDER and an authorization server."
  (and (listp metadata)
       (stringp (plist-get metadata :resource))
       (let ((servers (plist-get metadata :authorization_servers)))
         (and (sequencep servers) (> (length servers) 0)))
       (condition-case nil
           (equal (mcp-oauth--resource-uri provider (plist-get metadata :resource))
                  (mcp-oauth-provider-resource provider))
         (error nil))))

(defun mcp-oauth--challenge-metadata-url (provider)
  "Probe PROVIDER resource once and return its 401 Bearer metadata URL."
  (pcase-let ((`(,status ,headers ,_body)
               (mcp-oauth--http provider "POST" (mcp-oauth-provider-resource provider)
                                '(("Content-Type" . "application/json")
                                  ("Accept" . "application/json, text/event-stream"))
                                mcp-oauth--metadata-probe-body)))
    (unless (= status 401)
      (error "OAuth protected resource metadata discovery failed: no Bearer challenge"))
    (let ((url (mcp-oauth--bearer-resource-metadata headers)))
      (unless url
        (error "OAuth protected resource metadata discovery failed: invalid Bearer challenge"))
      (mcp-oauth--require-url provider url "Bearer resource_metadata")
      url)))

(defun mcp-oauth--protected-resource-metadata (provider)
  "Fetch verified RFC 9728 metadata for PROVIDER, using one 401 challenge fallback."
  (let ((configured (mcp-oauth--config provider :metadata-url)))
    (if configured
        (let ((metadata (mcp-oauth--request-json provider "GET" configured nil nil
                                                  "protected resource metadata")))
          (unless (mcp-oauth--valid-resource-metadata-p provider metadata)
            (error "OAuth protected resource metadata is invalid"))
          metadata)
      (let ((derived (mcp-oauth--metadata-url provider)))
        (condition-case nil
            (let ((metadata (mcp-oauth--request-json provider "GET" derived nil nil
                                                     "protected resource metadata")))
              (if (mcp-oauth--valid-resource-metadata-p provider metadata)
                  metadata
                (error "invalid metadata")))
          (error
           (let ((metadata (mcp-oauth--request-json provider "GET"
                                                     (mcp-oauth--challenge-metadata-url provider)
                                                     nil nil "protected resource metadata")))
             (unless (mcp-oauth--valid-resource-metadata-p provider metadata)
               (error "OAuth protected resource metadata is invalid"))
             metadata)))))))

(defun mcp-oauth--authorization-server-metadata-url (provider issuer)
  "Return RFC 8414 metadata URL for PROVIDER authorization ISSUER."
  (mcp-oauth--require-url provider issuer "Authorization server")
  (let* ((parsed (url-generic-parse-url issuer))
         (port (url-port parsed))
         (path (or (url-filename parsed) "")))
    (when (string-match-p "[?#]" path)
      (error "Authorization server issuer must not contain query or fragment"))
    (format "%s://%s%s/.well-known/oauth-authorization-server%s"
            (url-type parsed) (url-host parsed)
            (if (and port (not (= port 443))) (format ":%d" port) "")
            (if (string-empty-p path) "" (concat "/" (string-remove-prefix "/" path))))))

(defun mcp-oauth--public-client-p (client)
  "Return non-nil when CLIENT uses no token endpoint authentication."
  (member (plist-get client :token_endpoint_auth_method) '(nil "none")))

(defun mcp-oauth--validate-public-client (client label)
  "Reject non-public CLIENT credentials at LABEL."
  (unless (mcp-oauth--public-client-p client)
    (error "%s must use token_endpoint_auth_method none" label))
  client)

(defun mcp-oauth-discover (provider)
  "Discover protected-resource and authorization-server metadata for PROVIDER."
  (let* ((resource-metadata (mcp-oauth--protected-resource-metadata provider))
         (configured-issuer (mcp-oauth--config provider :authorization-server))
         (declared-issuers (plist-get resource-metadata :authorization_servers))
         (issuer (or configured-issuer (seq-first declared-issuers))))
    (when (and configured-issuer declared-issuers
               (not (seq-contains-p declared-issuers configured-issuer #'equal)))
      (error "Configured authorization server is not declared by the resource"))
    (mcp-oauth--require-url provider issuer "Authorization server")
    (let* ((metadata-url (mcp-oauth--authorization-server-metadata-url provider issuer))
           (server-metadata
            (mcp-oauth--request-json provider "GET" metadata-url nil nil
                                     "authorization server metadata"))
           (declared-issuer (plist-get server-metadata :issuer)))
      (unless (and (stringp declared-issuer) (equal declared-issuer issuer))
        (error "Authorization server metadata issuer does not match discovery"))
      (mcp-oauth--require-url provider (plist-get server-metadata :token_endpoint)
                              "token_endpoint")
      (when-let* ((declared-resource (plist-get resource-metadata :resource)))
        (unless (equal (mcp-oauth--resource-uri provider declared-resource)
                       (mcp-oauth-provider-resource provider))
          (error "Protected resource metadata does not match this MCP server")))
      (when (and (mcp-oauth-provider-authorization-server provider)
                 (not (equal (mcp-oauth-provider-authorization-server provider) issuer)))
        (setf (mcp-oauth-provider-client provider) nil))
      (setf (mcp-oauth-provider-authorization-server provider) issuer
            (mcp-oauth-provider-metadata provider) server-metadata)
      (when-let* ((state (or (mcp-oauth-provider-state provider)
                             (mcp-oauth--load-state provider))))
        (unless (equal (plist-get state :issuer) issuer)
          (setf (mcp-oauth-provider-client provider) nil)
          (mcp-oauth--delete-state provider)
          (error "OAuth state issuer does not match discovered issuer")))
      server-metadata)))

(defun mcp-oauth--client (provider)
  "Return PROVIDER's registered or static client information."
  (or (mcp-oauth-provider-client provider)
      (let* ((state (or (mcp-oauth-provider-state provider)
                        (mcp-oauth--load-state provider)))
             (client (or (mcp-oauth--config provider :static-client)
                         (plist-get state :client))))
        (when client
          (mcp-oauth--validate-public-client client "OAuth client")
          (unless (or (mcp-oauth--config provider :static-client)
                      (mcp-oauth--client-compatible-p provider client))
            (setq client nil)))
        (setf (mcp-oauth-provider-client provider) client)
        client)))

(defun mcp-oauth--public-client-state (client)
  "Return reusable public registration fields from CLIENT."
  (append (list :client_id (plist-get client :client_id)
                :token_endpoint_auth_method "none")
          (when-let* ((grants (plist-get client :grant_types)))
            (list :grant_types grants))
          (when-let* ((redirects (plist-get client :redirect_uris)))
            (list :redirect_uris redirects))))

(defun mcp-oauth--grant-type (provider)
  "Return PROVIDER's supported configured authorization grant type."
  (let ((grant (or (mcp-oauth--config provider :grant-type) 'authorization-code)))
    (unless (memq grant '(authorization-code device-code))
      (error "Unsupported OAuth grant type"))
    grant))

(defun mcp-oauth--client-compatible-p (provider client)
  "Return non-nil if CLIENT can serve PROVIDER's selected grant configuration."
  (if (eq (mcp-oauth--grant-type provider) 'device-code)
      (seq-contains-p (plist-get client :grant_types)
                      "urn:ietf:params:oauth:grant-type:device_code" #'string=)
    (and (seq-contains-p (plist-get client :grant_types) "authorization_code" #'string=)
         (seq-contains-p (plist-get client :redirect_uris)
                         (mcp-oauth--redirect-uri provider) #'string=))))

(defun mcp-oauth--register (provider)
  "Dynamically register PROVIDER and persist its client information."
  (let* ((metadata (or (mcp-oauth-provider-metadata provider)
                       (mcp-oauth-discover provider)))
         (endpoint (plist-get metadata :registration_endpoint)))
    (mcp-oauth--require-url provider endpoint "Dynamic registration endpoint")
    (let ((client (mcp-oauth--request-json
                   provider "POST" endpoint
                   '(("Content-Type" . "application/json"))
                   (json-serialize
                    (if (eq (mcp-oauth--grant-type provider) 'device-code)
                        `(:client_name ,(or (mcp-oauth--config provider :client-name)
                                             "Emacs MCP client")
                          :grant_types ["urn:ietf:params:oauth:grant-type:device_code"
                                        "refresh_token"]
                          :token_endpoint_auth_method "none")
                      `(:client_name ,(or (mcp-oauth--config provider :client-name)
                                           "Emacs MCP client")
                        :redirect_uris [,(mcp-oauth--redirect-uri provider)]
                        :response_types ["code"]
                        :grant_types ["authorization_code" "refresh_token"]
                        :token_endpoint_auth_method "none"))
                    :false-object :json-false)
                   "dynamic registration")))
      (mcp-oauth--validate-public-client client "Dynamic registration response")
      (setq client (mcp-oauth--public-client-state client))
      (setf (mcp-oauth-provider-client provider) client)
      (mcp-oauth--save-state
       provider (list :resource (mcp-oauth-provider-resource provider)
                      :issuer (mcp-oauth-provider-authorization-server provider)
                      :client client))
      client)))

(defun mcp-oauth--ensure-client (provider)
  "Return a static, stored, or dynamically registered client for PROVIDER."
  (or (mcp-oauth--client provider)
      (mcp-oauth--register provider)))

(defun mcp-oauth--positive-number (value label)
  "Return finite positive numeric VALUE for LABEL, accepting decimal strings."
  (cond ((and (numberp value) (> value 0)
              (or (not (floatp value))
                  (and (not (isnan value)) (not (equal value 1.0e+INF))))) value)
        ((and (stringp value) (string-match-p "\\`[0-9]+\\(?:\\.[0-9]+\\)?\\'" value))
         (mcp-oauth--positive-number (string-to-number value) label))
        (t (error "%s must be a positive number" label))))

(defun mcp-oauth--scope (provider)
  "Return normalized configured OAuth scope for PROVIDER."
  (let ((scopes (mcp-oauth--config provider :scopes)))
    (cond ((null scopes) "")
          ((stringp scopes) scopes)
          ((and (sequencep scopes) (seq-every-p #'stringp scopes))
           (string-join scopes " "))
          (t (error "OAuth scopes must be a string or list of strings")))))

(defun mcp-oauth--merge-state (provider tokens)
  "Merge TOKENS into PROVIDER state and persist them."
  (let* ((old (or (mcp-oauth-provider-state provider)
                  (mcp-oauth--load-state provider)
                  nil))
         (expires-in (and (plist-member tokens :expires_in)
                          (mcp-oauth--positive-number (plist-get tokens :expires_in) "expires_in")))
         (state (append (list :resource (mcp-oauth-provider-resource provider)
                              :issuer (mcp-oauth-provider-authorization-server provider)
                              :client (mcp-oauth--ensure-client provider))
                        tokens
                        (when expires-in
                          (list :expires_at (+ (float-time) expires-in)))
                        (when (and old (not (plist-get tokens :refresh_token)))
                          (list :refresh_token (plist-get old :refresh_token))))))
    (mcp-oauth--save-state provider state)
    state))

(defun mcp-oauth--token-response (provider fields label)
  "POST OAuth FIELDS and return parsed token response for LABEL."
  (let* ((metadata (or (mcp-oauth-provider-metadata provider)
                       (mcp-oauth-discover provider)))
         (client (mcp-oauth--ensure-client provider))
         (form (mcp-oauth--form
                (append fields
                        (list (cons "client_id" (plist-get client :client_id))
                              (cons "resource"
                                    (mcp-oauth-provider-resource provider)))))))
    (pcase-let ((`(,status ,_headers ,body)
                 (mcp-oauth--http
                  provider "POST" (plist-get metadata :token_endpoint)
                  '(("Content-Type" . "application/x-www-form-urlencoded"))
                  form)))
      (cons status (mcp-oauth--json body label)))))

(defun mcp-oauth--token-request (provider fields label)
  "POST OAuth FIELDS to PROVIDER token endpoint for LABEL."
  (pcase-let ((`(,status . ,payload)
               (mcp-oauth--token-response provider fields label)))
    (unless (<= 200 status 299)
      (error "OAuth %s failed (%d): %s" label status
             (mcp-oauth--redact
              (or (plist-get payload :error)
                  (plist-get payload :error_description)
                  "request failed"))))
    (unless (stringp (plist-get payload :access_token))
      (error "OAuth %s did not return an access token" label))
    (mcp-oauth--merge-state provider payload)))

;;;###autoload
(defun mcp-oauth-token (provider)
  "Return PROVIDER's cached access token, or nil."
  (plist-get (or (mcp-oauth-provider-state provider)
                 (mcp-oauth--load-state provider)) :access_token))

(defun mcp-oauth--expired-p (provider)
  "Return non-nil when PROVIDER's access token needs renewal."
  (let ((state (or (mcp-oauth-provider-state provider)
                   (mcp-oauth--load-state provider))))
    (or (not (stringp (plist-get state :access_token)))
        (let ((expiry (plist-get state :expires_at)))
          (and expiry (<= expiry (+ (float-time) mcp-oauth-expiry-skew)))))))

;;;###autoload
(defun mcp-oauth-refresh (provider)
  "Refresh PROVIDER credentials, clearing stale state on invalid_grant."
  (condition-case err
      (let ((refresh-token (plist-get (or (mcp-oauth-provider-state provider)
                                          (mcp-oauth--load-state provider))
                                      :refresh_token)))
        (unless (stringp refresh-token) (error "No OAuth refresh token"))
        (mcp-oauth--token-request
         provider (list (cons "grant_type" "refresh_token")
                        (cons "refresh_token" refresh-token)) "refresh"))
    (error
     (when (string-match-p "invalid_grant" (error-message-string err))
       (mcp-oauth--delete-state provider))
     (signal (car err) (cdr err)))))

(defun mcp-oauth--open-browser (provider url)
  "Open PROVIDER authorization URL when configured to do so."
  (let ((opener (mcp-oauth--config provider :open-browser)))
    (when opener
      (if (functionp opener)
          (funcall opener url)
        (browse-url url)))))

(defun mcp-oauth--finish (provider state error)
  "Complete PROVIDER authorization waiters with STATE or safe ERROR."
  (cl-incf (mcp-oauth-provider-authorization-generation provider))
  (dolist (timer (list (mcp-oauth-provider-poll-timer provider)
                       (mcp-oauth-provider-authorization-timer provider)))
    (when timer (cancel-timer timer)))
  (dolist (process (cons (mcp-oauth-provider-authorization-process provider)
                         (mcp-oauth-provider-authorization-clients provider)))
    (when process (mcp-oauth--close-loopback-client provider process)))
  (setf (mcp-oauth-provider-poll-timer provider) nil
        (mcp-oauth-provider-authorization-timer provider) nil
        (mcp-oauth-provider-authorization-process provider) nil
        (mcp-oauth-provider-authorization-clients provider) nil)
  (let ((waiters (nreverse (mcp-oauth-provider-waiters provider))))
    (setf (mcp-oauth-provider-waiters provider) nil)
    (dolist (waiter waiters)
      (if state
          (funcall (car waiter) state)
        (funcall (cdr waiter) error)))))

(defun mcp-oauth--device-expired-p (device)
  "Return non-nil when DEVICE's absolute authorization deadline passed."
  (<= (plist-get device :expires_at) (float-time)))

(defun mcp-oauth--schedule-poll (provider device)
  "Schedule PROVIDER's next DEVICE poll, unless its deadline has passed."
  (if (mcp-oauth--device-expired-p device)
      (mcp-oauth--finish provider nil "OAuth device authorization expired")
    (setf (mcp-oauth-provider-poll-timer provider)
          (run-at-time (plist-get device :interval) nil
                       #'mcp-oauth--device-poll provider device))))

(defun mcp-oauth--device-poll (provider device)
  "Poll PROVIDER device authorization DEVICE once."
  (if (mcp-oauth--device-expired-p device)
      (mcp-oauth--finish provider nil "OAuth device authorization expired")
    (condition-case err
        (pcase-let* ((`(,status . ,payload)
                      (mcp-oauth--token-response
                       provider
                       (list (cons "grant_type" "urn:ietf:params:oauth:grant-type:device_code")
                             (cons "device_code" (plist-get device :device_code)))
                       "device authorization"))
                     (code (plist-get payload :error)))
          (cond
           ((<= 200 status 299)
            (mcp-oauth--finish provider (mcp-oauth--merge-state provider payload) nil))
           ((member code '("authorization_pending" "slow_down"))
            (when (equal code "slow_down")
              (plist-put device :interval (+ 5 (plist-get device :interval))))
            (mcp-oauth--schedule-poll provider device))
           ((member code '("invalid_grant" "expired_token" "access_denied"))
            (mcp-oauth--delete-state provider)
            (mcp-oauth--finish provider nil "OAuth device authorization expired, was denied, or was revoked"))
           (t (mcp-oauth--finish provider nil "OAuth device authorization failed"))))
      (error (mcp-oauth--finish provider nil
                                (mcp-oauth--redact (error-message-string err)))))))

(defun mcp-oauth--windows-random-command (count)
  "Run the fixed PowerShell CSPRNG command for validated COUNT bytes."
  (let* ((system-root (getenv "SystemRoot"))
         (powershell (and system-root
                          (expand-file-name "System32/WindowsPowerShell/v1.0/powershell.exe"
                                            system-root))))
    (unless (and powershell (file-executable-p powershell))
      (error "Windows cryptographic random source is unavailable"))
    (with-temp-buffer
      (let ((status (call-process
                     powershell nil t nil "-NoProfile" "-NonInteractive" "-Command"
                     (format "$b=New-Object byte[] %d;[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b);[Convert]::ToBase64String($b)" count))))
        (unless (and (integerp status) (zerop status))
          (error "Windows cryptographic random source failed"))
        (buffer-string)))))

(defun mcp-oauth--windows-random-bytes (count)
  "Return COUNT cryptographically secure random bytes on native Windows.
The fixed PowerShell program receives only the validated requested byte count.
It emits base64 so no binary data is passed through a command argument."
  (unless (and (integerp count) (> count 0) (<= count 4096))
    (error "Invalid OAuth random byte count"))
  (condition-case nil
      (let ((bytes (base64-decode-string
                    (string-trim (mcp-oauth--windows-random-command count)))))
        (unless (= (length bytes) count)
          (error "Windows cryptographic random source returned invalid bytes"))
        bytes)
    (error (error "Windows cryptographic random source returned invalid bytes"))))

(defun mcp-oauth--random-bytes (count)
  "Return COUNT cryptographically random bytes, or fail closed."
  (if (eq system-type 'windows-nt)
      (mcp-oauth--windows-random-bytes count)
    (unless (file-readable-p "/dev/urandom")
      (error "No operating-system cryptographic random source is available"))
    (with-temp-buffer
      (set-buffer-multibyte nil)
      (insert-file-contents-literally "/dev/urandom" nil nil count)
      (let ((bytes (buffer-string)))
        (unless (= (length bytes) count)
          (error "Operating-system cryptographic random source returned invalid bytes"))
        bytes))))

(defun mcp-oauth--base64url (bytes)
  "Return unpadded base64url encoding of BYTES."
  (replace-regexp-in-string "=" ""
                            (replace-regexp-in-string "/" "_"
                                                      (replace-regexp-in-string "+" "-"
                                                                                (base64-encode-string bytes t)))))

(defun mcp-oauth--constant-time-string= (left right)
  "Compare equal-length strings LEFT and RIGHT without early exit."
  (and (stringp left) (stringp right) (= (length left) (length right))
       (= 0 (let ((difference 0)
                  (index 0))
              (while (< index (length left))
                (setq difference (logior difference
                                         (logxor (aref left index)
                                                 (aref right index)))
                      index (1+ index)))
              difference))))

(defun mcp-oauth--loopback-request (request port path state)
  "Return the validated authorization code in REQUEST, or signal a safe error."
  (unless (and (stringp request) (< (string-bytes request) 8192))
    (error "OAuth redirect validation failed"))
  (setq request (replace-regexp-in-string "\r" "" request))
  (unless (string-match-p "\n\n" request)
    (error "OAuth redirect validation failed"))
  (let* ((lines (mapcar #'string-trim (split-string request "\n" t)))
         (parts (split-string (car lines) " " t))
         (hosts (seq-filter (lambda (line)
                              (and (string-match-p "\\`[Hh][Oo][Ss][Tt]:" line) line))
                            (cdr lines)))
         (target (nth 1 parts))
         (query (and target (cadr (split-string target "?"))))
         ;; `url-parse-query-string' collapses duplicate keys, so count raw
         ;; fields first and only then use its decoded value.
         (raw-fields (and query (split-string query "&" t)))
         (raw-count (lambda (key)
                      (cl-count key raw-fields
                                :test (lambda (wanted field)
                                        (equal wanted (url-unhex-string
                                                       (car (split-string field "="))))))))
         (pairs (and query (url-parse-query-string query t)))
         (code (cadr (assoc "code" pairs)))
         (returned-state (cadr (assoc "state" pairs))))
    (unless (and (= (length parts) 3) (equal (car parts) "GET")
                 (equal (nth 2 parts) "HTTP/1.1")
                 (= (length hosts) 1)
                 (string= (downcase (string-trim (car hosts)))
                          (format "host: localhost:%d" port))
                 (stringp target) (string= (car (split-string target "?")) path)
                 (= (funcall raw-count "code") 1) (= (funcall raw-count "state") 1)
                 (stringp code) (mcp-oauth--constant-time-string= state returned-state))
      (error "OAuth redirect validation failed"))
    code))

(defun mcp-oauth--redirect-uri (provider)
  "Return PROVIDER's registered localhost HTTP redirect URI."
  (let ((uri (mcp-oauth--config provider :redirect-uri)))
    (unless (and (stringp uri)
                 (string-match-p "\\`http://localhost:[0-9]+/[^?#]*\\'" uri))
      (error "OAuth redirect-uri must be a registered localhost HTTP URI"))
    uri))

(defun mcp-oauth--close-loopback-client (provider connection)
  "Close CONNECTION and release its callback deadline and provider entry."
  (when-let* ((timer (process-get connection 'mcp-oauth-deadline)))
    (cancel-timer timer)
    (process-put connection 'mcp-oauth-deadline nil))
  (setf (mcp-oauth-provider-authorization-clients provider)
        (delq connection (mcp-oauth-provider-authorization-clients provider)))
  (when (process-live-p connection) (delete-process connection)))

(defun mcp-oauth--loopback-filter (provider port path state verifier redirect-uri generation connection chunk)
  "Accumulate one bounded loopback HTTP request and exchange its valid code."
  (when (and (mcp-oauth-provider-waiters provider)
             (= generation (mcp-oauth-provider-authorization-generation provider)))
  (let ((request (concat (or (process-get connection 'mcp-oauth-request) "") chunk)))
    (process-put connection 'mcp-oauth-request request)
    (cl-pushnew connection (mcp-oauth-provider-authorization-clients provider))
    (cond
     ((>= (string-bytes request) 8192)
      (mcp-oauth--finish provider nil "OAuth redirect validation failed"))
     ((or (string-match-p (regexp-quote "\r\n\r\n") request)
          (string-match-p (regexp-quote "\n\n") request))
      (condition-case nil
          (let ((code (mcp-oauth--loopback-request request port path state)))
            (cl-incf (mcp-oauth-provider-authorization-generation provider))
            (process-send-string connection "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            (let ((tokens (mcp-oauth--token-request
                           provider (list (cons "grant_type" "authorization_code")
                                          (cons "code" code)
                                          (cons "code_verifier" verifier)
                                          (cons "redirect_uri" redirect-uri))
                           "authorization code")))
              (when (= (1+ generation) (mcp-oauth-provider-authorization-generation provider))
                (mcp-oauth--finish provider tokens nil))))
        (error
         (when (memq (mcp-oauth-provider-authorization-generation provider)
                     (list generation (1+ generation)))
           (mcp-oauth--finish provider nil "OAuth redirect validation failed")))))))))

(defun mcp-oauth--authorize-code (provider)
  "Start PKCE authorization-code flow for PROVIDER."
  (let* ((metadata (or (mcp-oauth-provider-metadata provider) (mcp-oauth-discover provider)))
         (endpoint (plist-get metadata :authorization_endpoint))
         (methods (plist-get metadata :code_challenge_methods_supported))
         (client (mcp-oauth--ensure-client provider))
         (redirect-uri (mcp-oauth--redirect-uri provider))
         (parsed (url-generic-parse-url redirect-uri))
         (port (url-port parsed)) (path (url-filename parsed))
         (generation (mcp-oauth-provider-authorization-generation provider))
         (state (mcp-oauth--base64url (mcp-oauth--random-bytes 32)))
         (verifier (mcp-oauth--base64url (mcp-oauth--random-bytes 48))))
    (unless (and (stringp endpoint) (seq-contains-p methods "S256" #'string=))
      (error "OAuth authorization server does not support PKCE S256"))
    (mcp-oauth--require-url provider endpoint "authorization_endpoint")
    (setf (mcp-oauth-provider-authorization-process provider)
          (make-network-process
           :name "mcp-oauth-loopback" :family 'ipv4 :server t :host "127.0.0.1"
           :service port :noquery t
           :log (lambda (_server connection _message)
                  (setf (mcp-oauth-provider-authorization-clients provider)
                        (seq-filter #'process-live-p
                                    (mcp-oauth-provider-authorization-clients provider)))
                  (if (>= (length (mcp-oauth-provider-authorization-clients provider)) 8)
                      (delete-process connection)
                    (push connection (mcp-oauth-provider-authorization-clients provider))
                    (process-put connection 'mcp-oauth-deadline
                                 (run-at-time 5 nil #'mcp-oauth--close-loopback-client
                                              provider connection))
                    (set-process-filter
                     connection
                     (apply-partially #'mcp-oauth--loopback-filter provider port path state verifier redirect-uri generation))))))
    (setf (mcp-oauth-provider-authorization-timer provider)
          (run-at-time 300 nil #'mcp-oauth--finish provider nil "OAuth authorization timed out"))
    (mcp-oauth--open-browser
     provider
     (concat endpoint (if (string-match-p "?" endpoint) "&" "?")
             (mcp-oauth--form
              (list (cons "response_type" "code") (cons "client_id" (plist-get client :client_id))
                    (cons "redirect_uri" redirect-uri) (cons "resource" (mcp-oauth-provider-resource provider))
                    (cons "scope" (mcp-oauth--scope provider)) (cons "state" state)
                    (cons "code_challenge" (mcp-oauth--base64url (secure-hash 'sha256 verifier nil nil t)))
                    (cons "code_challenge_method" "S256")))))))

;;;###autoload
(defun mcp-oauth-authorize (provider success failure)
  "Start configured OAuth authorization for PROVIDER asynchronously.
Authorization-code S256 PKCE is default; device code is an explicit extension."
  (if (mcp-oauth-provider-waiters provider)
      (push (cons success failure) (mcp-oauth-provider-waiters provider))
    (setf (mcp-oauth-provider-waiters provider) (list (cons success failure)))
    (if (eq (mcp-oauth--grant-type provider) 'authorization-code)
        (condition-case err
            (mcp-oauth--authorize-code provider)
          (error (mcp-oauth--finish provider nil
                                    (mcp-oauth--redact (error-message-string err)))))
      (condition-case err
          (let* ((metadata (or (mcp-oauth-provider-metadata provider)
                               (mcp-oauth-discover provider)))
                 (endpoint (plist-get metadata :device_authorization_endpoint))
               (client (mcp-oauth--ensure-client provider)))
          (mcp-oauth--require-url provider endpoint "Device authorization endpoint")
          (let* ((device (mcp-oauth--request-json
                          provider "POST" endpoint
                          '(("Content-Type" . "application/x-www-form-urlencoded"))
                          (mcp-oauth--form
                           (list (cons "client_id" (plist-get client :client_id))
                                 (cons "scope" (mcp-oauth--scope provider))
                                 (cons "resource" (mcp-oauth-provider-resource provider))))
                          "device authorization"))
                 (verification-url (or (plist-get device :verification_uri_complete)
                                       (plist-get device :verification_uri)))
                 (expires-in (mcp-oauth--positive-number (plist-get device :expires_in) "expires_in"))
                 (interval (if (plist-member device :interval)
                               (mcp-oauth--positive-number (plist-get device :interval) "interval")
                             5)))
            (unless (and (stringp (plist-get device :device_code))
                         (stringp verification-url) (stringp (plist-get device :user_code)))
              (error "Device authorization response is incomplete"))
            (mcp-oauth--require-url provider verification-url "Device verification URL")
            (plist-put device :interval interval)
            (plist-put device :expires_at (+ (float-time) expires-in))
            (mcp-oauth--open-browser provider verification-url)
            (message "Authorize MCP in your browser at %s; enter code %s"
                     verification-url (plist-get device :user_code))
            (mcp-oauth--schedule-poll provider device)))
        (error (mcp-oauth--finish provider nil
                                  (mcp-oauth--redact (error-message-string err))))))))

;;;###autoload
(defun mcp-oauth-reset-discovery (provider)
  "Forget PROVIDER metadata and cached registration after a 401.
Keep refresh credentials until rediscovery verifies the issuer binding."
  (setf (mcp-oauth-provider-metadata provider) nil
        (mcp-oauth-provider-authorization-server provider) nil
        (mcp-oauth-provider-client provider) nil))

(defun mcp-oauth-ensure-token (provider success failure)
  "Ensure PROVIDER has a valid token; cold discovery is synchronous.
Cached metadata avoids synchronous discovery for every valid-token message."
  (condition-case err
      (progn
        (when (or (null (mcp-oauth-provider-metadata provider))
                  (mcp-oauth--expired-p provider))
          (mcp-oauth-discover provider))
        (if (not (mcp-oauth--expired-p provider))
            (funcall success (mcp-oauth-token provider))
          (condition-case refresh-error
              (let ((state (mcp-oauth-refresh provider)))
                (funcall success (plist-get state :access_token)))
            (error
             (if (string-match-p "No OAuth refresh token\\|invalid_grant"
                                 (error-message-string refresh-error))
                 (mcp-oauth-authorize
                  provider
                  (lambda (state)
                    (funcall success (plist-get state :access_token)))
                  failure)
               (funcall failure
                        (mcp-oauth--redact
                         (error-message-string refresh-error))))))))
    (error
     (funcall failure (mcp-oauth--redact (error-message-string err))))))

;;;###autoload
(defun mcp-oauth-invalidate-access-token (provider)
  "Discard only PROVIDER's access token, retaining refresh credentials.
The next `mcp-oauth-ensure-token' first attempts a refresh, then begins device
authorization only if no usable refresh credential remains."
  (let ((state (or (mcp-oauth-provider-state provider)
                   (mcp-oauth--load-state provider))))
    (when state
      (setq state (plist-put state :access_token nil))
      (setq state (plist-put state :expires_at 0))
      (mcp-oauth--save-state provider state))))

;;;###autoload
(defun mcp-oauth-cancel-authorization (provider)
  "Cancel PROVIDER's in-flight device authorization without deleting credentials."
  (when (mcp-oauth-provider-waiters provider)
    (mcp-oauth--finish provider nil "OAuth device authorization cancelled")))

(declare-function mcp--oauth "mcp")
(defvar mcp-server-connections)
(defvar mcp-hub-servers)

(defun mcp-oauth--read-provider ()
  "Read an OAuth provider from an active or configured MCP server.
A configured OAuth server is reconstructed without making a connection."
  (require 'mcp)
  (require 'mcp-hub nil t)
  (let (choices)
    (maphash (lambda (name connection)
               (when (and (object-of-class-p connection 'mcp-http-process-connection)
                          (mcp--oauth connection))
                 (push name choices)))
             mcp-server-connections)
    (dolist (server (and (boundp 'mcp-hub-servers) mcp-hub-servers))
      (when (plist-get (cdr server) :oauth) (push (car server) choices)))
    (let ((name (completing-read "MCP server or resource URL: "
                                 (delete-dups choices) nil nil)))
      (cond ((gethash name mcp-server-connections)
             (let ((connection (gethash name mcp-server-connections)))
               (unless (object-of-class-p connection 'mcp-http-process-connection)
                 (user-error "MCP server %s has no OAuth provider" name))
               (or (mcp--oauth connection)
                   (user-error "MCP server %s has no OAuth provider" name))))
            ((let ((server (assoc-string name mcp-hub-servers)))
               (when-let* ((config (cdr server))
                           (oauth (plist-get config :oauth))
                           (url (plist-get config :url)))
                 (if (mcp-oauth-provider-p oauth) oauth
                   (mcp-oauth-create url oauth)))))
            ((string-match-p "\\`https?://" name)
             (mcp-oauth-create name))
            (t (user-error "No OAuth configuration for %s" name))))))

;;;###autoload
(defun mcp-oauth-clear-credentials (provider)
  "Clear persisted OAuth credentials for PROVIDER."
  (interactive (list (mcp-oauth--read-provider)))
  (mcp-oauth-cancel-authorization provider)
  (mcp-oauth--delete-state provider))

(provide 'mcp-oauth)
;;; mcp-oauth.el ends here
