;;; mcp-oauth-test.el --- Tests for mcp-oauth -*- lexical-binding: t; -*-
(require 'ert)
(require 'cl-lib)
(require 'mcp-oauth)
(require 'mcp)
(require 'mcp-hub)

(defmacro mcp-oauth-test-with-provider (&rest body)
  `(let* ((directory (make-temp-file "mcp-oauth-test-" t))
          (provider (mcp-oauth-create "https://mcp.example.test/v1?tenant=a"
                                      (list :storage-directory directory :open-browser nil :grant-type 'device-code))))
     (unwind-protect (progn ,@body) (delete-directory directory t))))

(ert-deftest mcp-oauth-test-clear-credentials-has-interactive-provider-input ()
  (mcp-oauth-test-with-provider
   (let (cancelled deleted)
     (cl-letf (((symbol-function 'mcp-oauth--read-provider)
                (lambda () provider))
               ((symbol-function 'mcp-oauth-cancel-authorization)
                (lambda (value) (setq cancelled value)))
               ((symbol-function 'mcp-oauth--delete-state)
                (lambda (value) (setq deleted value))))
       (call-interactively #'mcp-oauth-clear-credentials)
       (should (eq cancelled provider))
       (should (eq deleted provider))))))

(ert-deftest mcp-oauth-test-valid-token-does-not-rediscover ()
  (mcp-oauth-test-with-provider
   (let ((discoveries 0) success)
     (setf (mcp-oauth-provider-metadata provider) '(:token_endpoint "https://issuer.test/token")
           (mcp-oauth-provider-state provider) '(:access_token "token" :expires_at 9999999999))
     (cl-letf (((symbol-function 'mcp-oauth-discover)
                (lambda (_) (setq discoveries (1+ discoveries)))))
       (mcp-oauth-ensure-token provider (lambda (token) (setq success token)) #'ignore)
       (should (equal success "token"))
       (should (= discoveries 0))))))

(ert-deftest mcp-oauth-test-normalizes-numeric-fields-and-scopes ()
  (mcp-oauth-test-with-provider
   (should (= 3600 (mcp-oauth--positive-number "3600" "expires_in")))
   (should (equal "tools:read" (mcp-oauth--scope
                                  (mcp-oauth-create "https://mcp.example.test/v1"
                                                    '(:scopes "tools:read" :grant-type device-code)))))
   (should-error (mcp-oauth--positive-number "many" "interval"))))

(ert-deftest mcp-oauth-test-existing-directory-is-not-chmodded ()
  (let ((directory (make-temp-file "mcp-oauth-test-" t)))
    (unwind-protect
        (cl-letf (((symbol-function 'mcp-oauth--directory-safe-p) (lambda (_) t))
                  ((symbol-function 'set-file-modes) (lambda (&rest _) (error "must not chmod"))))
          (mcp-oauth--ensure-directory directory))
      (delete-directory directory t))))

(ert-deftest mcp-oauth-test-constant-time-string-checks-every-byte ()
  (should (mcp-oauth--constant-time-string= "state" "state"))
  (should-not (mcp-oauth--constant-time-string= "state" "xtate"))
  (should-not (mcp-oauth--constant-time-string= "state" "statx")))

(ert-deftest mcp-oauth-test-loopback-request-rejects-duplicate-and-invalid-input ()
  (should (equal "code" (mcp-oauth--loopback-request
                          "GET /callback?code=code&state=state HTTP/1.1\r\nhOsT: localhost:49152\r\n\r\n"
                          49152 "/callback" "state")))
  (dolist (request '("GET /callback?code=code&code=other&state=state HTTP/1.1\r\nHost: localhost:49152\r\n\r\n"
                     "GET /callback?code=code&state=state&state=other HTTP/1.1\r\nHost: localhost:49152\r\n\r\n"
                     "GET /callback?code=code&state=state HTTP/1.0\r\nHost: localhost:49152\r\n\r\n"
                     "GET /callback?code=code&state=wrong HTTP/1.1\r\nHost: localhost:49152\r\n\r\n"))
    (should-error (mcp-oauth--loopback-request request 49152 "/callback" "state"))))

(ert-deftest mcp-oauth-test-pkce-loopback-exchanges-only-validated-code ()
  (mcp-oauth-test-with-provider
   (let (filter browser token-fields result failure)
     (setf (mcp-oauth-provider-metadata provider)
           '(:authorization_endpoint "https://issuer.test/authorize"
             :code_challenge_methods_supported ["S256"])
           (mcp-oauth-provider-client provider) '(:client_id "client"))
     (setf (mcp-oauth-provider-config provider)
           '(:redirect-uri "http://localhost:49152/oauth/callback" :open-browser t))
     (cl-letf (((symbol-function 'mcp-oauth--random-bytes)
                (lambda (count) (make-string count ?x)))
               ((symbol-function 'make-network-process)
                (lambda (&rest args)
                  (funcall (plist-get args :log) 'listener 'client "accept")
                  'listener))
               ((symbol-function 'set-process-filter) (lambda (_ value) (setq filter value)))
               ((symbol-function 'process-get) (lambda (&rest _) nil))
               ((symbol-function 'process-put) (lambda (&rest _) nil))
               ((symbol-function 'process-live-p) (lambda (_) nil))
               ((symbol-function 'process-send-string) (lambda (&rest _) nil))
               ((symbol-function 'run-at-time) (lambda (&rest _) nil))
               ((symbol-function 'mcp-oauth--open-browser)
                (lambda (_ url) (setq browser url)))
               ((symbol-function 'mcp-oauth--token-request)
                (lambda (_ fields _) (setq token-fields fields) '(:access_token "token"))))
       (mcp-oauth-authorize provider (lambda (state) (setq result state)) (lambda (message) (setq failure message)))
       (let ((state (cadr (assoc "state" (url-parse-query-string (cadr (split-string browser "?")) t)))))
         (funcall filter 'client (format "GET /oauth/callback?code=code&state=%s HTTP/1.1\r\nHost: localhost:49152\r\n\r\n" state)))
       (should-not failure)
       (should (equal (cdr (assoc-string "code" token-fields)) "code"))
       (should (equal (plist-get result :access_token) "token"))))))

(ert-deftest mcp-oauth-test-pkce-loopback-accepts-fragmented-local-request ()
  (mcp-oauth-test-with-provider
   (let (browser result failure port client)
     (setf (mcp-oauth-provider-metadata provider)
           '(:authorization_endpoint "https://issuer.test/authorize"
             :code_challenge_methods_supported ["S256"])
           (mcp-oauth-provider-client provider) '(:client_id "client"))
     (cl-letf (((symbol-function 'mcp-oauth--random-bytes) (lambda (count) (make-string count ?x)))
               ((symbol-function 'mcp-oauth--open-browser) (lambda (_ url) (setq browser url)))
               ((symbol-function 'mcp-oauth--token-request) (lambda (&rest _) '(:access_token "token"))))
       (setq port (+ 30000 (random 20000)))
       (setf (mcp-oauth-provider-config provider)
             (list :redirect-uri (format "http://localhost:%d/callback" port) :open-browser t
                   :static-client '(:client_id "client" :token_endpoint_auth_method "none")))
       (mcp-oauth-authorize provider (lambda (state) (setq result state))
                            (lambda (message) (setq failure message)))
       (accept-process-output nil 0.05)
       (should-not failure)
       (should (process-live-p (mcp-oauth-provider-authorization-process provider)))
       (setq client (open-network-stream "mcp-oauth-test-client" nil "127.0.0.1" port :type 'plain))
       (let ((state (cadr (assoc "state" (url-parse-query-string (cadr (split-string browser "?")) t)))))
         (process-send-string client (format "GET /callback?code=code&sta"))
         (accept-process-output nil 0.05)
         (process-send-string client (format "te=%s HTTP/1.1\r\nHost: localhost:%d\r\n\r\n" state port)))
       (dotimes (_ 20)
         (unless (or result failure)
           (accept-process-output (mcp-oauth-provider-authorization-process provider) 0.05)
           (accept-process-output nil 0.05)))
       (when (process-live-p client) (delete-process client))
       (should-not failure)
       (should (equal (plist-get result :access_token) "token"))))))

(ert-deftest mcp-oauth-test-pkce-loopback-rejects-state-mismatch ()
  (mcp-oauth-test-with-provider
   (let (filter exchanged failure)
     (setf (mcp-oauth-provider-metadata provider)
           '(:authorization_endpoint "https://issuer.test/authorize"
             :code_challenge_methods_supported ["S256"])
           (mcp-oauth-provider-client provider) '(:client_id "client")
           (mcp-oauth-provider-config provider) '(:redirect-uri "http://localhost:49153/callback" :open-browser t))
     (cl-letf (((symbol-function 'mcp-oauth--random-bytes) (lambda (count) (make-string count ?x)))
               ((symbol-function 'make-network-process)
                (lambda (&rest args)
                  (funcall (plist-get args :log) 'listener 'client "accept")
                  'listener))
               ((symbol-function 'set-process-filter) (lambda (_ value) (setq filter value)))
               ((symbol-function 'process-get) (lambda (&rest _) nil))
               ((symbol-function 'process-put) (lambda (&rest _) nil))
               ((symbol-function 'process-live-p) (lambda (_) nil))
               ((symbol-function 'run-at-time) (lambda (&rest _) nil))
               ((symbol-function 'mcp-oauth--open-browser) (lambda (&rest _) nil))
               ((symbol-function 'mcp-oauth--token-request) (lambda (&rest _) (setq exchanged t))))
       (mcp-oauth-authorize provider #'ignore (lambda (message) (setq failure message)))
       (funcall filter 'client "GET /callback?code=code&state=wrong HTTP/1.1\r\nHost: localhost:49153\r\n\r\n")
       (should-not exchanged)
       (should failure)))))

(ert-deftest mcp-oauth-test-stopped-server-clear-selection-skips-stdio ()
  (mcp-oauth-test-with-provider
   (let ((mcp-server-connections (make-hash-table :test #'equal))
         (pipe (make-pipe-process :name "mcp-stdio-test" :noquery t))
         (mcp-hub-servers
          (list (cons "stopped" (list :url "https://mcp.example.test/v1?tenant=a"
                                      :oauth (mcp-oauth-provider-config provider))))))
     (unwind-protect
         (progn
           (puthash "stdio" (make-instance 'mcp-stdio-process-connection :name "stdio" :process pipe)
                    mcp-server-connections)
           (cl-letf (((symbol-function 'completing-read) (lambda (&rest _) "stopped")))
             (let ((selected (mcp-oauth--read-provider)))
               (should (equal (mcp-oauth--state-file selected) (mcp-oauth--state-file provider)))
               (should (= 1 (hash-table-count mcp-server-connections))))))
       (when (process-live-p pipe) (delete-process pipe))))))

(ert-deftest mcp-oauth-test-sync-connection-rejected-before-process-creation ()
  (let ((mcp-server-connections (make-hash-table :test #'equal)))
    (cl-letf (((symbol-function 'make-network-process)
               (lambda (&rest _) (ert-fail "Connection creation must not occur"))))
      (should (equal "Synchronous MCP OAuth connections are unsupported"
                     (condition-case err
                         (mcp-connect-server "sync-oauth" :url "https://mcp.example.test/mcp"
                                             :oauth '(:grant-type device-code) :syncp t)
                       (error (error-message-string err)))))
      (should (= 0 (hash-table-count mcp-server-connections))))))

(ert-deftest mcp-oauth-test-loopback-idle-client-has-short-deadline ()
  (mcp-oauth-test-with-provider
   (let ((schedule (symbol-function 'run-at-time)) client failure)
     (setf (mcp-oauth-provider-metadata provider)
           '(:authorization_endpoint "https://issuer.test/authorize"
             :code_challenge_methods_supported ["S256"])
           (mcp-oauth-provider-client provider) '(:client_id "client")
           (mcp-oauth-provider-config provider)
           (list :redirect-uri (format "http://localhost:%d/callback" (+ 30000 (random 20000)))))
     (unwind-protect
         (cl-letf (((symbol-function 'run-at-time)
                    (lambda (time repeat function &rest args)
                      (apply schedule (if (equal time 5) 0.05 time) repeat function args))))
           (mcp-oauth-authorize provider #'ignore (lambda (message) (setq failure message)))
           (should-not failure)
           (setq client (open-network-stream
                         "mcp-oauth-idle-test" nil "127.0.0.1"
                         (url-port (url-generic-parse-url (mcp-oauth--redirect-uri provider))) :type 'plain))
           (dotimes (_ 5) (accept-process-output nil 0.05))
           (should-not (mcp-oauth-provider-authorization-clients provider))
           (should (process-live-p (mcp-oauth-provider-authorization-process provider)))
           (should (mcp-oauth-provider-waiters provider)))
       (when (and client (process-live-p client)) (delete-process client))
       (mcp-oauth-cancel-authorization provider)))))

(ert-deftest mcp-oauth-test-late-loopback-callback-never-exchanges ()
  (mcp-oauth-test-with-provider
   (let ((exchanges 0))
     (cl-letf (((symbol-function 'mcp-oauth--token-request)
                (lambda (&rest _) (cl-incf exchanges))))
       (mcp-oauth--loopback-filter provider 49152 "/callback" "state" "verifier"
                                  "http://localhost:49152/callback" 0 nil
                                  "GET /callback?code=c&state=state HTTP/1.1\r\nHost: localhost:49152\r\n\r\n")
       (setf (mcp-oauth-provider-waiters provider) (list (cons #'ignore #'ignore))
             (mcp-oauth-provider-authorization-generation provider) 1)
       (mcp-oauth--loopback-filter provider 49152 "/callback" "state" "verifier"
                                  "http://localhost:49152/callback" 0 nil "late")
       (should (= exchanges 0))))))

(ert-deftest mcp-oauth-test-401-reset-retains-refresh-until-issuer-verification ()
  (mcp-oauth-test-with-provider
   (setf (mcp-oauth-provider-state provider)
         '(:issuer "https://issuer.test" :refresh_token "refresh")
         (mcp-oauth-provider-metadata provider) '(:issuer "https://issuer.test")
         (mcp-oauth-provider-client provider) '(:client_id "client"))
   (mcp-oauth-reset-discovery provider)
   (should (equal "refresh" (plist-get (mcp-oauth-provider-state provider) :refresh_token)))
   (should-not (mcp-oauth-provider-metadata provider))
   (should-not (mcp-oauth-provider-client provider))))

(ert-deftest mcp-oauth-test-windows-random-bytes-rejects-malformed-output ()
  (cl-letf (((symbol-function 'mcp-oauth--windows-random-command)
             (lambda (_) "invalid")))
    (should-error (mcp-oauth--windows-random-bytes 32))))

(ert-deftest mcp-oauth-test-resource-keeps-query-and-rejects-fragment ()
  (should (equal (mcp-oauth-provider-resource (mcp-oauth-create "https://mcp.example.test/v1?tenant=a"))
                 "https://mcp.example.test/v1?tenant=a"))
  (should-not (equal (mcp-oauth--state-file (mcp-oauth-create "https://mcp.example.test/v1?a"))
                     (mcp-oauth--state-file (mcp-oauth-create "https://mcp.example.test/v1?b"))))
  (should-error (mcp-oauth-create "https://mcp.example.test/v1#fragment")))

(ert-deftest mcp-oauth-test-discovery-requires-exact-issuer ()
  (mcp-oauth-test-with-provider
   (cl-letf (((symbol-function 'mcp-oauth--protected-resource-metadata)
              (lambda (_) '(:resource "https://mcp.example.test/v1?tenant=a"
                            :authorization_servers ["https://issuer.test"])))
             ((symbol-function 'mcp-oauth--request-json)
              (lambda (&rest _) '(:token_endpoint "https://issuer.test/token"))))
     (should-error (mcp-oauth-discover provider)))))

(ert-deftest mcp-oauth-test-rfc8414-root-and-path-issuer-urls ()
  (let ((provider (mcp-oauth-create "https://mcp.example.test/v1")))
    (should (equal (mcp-oauth--authorization-server-metadata-url provider "https://issuer.test")
                   "https://issuer.test/.well-known/oauth-authorization-server"))
    (should (equal (mcp-oauth--authorization-server-metadata-url provider "https://issuer.test/tenant")
                   "https://issuer.test/.well-known/oauth-authorization-server/tenant"))
    (should-error (mcp-oauth--authorization-server-metadata-url provider "https://issuer.test/a?x=1"))))

(ert-deftest mcp-oauth-test-redacts-common-text-forms ()
  (let ((text (mcp-oauth--redact
               "{\"access_token\":\"a\", refresh_token: r, 'client_secret'=s, device_code=d, code=c} Authorization: Bearer bearer")))
    (let ((case-fold-search nil))
      (dolist (secret '("\"a\"" "refresh_token: r" "=s" "=d" "=c" "bearer"))
        (should-not (string-match-p (regexp-quote secret) text))))
    (should (string-match-p "REDACTED" text))))

(ert-deftest mcp-oauth-test-refuses-redirect-without-parsing-body ()
  (mcp-oauth-test-with-provider
   (cl-letf (((symbol-function 'mcp-oauth--http)
              (lambda (&rest _) '(302 "Location: http://evil.test" "access_token=secret"))))
     (let ((message (condition-case err
                        (mcp-oauth--request-json provider "GET" "https://issuer.test/x" nil nil "metadata")
                      (error (error-message-string err)))))
       (should (string-match-p "redirect refused" message))
       (should-not (string-match-p "secret" message))))))

(ert-deftest mcp-oauth-test-state-round-trips-json-arrays ()
  (mcp-oauth-test-with-provider
   (let* ((client (mcp-oauth--json
                   "{\"client_id\":\"client\",\"grant_types\":[\"device_code\",\"refresh_token\"]}"
                   "test client"))
          (state (list :resource (mcp-oauth-provider-resource provider)
                       :issuer "https://issuer.test"
                       :client client)))
     (mcp-oauth--save-state provider state)
     (setf (mcp-oauth-provider-state provider) nil)
     (let ((loaded (mcp-oauth--load-state provider)))
       (should (equal ["device_code" "refresh_token"]
                      (plist-get (plist-get loaded :client) :grant_types)))))))

(ert-deftest mcp-oauth-test-combined-auth-bearer-bypasses-basic-handler ()
  (mcp-oauth-test-with-provider
   (let (delegated)
     (cl-letf (((symbol-function 'url-retrieve-synchronously)
                (lambda (&rest _)
                  (with-temp-buffer
                    (insert "HTTP/1.1 401 Unauthorized\r\n"
                            "WWW-Authenticate: Basic realm=\"x\", Bearer resource_metadata=\"https://issuer.test/metadata\"\r\n\r\n")
                    (setq-local url-http-end-of-headers (point-max))
                    (should (funcall (symbol-function
                                      'url-http-handle-authentication)
                                     nil)))
                  nil))
               ((symbol-function 'url-http-handle-authentication)
                (lambda (_proxy) (setq delegated t))))
       (should-error
        (mcp-oauth--http provider "POST"
                         "https://mcp.example.test/v1" nil "{}"))
       (should-not delegated)))))

(ert-deftest mcp-oauth-test-derived-metadata-url-excludes-query ()
  (mcp-oauth-test-with-provider
   (should (equal
            "https://mcp.example.test/.well-known/oauth-protected-resource/v1"
            (mcp-oauth--metadata-url provider)))))

(ert-deftest mcp-oauth-test-bearer-401-bypasses-basic-auth-handler ()
  (mcp-oauth-test-with-provider
   (let (delegated)
     (cl-letf (((symbol-function 'url-retrieve-synchronously)
                (lambda (&rest _)
                  (with-temp-buffer
                    (insert "HTTP/1.1 401 Unauthorized\n"
                            "WWW-Authenticate: Bearer resource_metadata=\"https://issuer.test/metadata\"\n\n")
                    (setq-local url-http-end-of-headers (point-max))
                    (should (funcall (symbol-function
                                      'url-http-handle-authentication)
                                     nil)))
                  nil))
               ((symbol-function 'url-http-handle-authentication)
                (lambda (_proxy) (setq delegated t))))
       (should-error
        (mcp-oauth--http provider "POST"
                         "https://mcp.example.test/v1" nil "{}"))
       (should-not delegated)))))

(ert-deftest mcp-oauth-test-disables-url-redirects ()
  (mcp-oauth-test-with-provider
   (let (redirects)
     (cl-letf (((symbol-function 'url-retrieve-synchronously)
                (lambda (&rest _) (setq redirects url-max-redirections) nil)))
       (should-error (mcp-oauth--http provider "GET" "https://issuer.test/x" nil nil))
       (should (= redirects 0))))))

(ert-deftest mcp-oauth-test-requires-token-endpoint-not-authorization-endpoint ()
  (mcp-oauth-test-with-provider
   (cl-letf (((symbol-function 'mcp-oauth--http)
              (lambda (_p _m url _h _d)
                (if (string-match-p "protected-resource" url)
                    '(200 "" "{\"resource\":\"https://mcp.example.test/v1?tenant=a\",\"authorization_servers\":[\"https://issuer.test\"]}")
                  '(200 "" "{\"issuer\":\"https://issuer.test\",\"token_endpoint\":\"https://issuer.test/token\"}")))))
     (should (plist-get (mcp-oauth-discover provider) :token_endpoint)))))

(ert-deftest mcp-oauth-test-public-client-state-drops-unused-secret ()
  (should (equal '(:client_id "client" :token_endpoint_auth_method "none")
                 (mcp-oauth--public-client-state
                  '(:client_id "client"
                    :client_secret "unused"
                    :token_endpoint_auth_method "none")))))

(ert-deftest mcp-oauth-test-rejects-non-public-clients ()
  (should-error (mcp-oauth--validate-public-client '(:client_id "x" :token_endpoint_auth_method "client_secret_post") "test")))

(ert-deftest mcp-oauth-test-load-rejects-unsafe-state ()
  (mcp-oauth-test-with-provider
   (mcp-oauth--save-state
    provider `(:resource ,(mcp-oauth-provider-resource provider)
                         :issuer "https://issuer.test"))
   (let ((file (mcp-oauth--state-file provider)))
     ;; Exercise POSIX mode policy independently of the host filesystem.
     (cl-letf (((symbol-function 'file-modes) (lambda (_) #o644))
               ((symbol-function 'file-symlink-p) (lambda (_) nil))
               ((symbol-function 'file-regular-p) (lambda (_) t)))
       (let ((system-type 'gnu/linux))
         (should-error (mcp-oauth--load-state provider))))
     ;; Symlinks remain unsafe on every platform, including native Windows.
     (cl-letf (((symbol-function 'file-symlink-p) (lambda (_) "target"))
               ((symbol-function 'file-regular-p) (lambda (_) t)))
       (should-error (mcp-oauth--load-state provider)))
     (cl-letf (((symbol-function 'file-modes) (lambda (_) #o666))
               ((symbol-function 'file-symlink-p) (lambda (_) nil))
               ((symbol-function 'file-regular-p) (lambda (_) t)))
       (let ((system-type 'windows-nt))
         (should (mcp-oauth--state-file-safe-p file))))
     (let ((system-type 'windows-nt))
       (cl-letf (((symbol-function 'file-symlink-p) (lambda (_) "target"))
                 ((symbol-function 'file-regular-p) (lambda (_) t)))
         (should-not (mcp-oauth--state-file-safe-p file)))
       (cl-letf (((symbol-function 'file-symlink-p) (lambda (_) nil))
                 ((symbol-function 'file-regular-p) (lambda (_) nil)))
         (should-not (mcp-oauth--state-file-safe-p file)))))))

(ert-deftest mcp-oauth-test-single-flight-and-cancel ()
  (mcp-oauth-test-with-provider
   (let ((calls 0) (failures 0) timer)
     (setf (mcp-oauth-provider-metadata provider) '(:device_authorization_endpoint "https://issuer.test/device")
           (mcp-oauth-provider-client provider) '(:client_id "client")
           (mcp-oauth-provider-config provider) '(:grant-type device-code))
     (cl-letf (((symbol-function 'mcp-oauth--request-json)
                (lambda (&rest _) (setq calls (1+ calls))
                  '(:device_code "hidden" :verification_uri "https://issuer.test/v" :user_code "u" :expires_in 60)))
               ((symbol-function 'run-at-time) (lambda (&rest _) (setq timer 'timer) timer))
               ((symbol-function 'cancel-timer) (lambda (_timer) (setq timer 'cancelled))))
       (mcp-oauth-authorize provider #'ignore (lambda (_) (setq failures (1+ failures))))
       (mcp-oauth-authorize provider #'ignore (lambda (_) (setq failures (1+ failures))))
       (should (= calls 1)) (mcp-oauth-cancel-authorization provider)
       (should (eq timer 'cancelled)) (should (= failures 2))))))

(ert-deftest mcp-oauth-test-expired-device-never-polls-or-reschedules ()
  (mcp-oauth-test-with-provider
   (let ((requests 0) (scheduled 0) failed)
     (setf (mcp-oauth-provider-waiters provider) (list (cons #'ignore (lambda (e) (setq failed e)))))
     (cl-letf (((symbol-function 'mcp-oauth--token-response) (lambda (&rest _) (setq requests (1+ requests))))
               ((symbol-function 'run-at-time) (lambda (&rest _) (setq scheduled (1+ scheduled)))))
       (mcp-oauth--device-poll provider '(:expires_at 0 :interval 1 :device_code "x"))
       (mcp-oauth--schedule-poll provider '(:expires_at 0 :interval 1))
       (should (= requests 0)) (should (= scheduled 0)) (should failed)))))

(defun mcp-oauth-test--metadata ()
  "Return valid protected-resource metadata for the standard fixture."
  "{\"resource\":\"https://mcp.example.test/v1?tenant=a\",\"authorization_servers\":[\"https://issuer.test\"]}")

(ert-deftest mcp-oauth-test-derived-protected-metadata-skips-probe ()
  (mcp-oauth-test-with-provider
   (let (calls)
     (cl-letf (((symbol-function 'mcp-oauth--http)
                (lambda (_provider method url headers data)
                  (push (list method url headers data) calls) (list 200 "" (mcp-oauth-test--metadata)))))
       (should (mcp-oauth--protected-resource-metadata provider))
       (should (equal (mapcar #'car calls) '("GET")))))))

(ert-deftest mcp-oauth-test-challenge-discovers-protected-metadata ()
  (mcp-oauth-test-with-provider
   (let (calls)
     (cl-letf (((symbol-function 'mcp-oauth--http)
                (lambda (_provider method url headers data)
                  (push (list method url headers data) calls)
                  (cond ((and (equal method "GET") (string-match-p "oauth-protected-resource/v1" url)) '(404 "" "not json"))
                        ((equal method "POST") '(401 "wWw-AuThEnTiCaTe: Basic realm=\"x\", Bearer scope=\"mcp\", resource_metadata=\"https://metadata.example.test/resource\"" "ignored"))
                        ((equal url "https://metadata.example.test/resource") (list 200 "" (mcp-oauth-test--metadata)))
                        (t (error "unexpected request"))))))
       (should (mcp-oauth--protected-resource-metadata provider))
       (let ((ordered (nreverse calls)))
         (should (equal (mapcar #'car ordered) '("GET" "POST" "GET")))
         (should (equal (nth 1 (cadr ordered)) "https://mcp.example.test/v1?tenant=a"))
         (should (string-match-p "\\\"method\\\":\\\"initialize\\\"" (nth 3 (cadr ordered))))
         (should-not (assoc "Authorization" (nth 2 (cadr ordered)))))))))

(ert-deftest mcp-oauth-test-challenge-rejects-invalid-metadata-urls ()
  (mcp-oauth-test-with-provider
   (dolist (headers '("WWW-Authenticate: Bearer scope=\"x\""
                      "WWW-Authenticate: Bearer resource_metadata=\"http://insecure.test/meta\""))
     (cl-letf (((symbol-function 'mcp-oauth--http)
                (lambda (_provider method _url _headers _data) (if (equal method "POST") (list 401 headers "") '(404 "" "")))))
       (should-error (mcp-oauth--protected-resource-metadata provider))))))

(ert-deftest mcp-oauth-test-only-401-bearer-challenge-is-accepted ()
  (mcp-oauth-test-with-provider
   (cl-letf (((symbol-function 'mcp-oauth--http)
              (lambda (_provider method _url _headers _data) (if (equal method "POST") '(403 "WWW-Authenticate: Bearer resource_metadata=\"https://metadata.test/x\"" "") '(404 "" "")))))
     (should-error (mcp-oauth--protected-resource-metadata provider)))))

(ert-deftest mcp-oauth-test-explicit-metadata-override-skips-probe ()
  (let* ((directory (make-temp-file "mcp-oauth-test-" t))
         (provider (mcp-oauth-create "https://mcp.example.test/v1" (list :storage-directory directory :metadata-url "https://override.test/meta"))) calls)
    (unwind-protect
        (cl-letf (((symbol-function 'mcp-oauth--http)
                   (lambda (_provider method url _headers _data) (push (list method url) calls)
                     '(200 "" "{\"resource\":\"https://mcp.example.test/v1\",\"authorization_servers\":[\"https://issuer.test\"]}"))))
          (should (mcp-oauth--protected-resource-metadata provider))
          (should (equal calls '(("GET" "https://override.test/meta")))))
      (delete-directory directory t))))

(provide 'mcp-oauth-test)
