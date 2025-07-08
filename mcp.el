;;; mcp.el --- Model Context Protocol                -*- lexical-binding: t; -*-

;; Copyright (C) 2025  lizqwer scott

;; Author: lizqwer scott <lizqwerscott@gmail.com>
;; Version: 0.1.0
;; Package-Requires: ((emacs "30.1") (jsonrpc "1.0.25"))
;; Keywords: tools
;; URL: https://github.com/lizqwerscott/mcp.el

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <https://www.gnu.org/licenses/>.

;;; Commentary:

;; mcp is an Emacs client for interfacing with
;; [MCP](https://modelcontextprotocol.io/introduction), supporting
;; connections to MCP servers.
;;
;; Features:
;;
;; - Structured communication with MCP servers
;; - Support for filesystem and generic MCP servers
;; - Extensible tool and prompt system
;; - Asynchronous and synchronous operations
;; - Resource management capabilities
;; - Intuitive interface for managing server lifecycle (start/stop/restart)
;; - Integration with popular Emacs packages (e.g., gptel, llm)
;;
;; Usage:
;; - config `mcp-hub-servers'
;; - call `mcp-hub' to start mcp servers

;;; Code:

(require 'jsonrpc)
(require 'cl-lib)
(require 'url)

(defconst mcp--support-versions (list "2025-03-26" "2024-11-05")
  "MCP support version.")

(defcustom mcp-server-start-time 60
  "The Seconds of mcp server start time."
  :group 'mcp
  :type 'integer)

(defcustom mcp-server-wait-initial-time 2
  "Seconds to wait after server init before fetching MCP resources.

This delay is applied after server initialization completes, but
before requesting tools, prompts and resources. Gives the server
time to fully initialize all components before handling requests."
  :group 'mcp
  :type 'integer)

(defcustom mcp-log-level 'info
  "The min log level for mcp server.
Available levels:
- debug: Detailed debugging information (function entry/exit points)
- info: General informational messages (operation progress updates)
- notice: Normal but significant events (configuration changes)
- warning: Warning conditions (deprecated feature usage)
- error: Error conditions (operation failures)
- critical: Critical conditions (system component failures)
- alert: Action must be taken immediately (data corruption detected)
- emergency: System is unusable (complete system failure)"
  :group 'mcp
  :type '(choice (const :tag "debug" debug)
          (const :tag "info" info)
          (const :tag "notice" notice)
          (const :tag "warning" warning)
          (const :tag "error" error)
          (const :tag "critical" critical)
          (const :tag "alert" alert)
          (const :tag "emergency" emergency)))

(defcustom mcp-log-size nil
  "Maximum size for logging jsonrpc event.  0 disables, nil means infinite."
  :group 'mcp
  :type 'integer)

(defclass mcp-process-connection (jsonrpc-process-connection)
  ((connection-type
    :initarg :connection-type
    :accessor mcp--connection-type)
   (-status
    :initform 'init
    :accessor mcp--status)
   (-capabilities
    :initform nil
    :accessor mcp--capabilities)
   (-serverinfo
    :initform nil
    :accessor mcp--server-info)
   (-prompts
    :initform nil
    :accessor mcp--prompts)
   (-tools
    :initform nil
    :accessor mcp--tools)
   (-resources
    :initform nil
    :accessor mcp--resources)
   (-template-resources
    :initform nil
    :accessor mcp--template-resources)
   (-initial-callback
    :initarg :initial-callback
    :accessor mcp--initial-callback)
   (-prompts-callback
    :initarg :prompts-callback
    :accessor mcp--prompts-callback)
   (-tools-callback
    :initarg :tools-callback
    :accessor mcp--tools-callback)
   (-resources-callback
    :initarg :resources-callback
    :accessor mcp--resources-callback)
   (-resources-templates-callback
    :initarg :resources-templates-callback
    :accessor mcp--resources-templates-callback)
   (-error-callback
    :initarg :error-callback
    :accessor mcp--error-callback))
  :documentation "A MCP connection over an Emacs process.")

(defclass mcp-http-process-connection (mcp-process-connection)
  ((-host
    :initarg :host
    :accessor mcp--host)
   (-port
    :initarg :port
    :accessor mcp--port)
   (-path
    :initarg :path
    :accessor mcp--path)
   (-tls
    :initarg :tls
    :accessor mcp--tls)
   (-sse
    :initform nil
    :accessor mcp--sse)
   (-endpoint
    :initform nil
    :accessor mcp--endpoint)
   (-session-id
    :initform nil
    :accessor mcp--session-id)
   (-running
    :initform t
    :accessor mcp--running))
  :documentation "A sse MCP connection over an Emacs process.")

(defclass mcp-stdio-process-connection (mcp-process-connection)
  ()
  :documentation "A stdio MCP connection over an Emacs process.")

(cl-defmethod initialize-instance :after ((_ mcp-process-connection) slots)
  "Init mcp process connection."
  (cl-destructuring-bind (&key ((:process proc)) &allow-other-keys) slots
    (set-process-filter proc #'mcp--process-filter)))

(cl-defmethod initialize-instance :around ((conn mcp-http-process-connection) slots)
  "Init mcp process connection."
  (shared-initialize conn slots)
  (setf (jsonrpc--process conn) nil))

(cl-defmethod jsonrpc-running-p ((conn mcp-http-process-connection))
  "Return non-nil if JSONRPC connection CONN is running."
  (mcp--running conn))

(cl-defmethod jsonrpc-shutdown :after ((conn mcp-http-process-connection))
  "Return non-nil if JSONRPC connection CONN is running."
  (setf (mcp--running conn) nil))

(defun mcp--parse-http-header (headers)
  "Parse HTTP response headers into a plist.

HEADERS is a string containing the raw HTTP response headers.
Returns a plist where each header field is a keyword (e.g. :content-type)
with its corresponding value.

Example:
  (mcp--parse-http-header \"Content-Type: text/html\\r\\nServer: nginx\\r\\n\")
  => (:content-type \"text/html\" :server \"nginx\")"
  (when-let* ((header-lines (split-string headers "\n"))
              (status-line (car header-lines))
              (res (split-string status-line " "))
              (status-code (elt res 1)))
    (plist-put (apply #'append
                      (mapcar (lambda (line)
                                (when-let* ((line (string-trim line))
                                            (search-sep-pos (string-search ":" line)))
                                  (list (intern
                                         (concat ":"
                                                 (downcase
                                                  (string-trim
                                                   (substring line 0 search-sep-pos)))))
                                        (string-trim
                                         (substring line
                                                    (+ search-sep-pos 1))))))
                              (cdr header-lines)))
               :response-code
               status-code)))

(cl-defmethod jsonrpc-connection-send ((connection mcp-process-connection)
                                       &rest args
                                       &key
                                       id
                                       method
                                       _params
                                       (_result nil result-supplied-p)
                                       error
                                       _partial)
  "Send JSON-RPC message to CONNECTION.
CONNECTION is an MCP process connection instance. ARGS is a plist
containing the message components:

METHOD - Method name (string, symbol or keyword)
PARAMS - Parameters for the method (optional)
ID     - Request ID (optional)
RESULT - Response result (for replies)
error   - Error object (for error replies)
partial - Partial response flag (optional)

For requests, both :method and :id should be provided.
For notifications, only :method is required.
For replies, either :_result or :error should be provided.

The message is sent differently based on connection type:
- SSE connections use HTTP POST requests
- Stdio connections write directly to the process"
  (when method
    ;; sanitize method into a string
    (setq args
          (plist-put args :method
                     (cond ((keywordp method) (substring (symbol-name method) 1))
                           ((symbolp method) (symbol-name method))
                           ((stringp method) method)
                           (t (error "[jsonrpc] invalid method %s" method))))))
  (let* ((kind (cond ((or result-supplied-p error) 'reply)
                     (id 'request)
                     (method 'notification)))
         (converted (jsonrpc-convert-to-endpoint connection args kind))
         (json (json-serialize converted
                               :false-object :json-false
                               :null-object :json-null)))
    (pcase (mcp--connection-type connection)
      ('http
       (let ((url-request-method "POST")
             (url-request-extra-headers
              `(("Content-Type" . "application/json")
                ,@(when-let* ((session-id (mcp--session-id connection)))
                    `(("Mcp-Session-Id" . ,session-id)))))
             (url-request-data (encode-coding-string
                                json
                                'utf-8))
             (url-mime-accept-string "text/event-stream, application/json")
             (url (format "%s://%s:%s%s"
                          (if (mcp--tls connection) "https" "http")
                          (mcp--host connection)
                          (mcp--port connection)
                          (if-let* ((endpoint (mcp--endpoint connection)))
                              endpoint
                            (mcp--path connection)))))
         (with-current-buffer
             (url-retrieve url
                           (lambda (_)
                             (when (buffer-live-p (current-buffer))
                               (goto-char (point-min))
                               (when (search-forward "\n\n" nil t)
                                 (let* ((headers (buffer-substring (point-min) (point)))
                                        (body (buffer-substring (point) (point-max)))
                                        (headers-plist (mcp--parse-http-header headers))
                                        (session-id (plist-get headers-plist :mcp-session-id))
                                        (response-code (plist-get headers-plist :response-code)))
                                   (when (string= "4"
                                                  (substring response-code 0 1))
                                     (setf (mcp--sse connection) t))
                                   (when session-id
                                     (setf (mcp--session-id connection)
                                           session-id))
                                   ;; connect sse
                                   (unless (jsonrpc--process connection)
                                     (mcp--connect-sse connection))
                                   (unless (mcp--sse connection)
                                     (when-let* ((content-type (plist-get headers-plist :content-type)))
                                       (when (string= content-type "text/event-stream")
                                         (let ((data)
                                               (json))
                                           (dolist (line (split-string body "\n"))
                                             (cond
                                              ((string-prefix-p "data: " line)
                                               (setq data (string-trim (substring line 5))))))
                                           (condition-case-unless-debug err
                                               (setq json (json-parse-string data
                                                                             :object-type 'plist
                                                                             :null-object nil
                                                                             :false-object :json-false))
                                             (json-parse-error
                                              ;; parse error and not because of incomplete json
                                              (jsonrpc--warn "Invalid JSON: %s\t %s" (cdr err) data)))
                                           (when json
                                             (jsonrpc-connection-receive connection json))))))))
                               (kill-buffer))))
           (set (make-local-variable 'url-mime-accept-string) url-mime-accept-string))))
      ('stdio
       (process-send-string
        (jsonrpc--process connection)
        (format "%s\r\n" json))))
    (jsonrpc--event
     connection
     'client
     :json json
     :kind  kind
     :message args
     :foreign-message converted)))

(defvar mcp--in-process-filter nil
  "Non-nil if inside `mcp--process-filter'.")

(cl-defun mcp--process-filter (proc string)
  "Called when new data STRING has arrived for PROC."
  (when mcp--in-process-filter
    ;; Problematic recursive process filters may happen if
    ;; `jsonrpc-connection-receive', called by us, eventually calls
    ;; client code which calls `process-send-string' (which see) to,
    ;; say send a follow-up message.  If that happens to writes enough
    ;; bytes for pending output to be received, we will lose JSONRPC
    ;; messages.  In that case, remove recursiveness by re-scheduling
    ;; ourselves to run from within a timer as soon as possible
    ;; (bug#60088)
    (run-at-time 0 nil #'mcp--process-filter proc string)
    (cl-return-from mcp--process-filter))
  (when (buffer-live-p (process-buffer proc))
    (with-current-buffer (process-buffer proc)
      (let* ((conn (process-get proc 'jsonrpc-connection))
             (type (mcp--connection-type conn))
             (queue (or (process-get proc 'jsonrpc-mqueue) nil))
             (buf (or (process-get proc 'jsonrpc-pending)
                      (plist-get (process-put
                                  proc 'jsonrpc-pending
                                  (generate-new-buffer
                                   (format " *mcp-%s-jsonrpc-pending*" (jsonrpc-name conn))
                                   'inhibit-hooks))
                                 'jsonrpc-pending)))
             (message-rest-size (or (process-get proc 'jsonrpc-message-rest-size)
                                    0))
             (data (if (equal type 'stdio)
                       (with-current-buffer buf
                         (goto-char (point-max))
                         (insert string)
                         (buffer-string))
                     string))
             (parsed-messages nil)
             (separator (if (equal type 'stdio)
                            "\n"
                          (if (mcp--sse conn)
                              "\r\n\r\n"
                            "\n\n")))
             (data-blocks (split-string data separator)))
        (dolist (data-block data-blocks)
          (let ((data-block (string-trim data-block)))
            (unless (string-empty-p data-block)
              (pcase type
                ('http
                 (if (string-prefix-p "HTTP" data-block)
                     (if-let* ((headers (mcp--parse-http-header data-block))
                               (response-code (plist-get headers :response-code))
                               (content-type (or (plist-get headers :content-type) "")))
                         (when (or (not (string= response-code "200"))
                                   (not (string-match "text/event-stream" content-type)))
                           ;; sse not connect success
                           (message "sse not connect, return code: %s" response-code))
                       ;; can't parse headers
                       (message "can't parse headers: %s" data-block))
                   (if (= 0 message-rest-size)
                       (let* ((data-line (split-string data-block "\n"))
                              (data-size-line (cl-first data-line))
                              (event-line (cl-second data-line))
                              (id-line (when-let* ((id-line (cl-third data-line)))
                                         (if (string-prefix-p "id" id-line)
                                             id-line)))
                              (data-body (if id-line
                                             (cl-fourth data-line)
                                           (cl-third data-line)))
                              (data (when data-body
                                      (string-trim (substring data-body 6)))))
                         (when-let* ((event-line event-line)
                                     (data-size (string-to-number (string-trim data-size-line)
                                                                  16))
                                     (event-type (if (string-prefix-p ": ping" event-line)
                                                     'ping
                                                   (intern (string-trim (substring event-line 6)))))
                                     (body-size (let ((len 0))
                                                  (dolist (i (cdr data-line)) (setq len (+ len (length i))))
                                                  (+ len (length (cdr data-line)) -1)))
                                     (rest-size (- data-size
                                                   2 ; \r\n after data-size
                                                   ;; only sse need add 2
                                                   (if (mcp--sse conn)
                                                       2 ; \r\n after the last data-line
                                                     0)
                                                   body-size)))
                           (pcase event-type
                             ('endpoint
                              (let* ((endpoint (if (string-match "http://[^/]+\\(/[^[:space:]]+\\)" data)
                                                   (match-string 1 data)
                                                 data)))
                                (unless (mcp--endpoint conn)
                                  (setf (mcp--endpoint conn) endpoint)
                                  (mcp--send-initial-message conn))))
                             ('message
                              (if (>= 0 rest-size)
                                  (push data
                                        parsed-messages)
                                (process-put proc 'jsonrpc-message-rest-size rest-size)
                                (with-current-buffer buf
                                  (goto-char (point-max))
                                  (insert data))))
                             (_))))
                     (let* ((data-block-size (length data-block))
                            (new-message-rest-size (- message-rest-size data-block-size)))
                       (process-put proc 'jsonrpc-message-rest-size new-message-rest-size)
                       (with-current-buffer buf
                         (goto-char (point-max))
                         (insert (string-trim data-block))
                         (when (= 0 new-message-rest-size)
                           (push (buffer-string)
                                 parsed-messages)
                           (erase-buffer)))))))
                ('stdio
                 (push data-block parsed-messages))))))

        (setq parsed-messages (nreverse parsed-messages))

        (when (equal type 'stdio)
          (with-current-buffer buf (erase-buffer)))
        ;; Add messages to MQUEUE
        (dolist (msg parsed-messages)
          (let ((json nil)
                (json-str (with-current-buffer buf
                            (if (= (point-min) (point-max))
                                msg
                              (goto-char (point-max))
                              (insert msg)
                              (buffer-string)))))
            (condition-case-unless-debug err
                (setq json
                      (json-parse-string json-str
                                         :object-type 'plist
                                         :null-object nil
                                         :false-object :json-false))
              (json-parse-error
               ;; parse error and not because of incomplete json
               (jsonrpc--warn "Invalid JSON: %s\t %s" (cdr err) json-str))
              (json-end-of-file
               ;; Save remaining data to pending for next processing
               (with-current-buffer buf
                 (goto-char (point-max))
                 (insert json-str)
                 (process-put proc 'jsonrpc-pending buf))))
            (when json
              (when (equal type 'stdio)
                (with-current-buffer buf (erase-buffer)))
              (when (listp json)
                (setq json (plist-put json :jsonrpc-json json-str))
                (push json queue)))))

        ;; Save updated queue
        (process-put proc 'jsonrpc-mqueue queue)

        ;; Dispatch messages in timer
        (cl-loop with time = (current-time)
                 for msg = (pop queue) while msg
                 do (let ((timer (timer-create)))
                      (timer-set-time timer time)
                      (timer-set-function timer
                                          (lambda (conn msg)
                                            (with-temp-buffer
                                              (jsonrpc-connection-receive conn msg)))
                                          (list conn msg))
                      (timer-activate timer)))

        ;; Save final queue (might have been consumed by timer pop)
        (process-put proc 'jsonrpc-mqueue queue)))))

(cl-defmethod mcp--connect-sse ((conn mcp-http-process-connection))
  "Establish SSE (Server-Sent Events) connection for HTTP CONN."
  (let* ((name (jsonrpc-name conn))
         (buffer-name (format "*Mcp %s server*" name))
         (process-name (format "mcp-%s-server" name))
         (host (mcp--host conn))
         (port (mcp--port conn))
         (path (mcp--path conn))
         (proc (progn
                 (get-buffer-create buffer-name)
                 (open-network-stream process-name
                                      buffer-name
                                      host
                                      port
                                      :type (if (mcp--tls conn)
                                                'tls
                                              'network)
                                      :coding 'utf-8-unix))))
    (let* ((stderr-buffer-name (format "*%s stderr*" name))
           (stderr-buffer (jsonrpc--forwarding-buffer stderr-buffer-name "[stderr] " conn))
           (hidden-name (concat " " stderr-buffer-name)))
      (with-current-buffer stderr-buffer
        (ignore-errors (kill-buffer hidden-name))
        (rename-buffer hidden-name)
        (setq buffer-read-only t))
      (process-put proc 'jsonrpc-stderr stderr-buffer))
    (setf (jsonrpc--process conn) proc)
    (set-process-buffer proc (get-buffer-create (format " *%s output*" name)))
    (set-process-filter proc #'mcp--process-filter)
    (set-process-sentinel proc #'jsonrpc--process-sentinel)
    (with-current-buffer (process-buffer proc)
      (buffer-disable-undo)
      (set-marker (process-mark proc) (point-min))
      (let ((inhibit-read-only t))
        (erase-buffer))
      (setq buffer-read-only t))
    (process-put proc 'jsonrpc-connection conn)

    (process-send-string proc
                         (concat
                          (format "GET %s HTTP/1.1\r\n"
                                  path)
                          (format "Host: %s:%s\r\n"
                                  host
                                  port)
                          "Accept: text/event-stream\r\n"
                          (if (mcp--sse conn)
                              ""
                            (format "Mcp-Session-Id: %s\r\n"
                                    (mcp--session-id conn)))
                          "Cache-Control: no-cache\r\n"
                          "Connection: keep-alive\r\n\r\n"))))

(cl-defun mcp-notify (connection method &optional (params nil))
  "Send notification to CONNECTION without expecting response.
METHOD is the notification name (string or symbol). PARAMS is an
optional plist of parameters.
This is a thin wrapper around =jsonrpc-connection-send' that
omits the :id parameter to indicate it's a notification rather
than a request."
  (apply #'jsonrpc-connection-send
         `(,connection
           :method ,method
           ,@(when params
               (list :params params)))))

(defvar mcp-server-connections (make-hash-table :test #'equal)
  "Mcp server process.")

(defun mcp-request-dispatcher (name method params)
  "Default handler for MCP server requests.
NAME identifies the server connection. METHOD is the requested
method name. PARAMS contains the method parameters.

This basic implementation just logs the request. Applications
should override this to implement actual request handling."
  (message "%s Received request: method=%s, params=%s" name method params))

(defun mcp-notification-dispatcher (connection name method params)
  "Handle notifications from MCP server.
CONNECTION is the JSON-RPC connection object. NAME identifies the
server. METHOD is the notification name. PARAMS contains the
notification data."
  (pcase method
    ('notifications/message
     (cond ((or (plist-member (mcp--capabilities connection) :logging)
                (and (plist-member params :level)
                     (plist-member params :data)))
            (cl-destructuring-bind (&key level data &allow-other-keys) params
              (let ((logger (plist-get params :logger)))
                (message "[mcp][%s][%s]%s: %s"
                         name
                         level
                         (if logger
                             (format "[%s]" logger)
                           "")
                         data))))))
    (_
     (message "%s Received notification: method=%s, params=%s" name method params))))

(defun mcp-on-shutdown (name)
  "When NAME mcp server shutdown."
  (message "%s connection shutdown" name))

(defun mcp--parse-http-url (url)
  "Parse HTTP/HTTPS URL into connection components.
URL should be a string in format http(s)://host[:port][/path].

Returns a plist with connection parameters:
:tls   - Boolean indicating HTTPS (t) or HTTP (nil)
:host  - Server hostname (string)
:port  - Port number (integer, defaults to 80/443)
:path  - URL path component (string)

Returns nil if URL is invalid or not HTTP/HTTPS."
  (when-let* ((url (url-generic-parse-url url))
              (type (url-type url))
              (host (url-host url))
              (filename (url-filename url)))
    (when (or (string= type "http")
              (string= type "https"))
      (let ((port (url-port url))
            (tls (string= "https" type)))
        (list :tls tls
              :host host
              :port (if port
                        port
                      (if tls
                          443
                        80))
              :path filename)))))

(defun mcp--send-initial-message (connection &optional check-sse)
  "Send initialization message to MCP server CONNECTION.

This function sends the initial handshake message to establish communication
with the MCP server. It is called internally during server connection setup.

CONNECTION is the MCP connection object representing the server connection.
CHECK-SSE is an optional boolean flag indicating whether to verify is SSE
mcp server before sending."
  (mcp-async-initialize-message
   connection
   check-sse
   (lambda (protocolVersion serverInfo capabilities)
     (if (cl-find protocolVersion mcp--support-versions :test #'string=)
         (progn
           (message "[mcp] Connected! Server `MCP (%s)' now managing." (jsonrpc-name connection))
           (setf (mcp--capabilities connection) capabilities
                 (mcp--server-info connection) serverInfo)
           ;; Notify server initialized
           (mcp-notify connection
                       :notifications/initialized)
           (when (mcp--initial-callback connection)
             (funcall (mcp--initial-callback connection) connection))
           (run-with-idle-timer mcp-server-wait-initial-time
                                nil
                                (lambda ()
                                  ;; handle logging
                                  (when (plist-member capabilities :logging)
                                    (mcp-async-set-log-level connection mcp-log-level))
                                  ;; Get prompts
                                  (when (plist-member capabilities :prompts)
                                    (mcp-async-list-prompts connection (mcp--prompts-callback connection)))
                                  ;; Get tools
                                  (when (plist-member capabilities :tools)
                                    (mcp-async-list-tools connection (mcp--tools-callback connection)))
                                  ;; Get resources
                                  (when (plist-member capabilities :resources)
                                    (mcp-async-list-resources connection (mcp--resources-callback connection)))
                                  ;; Get templace resources
                                  (when (plist-member capabilities :resources)
                                    (mcp-async-list-resource-templates connection (mcp--resources-templates-callback connection)))))
           (setf (mcp--status connection) 'connected))
       (progn
         (message "[mcp] Error %s server protocolVersion(%s) not support, client Version: %s."
                  (jsonrpc-name connection)
                  protocolVersion
                  mcp--support-versions)
         (mcp-stop-server (jsonrpc-name connection)))))
   (lambda (code message)
     (mcp-stop-server (jsonrpc-name connection))
     (setf (mcp--status connection) 'error)
     (when (mcp--error-callback connection)
       (funcall (mcp--error-callback connection) code message))
     (message "Sadly, %s mpc server reports %s: %s"
              (jsonrpc-name connection) code message))))

(defun mcp--server-running-p (name)
  "Return non-nil if server NAME is in running state."
  (when-let* ((conn (gethash name mcp-server-connections)))
    (not (member (mcp--status conn) '(stop error)))))

;;;###autoload
(cl-defun mcp-connect-server (name &key command args url env initial-callback
                                   tools-callback prompts-callback
                                   resources-callback resources-templates-callback
                                   error-callback)
  "Connect to an MCP server with NAME, COMMAND, and ARGS or URL.

NAME is a string representing the name of the server.
COMMAND is a string representing the command to start the server
in stdio mcp server.
ARGS is a list of arguments to pass to the COMMAND.
URL is a string arguments to connect sse mcp server.
ENV is a plist argument to set mcp server env.

INITIAL-CALLBACK is a function called when the server completes
the connection.
TOOLS-CALLBACK is a function called to handle the list of tools
provided by the server.
PROMPTS-CALLBACK is a function called to handle the list of prompts
provided by the server.
RESOURCES-CALLBACK is a function called to handle the list of
resources provided by the server.
RESOURCES-TEMPLATES-CALLBACK is a function called to handle the list of
resources-templates provided by the server.
ERROR-CALLBACK is a function to call on error.

This function creates a new process for the server, initializes a connection,
and sends an initialization message to the server. The connection is stored
in the `mcp-server-connections` hash table for future reference."
  (unless (mcp--server-running-p name)
    (when-let* ((server-config (cond (command
                                      (list :connection-type 'stdio
                                            :command command
                                            :args args))
                                     (url
                                      (when-let* ((res (mcp--parse-http-url url)))
                                        (plist-put res
                                                   :connection-type 'http)))))
                (connection-type (plist-get server-config :connection-type))
                (buffer-name (format "*Mcp %s server*" name))
                (process-name (format "mcp-%s-server" name))
                (process (pcase connection-type
                           ('http 'empty)
                           ('stdio
                            (let ((env (mapcar (lambda (item)
                                                 (pcase-let* ((`(,key ,value) item))
                                                   (let ((key (symbol-name key)))
                                                     (list (substring key 1)
                                                           (format "%s" value)))))
                                               (seq-partition env 2)))
                                  (process-environment (copy-sequence process-environment)))
                              (when env
                                (dolist (elem env)
                                  (setenv (car elem) (cadr elem))))
                              (make-process
                               :name name
                               :command (append (list command)
                                                (plist-get server-config :args))
                               :connection-type 'pipe
                               :coding 'utf-8-unix
                               ;; :noquery t
                               :stderr (get-buffer-create
                                        (format "*%s stderr*" name))
                               ;; :file-handler t
                               ))))))
      (let ((connection (apply #'make-instance
                               `(,(pcase connection-type
                                    ('http
                                     'mcp-http-process-connection)
                                    ('stdio
                                     'mcp-stdio-process-connection))
                                 :connection-type ,connection-type
                                 :name ,name
                                 :process ,process
                                 :events-buffer-config (:size ,mcp-log-size)
                                 :request-dispatcher ,(lambda (_ method params)
                                                        (funcall #'mcp-request-dispatcher name method params))
                                 :notification-dispatcher ,(lambda (connection method params)
                                                             (funcall #'mcp-notification-dispatcher connection name method params))
                                 :on-shutdown ,(lambda (_)
                                                 (funcall #'mcp-on-shutdown name))
                                 :initial-callback ,initial-callback
                                 :prompts-callback ,prompts-callback
                                 :tools-callback ,tools-callback
                                 :resources-callback ,resources-callback
                                 :resources-templates-callback ,resources-templates-callback
                                 :error-callback ,error-callback
                                 ,@(when (equal connection-type 'http)
                                     (list :host (plist-get server-config :host)
                                           :port (plist-get server-config :port)
                                           :tls (plist-get server-config :tls)
                                           :path (plist-get server-config :path)))))))
        ;; Initialize connection
        (puthash name connection mcp-server-connections)
        ;; Send the Initialize message
        (run-with-idle-timer 1
                             nil
                             (lambda ()
                               (condition-case-unless-debug err
                                   (if (jsonrpc-running-p connection)
                                       (when (or (equal connection-type 'stdio)
                                                 (equal connection-type 'http))
                                         (mcp--send-initial-message connection t))
                                     (error "Process start error"))
                                 (error
                                  (mcp-stop-server (jsonrpc-name connection))
                                  (setf (mcp--status connection) 'error)
                                  (when error-callback
                                    (funcall error-callback -1 (format "%s" (cdr err))))
                                  (message "Sadly, %s mcp server process start error" name)))))))))

;;;###autoload
(defun mcp-stop-server (name)
  "Stop the MCP server with the given NAME.
If the server is running, it will be shutdown and its connection will be removed
from `mcp-server-connections'. If no server with the given NAME is found,
a message will be displayed indicating that the server is not running."
  (if-let* ((connection (gethash name mcp-server-connections)))
      (progn
        (ignore-errors
          (jsonrpc-shutdown connection))
        (setf (mcp--status connection) 'stop))
    (message "mcp %s server not started" name)))

(defun mcp--parse-tool-args (properties required)
  "Parse tool arguments from PROPERTIES and REQUIRED lists.

PROPERTIES is a plist of tool argument properties.
REQUIRED is a list of required argument names.

The function processes each argument in PROPERTIES, marking optional arguments
if they are not in REQUIRED. Each argument is parsed into a structured plist
with :name, :type, and :optional fields.

Returns a list of parsed argument plists."
  (let ((need-length (- (/ (length properties) 2)
                        (length required))))
    (cl-mapcar (lambda (arg-value required-name)
                 (pcase-let* ((`(,key ,value) arg-value))
                   `( :name ,(substring (symbol-name key) 1)
                      ,@value
                      ,@(unless required-name
                          `(:optional t)))))
               (seq-partition properties 2)
               (append required
                       (when (> need-length 0)
                         (make-list need-length nil))))))


(defun mcp--parse-tool-call-result (res)
  "Parse the result of a tool call from RES.

RES is a plist representing the tool call result.

The function extracts text content from the result, concatenating it into
a single string if multiple text entries are present.

Returns the concatenated text or nil if no text content is found."
  (string-join
   (cl-remove-if #'null
                 (mapcar (lambda (content)
                           (when (string= "text" (plist-get content :type))
                             (plist-get content :text)))
                         (plist-get res :content)))
   "\n"))

(defun mcp--generate-tool-call-args (args properties)
  "Generate tool call arguments from ARGS and PROPERTIES.

ARGS is a list of argument values provided by the caller.
PROPERTIES is a plist of tool argument properties.

The function matches ARGS to PROPERTIES, filling in default values for missing
optional arguments. It ensures the generated arguments match the tool's schema.

Returns a plist of argument names and values ready for tool invocation."
  (let ((need-length (- (/ (length properties) 2)
                        (length args))))
    (apply #'append
           (cl-mapcar (lambda (arg value)
                        (when-let* ((value (if value
                                               value
                                             (plist-get (cl-second arg)
                                                        :default))))
                          (list (cl-first arg)
                                value)))
                      (seq-partition properties 2)
                      (append args
                              (when (> need-length 0)
                                (make-list need-length nil)))))))

;;;###autoload
(defun mcp-make-text-tool (name tool-name &optional asyncp)
  "Create a `gptel' tool with the given NAME, TOOL-NAME, and ASYNCP.

NAME is the name of the server connection.
TOOL-NAME is the name of the tool to be created.

Currently, only synchronous messages are supported.

This function retrieves the tool definition from the server connection,
constructs a basic tool with the appropriate properties, and returns it.
The tool is configured to handle input arguments, call the server, and process
the response to extract and return text content."
  (when-let* ((connection (gethash name mcp-server-connections))
              (tools (mcp--tools connection))
              (tool (cl-find tool-name tools :test #'equal :key (lambda (tool) (plist-get tool :name)))))
    (cl-destructuring-bind (&key description ((:inputSchema input-schema)) &allow-other-keys) tool
      (cl-destructuring-bind (&key properties required &allow-other-keys) input-schema
        (list
         :function (if asyncp
                       (lambda (callback &rest args)
                         (when (< (length args) (length required))
                           (error "Error: args not match: %s -> %s" required args))
                         (if-let* ((connection (gethash name mcp-server-connections)))
                             (mcp-async-call-tool connection
                                                  tool-name
                                                  (mcp--generate-tool-call-args args properties)
                                                  (lambda (res)
                                                    (funcall callback
                                                             (mcp--parse-tool-call-result res)))
                                                  (lambda (code message)
                                                    (funcall callback
                                                             (format "call %s tool error with %s: %s"
                                                                     tool-name
                                                                     code
                                                                     message))))
                           (error "Error: %s server not connect" name)))
                     (lambda (&rest args)
                       (when (< (length args) (length required))
                         (error "Error: args not match: %s -> %s" required args))
                       (if-let* ((connection (gethash name mcp-server-connections)))
                           (if-let* ((res (mcp-call-tool connection
                                                         tool-name
                                                         (mcp--generate-tool-call-args args properties))))
                               (mcp--parse-tool-call-result res)
                             (error "Error: call %s tool error" tool-name))
                         (error "Error: %s server not connect" name))))
         :name tool-name
         :async asyncp
         :description description
         :args
         (mcp--parse-tool-args properties (or required '())))))))

(defun mcp-async-set-log-level (connection log-level)
  "Asynchronously set the log level for the MCP server.

CONNECTION is the MCP connection object.
LOG-LEVEL is the desired log level, which must be one of:
- `debug': Detailed debugging information (function entry/exit points)
- `info': General informational messages (operation progress updates)
- `notice': Normal but significant events (configuration changes)
- `warning': Warning conditions (deprecated feature usage)
- `error': Error conditions (operation failures)
- `critical': Critical conditions (system component failures)
- `alert': Action must be taken immediately (data corruption detected)
- `emergency': System is unusable (complete system failure)

On success, displays a message confirming the log level change.
On error, displays an error message with the server's response code and message."
  (jsonrpc-async-request connection
                         :logging/setLevel
                         (list :level (format "%s" log-level))
                         :success-fn
                         (lambda (res)
                           (message "[mcp] setLevel success: %s" res))
                         :error-fn (jsonrpc-lambda (&key code message _data)
                                     (message "Sadly, %s mpc server reports %s: %s"
                                              (jsonrpc-name connection) code message))))

(defun mcp-async-ping (connection)
  "Send an asynchronous ping request to the MCP server via CONNECTION.

The function uses `jsonrpc-async-request' to send a ping request.
On success, it displays a message with the response.
On error, it displays an error message with the code from the server."
  (jsonrpc-async-request connection
                         :ping
                         nil
                         :success-fn
                         (lambda (res)
                           (message "[mcp] ping success: %s" res))
                         :error-fn (jsonrpc-lambda (&key code message _data)
                                     (message "Sadly, %s mpc server reports %s: %s"
                                              (jsonrpc-name connection) code message))))

(defun mcp-async-initialize-message (connection check-sse callback &optional error-callback)
  "Sending an `initialize' request to the CONNECTION.

CONNECTION is the MCP connection object.
CHECK-SSE is an optional boolean flag indicating whether to verify is SSE
mcp server before sending.
CALLBACK is a function to call upon successful initialization.
ERROR-CALLBACK is an optional function to call if an error occurs.

This function sends an `initialize' request to the server
with the client's capabilities and version information."
  (jsonrpc-async-request connection
                         :initialize
                         `( :protocolVersion ,(car mcp--support-versions)
                            :capabilities (:roots (:listChanged t))
                            :clientInfo (:name "mcp-emacs" :version "0.1.0"))
                         :success-fn
                         (lambda (res)
                           (cl-destructuring-bind (&key protocolVersion serverInfo capabilities &allow-other-keys) res
                             (funcall callback protocolVersion serverInfo capabilities)))
                         :error-fn
                         (jsonrpc-lambda (&key code message _data)
                           (if error-callback
                               (funcall error-callback code message)
                             (message "Sadly, %s mpc server reports %s: %s"
                                      (jsonrpc-name connection) code message)))
                         :timeout mcp-server-start-time
                         :timeout-fn (lambda ()
                                       (unless (and check-sse
                                                    (mcp-http-process-connection-p connection)
                                                    (mcp--sse connection))
                                         (if error-callback
                                             (funcall error-callback 124 "timeout")
                                           (message "Sadly, mcp server (%s) timed out"
                                                    (jsonrpc-name connection)))))))

(defun mcp--async-list (connection method key-name slot-name callback error-callback)
  "Helper function to asynchronously list items from the MCP server.

CONNECTION is the MCP connection object.
METHOD is the JSON-RPC method to call (e.g., :tools/list).
KEY-NAME is the connection slot to store results (e.g., :tools).
SLOT-NAME is the connection slot to store results (e.g., -tools).
CALLBACK is a function to call with the result.
ERROR-CALLBACK is a function to call on error."
  (jsonrpc-async-request connection
                         method nil
                         :success-fn
                         (lambda (res)
                           (when-let* ((items (plist-get res key-name)))
                             (setf (slot-value connection slot-name) items)
                             (when callback
                               (funcall callback connection items))))
                         :error-fn
                         (jsonrpc-lambda (&key code message _data)
                           (if error-callback
                               (funcall error-callback code message)
                             (message "Sadly, %s mpc server reports %s: %s"
                                      (jsonrpc-name connection) code message)))))

(defun mcp-async-list-tools (connection &optional callback error-callback)
  "Get a list of tools from the MCP server using the provided CONNECTION.
CALLBACK is a function to call with the result.
ERROR-CALLBACK is a function to call on error."
  (mcp--async-list connection :tools/list :tools '-tools callback error-callback))

(defun mcp-call-tool (connection name arguments)
  "Call a tool on the remote CONNECTION with NAME and ARGUMENTS.

CONNECTION is the MCP connection object.
NAME is the name of the tool to call.
ARGGUMENTS is a list of arguments to pass to the tool."
  (jsonrpc-request connection
                   :tools/call
                   (list :name name
                         :arguments (if arguments
                                        arguments
                                      #s(hash-table)))))

(defun mcp-async-call-tool (connection name arguments callback error-callback)
  "Async Call a tool on the remote CONNECTION with NAME and ARGUMENTS.

CONNECTION is the MCP connection object.
NAME is the name of the tool to call.
ARGUMENTS is a list of arguments to pass to the tool.
CALLBACK is a function to call on success.
ERROR-CALLBACK is a function to call on error."
  (jsonrpc-async-request connection
                         :tools/call
                         (list :name name
                               :arguments (if arguments
                                              arguments
                                            #s(hash-table)))
                         :success-fn
                         (lambda (res)
                           (funcall callback res))
                         :error-fn
                         (jsonrpc-lambda (&key code message _data)
                           (funcall error-callback code message))))

(defun mcp-async-list-prompts (connection &optional callback error-callback)
  "Get list of prompts from the MCP server using the provided CONNECTION.
CALLBACK is a function to call with the result.
ERROR-CALLBACK is a function to call on error."
  (mcp--async-list connection :prompts/list :prompts '-prompts callback error-callback))

(defun mcp-get-prompt (connection name arguments)
  "Call a prompt on the remote CONNECTION with NAME and ARGUMENTS.

CONNECTION is the MCP connection object.
NAME is the name of the prompt to call.
ARGGUMENTS is a list of arguments to pass to the prompt"
  (jsonrpc-request connection
                   :prompts/get
                   (list :name name
                         :arguments (if arguments
                                        arguments
                                      #s(hash-table)))))

(defun mcp-async-get-prompt (connection name arguments callback error-callback)
  "Async Call a prompt on the remote CONNECTION with NAME and ARGUMENTS.

CONNECTION is the MCP connection object.
NAME is the name of the prompt to call.
ARGUMENTS is a list of arguments to pass to the prompt.
CALLBACK is a function to call on successful response.
ERROR-CALLBACK is a function to call on error."
  (jsonrpc-async-request connection
                         :prompts/get
                         (list :name name
                               :arguments (if arguments
                                              arguments
                                            #s(hash-table)))
                         :success-fn
                         (lambda (res)
                           (funcall callback res))
                         :error-fn
                         (jsonrpc-lambda (&key code message _data)
                           (funcall error-callback code message))))

(defun mcp-async-list-resources (connection &optional callback error-callback)
  "Get list of resources from the MCP server using the provided CONNECTION.
CALLBACK is a function to call with the result.
ERROR-CALLBACK is a function to call on error."
  (mcp--async-list connection :resources/list :resources '-resources callback error-callback))

(defun mcp-read-resource (connection uri)
  "Call a resource on the remote CONNECTION with URI.

CONNECTION is the MCP connection object.
URI is the uri of the resource to call."
  (jsonrpc-request connection
                   :resources/read
                   (list :uri uri)))

(defun mcp-async-read-resource (connection uri &optional callback error-callback)
  "Call a resource on the remote CONNECTION with URI.

CONNECTION is the MCP connection object.
URI is the URI of the resource to call.
CALLBACK is a function to call with the result on success.
ERROR-CALLBACK is a function to call with the error code and message on failure.

This function asynchronously reads a resource from the remote connection
using the specified URI. The result is passed to CALLBACK if the request
succeeds, or ERROR-CALLBACK if it fails."
  (jsonrpc-async-request connection
                         :resources/read
                         (list :uri uri)
                         :success-fn
                         (lambda (res)
                           (funcall callback res))
                         :error-fn
                         (jsonrpc-lambda (&key code message _data)
                           (funcall error-callback code message))))

(defun mcp-async-list-resource-templates (connection &optional callback error-callback)
  "Get list of resource templates from the MCP server using the CONNECTION.
CALLBACK is a function to call with the result.
ERROR-CALLBACK is a function to call on error."
  (mcp--async-list connection :resources/templates/list :templateResources '-template-resources callback error-callback))

(provide 'mcp)
;;; mcp.el ends here
