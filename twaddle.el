;;; twaddle.el -- a sane twitter client -*- lexical-binding: t -*-

(require 'web)
(require 'url-util) ; url-hexify-string
(require 'cl) ; for flet - we could use noflet maybe?
(require 'noflet)

(require 'elnode)

(defun twaddle-callback-handler (httpcon)
  (message "twaddle-elnode: %S" (elnode-http-query httpcon))
  (elnode-send-json httpcon '((data . "some data"))))

;;(elnode-start 'twaddle-callback-handler :port 8091)

;; This is lifted from here:
;;
;;  https://github.com/psanford/emacs-oauth/blob/master/hmac-sha1.el
;;
;; It really should be packaged
(defun twaddle/hmac-sha1 (key message)
  "Return an HMAC-SHA1 authentication code for KEY and MESSAGE.

KEY and MESSAGE must be unibyte strings.  The result is a unibyte
string.  Use the function `encode-hex-string' or the function
`base64-encode-string' to produce human-readable output."
  (when (multibyte-string-p key)
    (error "key %s must be unibyte" key))
  (when (multibyte-string-p message)
    (error "message %s must be unibyte" message))
  (let ((+hmac-sha1-block-size-bytes+ 64)) ; SHA-1 uses 512-bit blocks
    (when (< +hmac-sha1-block-size-bytes+ (length key))
      (setq key (sha1 key nil nil t)))
    (let ((key-block (make-vector +hmac-sha1-block-size-bytes+ 0)))
      (dotimes (i (length key))
        (aset key-block i (aref key i)))
      (let ((opad (make-vector +hmac-sha1-block-size-bytes+ #x5c))
            (ipad (make-vector +hmac-sha1-block-size-bytes+ #x36)))
        (dotimes (i +hmac-sha1-block-size-bytes+)
          (aset ipad i (logxor (aref ipad i) (aref key-block i)))
          (aset opad i (logxor (aref opad i) (aref key-block i))))
        (when (fboundp 'unibyte-string)
          (setq opad (apply 'unibyte-string (mapcar 'identity opad)))
          (setq ipad (apply 'unibyte-string (mapcar 'identity ipad))))
        (sha1
         (concat opad (sha1 (concat ipad message) nil nil t))
         nil nil t)))))

(defconst twaddle-consumer-key "pGyt24tDKgjja5GULbFoA")
(defconst twaddle-consumer-secret "mToqSH9MwGXAStXmOT8ZrqKycU2MUqwdHsyZeGxTAKU")
(defconst twaddle-request-token-url "https://api.twitter.com/oauth/request_token")
(defconst twaddle-authorize-url	"https://api.twitter.com/oauth/authorize")
(defconst twaddle-access-token-url "https://api.twitter.com/oauth/access_token")
(defconst twaddle-callback-url "http://nic.ferrier.me.uk/emacs-twaddle")

(defun twaddle-log (con hdr data)
  (with-current-buffer (get-buffer-create "*twitter-log*")
     (insert (format "%s %S %s\n" con hdr data))))

;; OAuth header and signature implementation
(defun* twaddle|oauth1-header-do (url
                                  &key
                                  http-params method oauth-token
                                  ;; testing params
                                  oauth-timestamp oauth-nonce)
  "Private function implementing oauth header construction."
  (let* ((oauth-params
          `(("oauth_consumer_key" . ,twaddle-consumer-key)
            ("oauth_signature_method" . "HMAC-SHA1")
            ("oauth_timestamp" . ,(or oauth-timestamp (timestamp)))
            ("oauth_nonce" . ,(or oauth-nonce (number-to-string (abs (random)))))
            ("oauth_version" . "1.0")))
         (oauth-sign-params
          (if oauth-token
              (alist "oauth-token" oauth-token oauth-params)
              oauth-params))
         (sign-params
          (append oauth-sign-params
                  (if (hash-table-p http-params) ; maybe we want cond instead
                      (kvhash->alist http-params)
                      http-params)))
         (sign-params-str (join (string-sort sign-params) "&"))
         (signature-base
          (s-format "${method}&${url}&${params}" 'aget
                    (alist "method" method
                           "url" (url-hexify-string url)
                           "params" (url-hexify-string sign-params-str))))
         (signing-key
          (concat
           (url-hexify-string twaddle-consumer-secret)
           "&"
           (when oauth-token
             (url-hexify-string oauth-token))))
         (oauth-sig 
          (base64-encode-string
            (twaddle/hmac-sha1 signing-key signature-base)))
         (oauth-sig-params (list (cons "oauth_signature" oauth-sig)))
         (oauth-header (append oauth-sign-params oauth-sig-params)))
    (cons (propertize "Authorization"
                      :sign-params sign-params-str
                      :signature-base signature-base
                      :signing-key signing-key)
          (format "OAuth %s" (join (string-sort oauth-header) "," t)))))

(defun* twaddle/oauth1-header (url &key http-params (method "GET") oauth-token
                                   oauth-timestamp oauth-nonce)
  "Return the value of the OAuth authorization header.

URL is the absolute HTTP url being requested.

HTTP-PARAMS is an alist or hashtable of additional HTTP
parameters, either POST or GET, that are going to be passed in
the request.

METHOD is the HTTP method you will use to send the request,
\"GET\", \"POST\", \"PUT\", \"DELETE\", etc...

OAUTH-TOKEN is an optional OAuth token.

This process is documented here:

  http://oauth.net/core/1.0/#signing_process

The implementation of this function is largely provided by
`twaddle|oauth1-header'.

The return value is the string OAuth header."
  ;; Setup some functions to make the implemetation simpler
  (noflet ((string-sort (lst)
             (sort lst (lambda (a b)
                         (string-lessp (car a) (car b)))))
           (timestamp () ; pinched from psandford's oauth.el
             (format "%d" (ftruncate (float-time (current-time)))))
           (join (param-list joiner &optional quote)
             (mapconcat
              (lambda (cell)
                (format
                 "%s=%s"
                 (car cell)
                 (if quote
                     (format "\"%s\"" 
                             (url-hexify-string (cdr cell)))
                     (url-hexify-string (cdr cell)))))
              param-list joiner))
           (alist (&rest conses) ; possible kv function
             (loop for cell on conses by 'cddr
                if (cdr cell)
                collect (cons (car cell) (cadr cell))
                else append (car cell))))
    (funcall 'twaddle|oauth1-header-do url
             :http-params http-params
             :method method
             :oauth-token oauth-token
             :oauth-timestamp oauth-timestamp
             :oauth-nonce oauth-nonce)))

(defun twaddle/request ()
  (let ((url twaddle-request-token-url))
    (web-http-post
     (web-handler (con hdr data)
       (200
        (let ((oauth-resp (url-parse-query-string data)))
          (twaddle-log con (format "%S" oauth-resp) "")
          (browse-url
           (format
            "https://api.twitter.com/oauth/authenticate?oauth_token=%s"
            (cadr (assoc "oauth_token" oauth-resp))))))
       (401 
        (twaddle-log con (format "%S" (kvhash->alist hdr)) data)))
     :url url
     :extra-headers
     (list (twaddle/oauth1-header url :method "POST"))
     :logging t)))

(twaddle/request)

;;; twaddle.el ends here
