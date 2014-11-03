;;; twaddle.el --- a sane twitter client -*- lexical-binding: t -*-

;; Copyright (C) 2014  Nic Ferrier

;; Author: Nic Ferrier <nferrier@ferrier.me.uk>
;; Keywords: lisp
;; Version: 0.0.1
;; Url: https://github.com/nicferrier/emacs-twaddle
;; Package-requires: ((kv "0.0.19")(dash "2.9.0")(shadchen "1.4")(noflet "0.0.15")(web "0.5.1")(elnode "0.9.9.8.8"))

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <http://www.gnu.org/licenses/>.

;;; Commentary:

;; A modern twitter client for Emacs.

;; Twitter oauth stuff resources

;; https://dev.twitter.com/web/sign-in/implementing
;; https://apps.twitter.com/app/4519285/show - Nic's keys, presumably you can't see this.

;;; Code:

(require 'web)
(require 'url-util) ; url-hexify-string
(require 'cl-lib)
(require 'noflet)
(require 'elnode)
(require 'kv)
(require 'shadchen)
(require 'eww)
(require 'dash)

(defun twaddle/log (str &rest vars)
  "Helps with debugging."
  (with-current-buffer (get-buffer-create "*twitter-log*")
    (goto-char (point-max))
    (insert (apply 'format str vars) "\n")))


;;; Wrap web to make a simpler client for twitter

(cl-defun twaddle/web (handler url params
                               &key
                               (method "POST")
                               oauth-token
                               oauth-token-secret)
  "Specific web client eases the creation of oauth header."
  (let* ((oauth-header
          (twaddle/oauth1-header
           url
           :method method
           :http-params params
           :oauth-token oauth-token
           :oauth-token-secret oauth-token-secret))
         (hdrs (list
                oauth-header
                (cons "User-Agent" "emacs-twaddle"))))
    (if (equal method "POST")
        (web-http-post
         handler
         :url url :data params
         :extra-headers hdrs :logging t)
        (web-http-get
         handler
         :url (concat url "?" (web-to-query-string params))
         :extra-headers hdrs :logging t))))


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


;;; Twaddle OAuth

(defconst twaddle-consumer-key  "jPzM4OZODLvdCSvsiCEPrg")
(defconst twaddle-consumer-secret "PU2P33dfkyj1lguf2SZ71TcTVxulLUppReGHuk5aE8")

(defconst twaddle-authorize-url	"https://api.twitter.com/oauth/authorize")

(defun twaddle/timestamp () ; pinched from psandford's oauth.el
  (format "%d" (ftruncate (float-time (current-time)))))

(defun twaddle/join (param-list joiner &optional quote)
  (let ((sorted
         (--sort
          (string-lessp (car it) (car other))
          param-list)))
    (mapconcat
     (lambda (cell)
       (format
        "%s=%s"
        (car cell)
        (if quote
            (format "\"%s\"" 
                    (url-hexify-string (cdr cell)))
            (url-hexify-string (cdr cell)))))
     sorted
     joiner)))

(defun twaddle/conses->alist (&rest conses) ; possible kv function
  "Make a list of pairs into an alist:

For example:  'a 1 'b 2 'c 3 => '((a . 1)(b . 2)(c . 3))"
  (loop for cell on conses by 'cddr
     if (cdr cell)
     collect (cons (car cell) (cadr cell))
     else append (car cell)))

(cl-defun twaddle/oauth1-get-sig-base (method url http-params
                                              &key
                                              oauth-token
                                              oauth-token-secret
                                              oauth-nonce
                                              oauth-timestamp)
  "Make the signature base.

Returns a list of: 

  the signature base
  the oauth-params 
  the sign-params-str.

Whcih normally you destructure with some matching let like
`destructuring-bind' or `-let' or `match-let'."
  (let* ((oauth-params
          `(("oauth_consumer_key" . ,twaddle-consumer-key)
            ("oauth_signature_method" . "HMAC-SHA1")
            ("oauth_timestamp" . ,(or oauth-timestamp (twaddle/timestamp)))
            ("oauth_nonce" . ,(or oauth-nonce (number-to-string (abs (random)))))
            ("oauth_version" . "1.0")))
         (oauth-sign-params
          (if oauth-token
              (twaddle/conses->alist "oauth_token" oauth-token oauth-params)
              oauth-params))
         (sign-params
          (append oauth-sign-params
                  (if (hash-table-p http-params) ; maybe we want cond instead
                      (kvhash->alist http-params)
                      http-params)))
         (sign-params-str (twaddle/join sign-params "&"))
         (signature-base
          (s-format "${method}&${url}&${params}" 'aget
                    (twaddle/conses->alist
                     "method" method
                     "url" (url-hexify-string url)
                     "params" (url-hexify-string sign-params-str)))))
    (list signature-base oauth-sign-params sign-params-str)))

;; OAuth header and signature implementation
(cl-defun twaddle/oauth1-header-do (url
                                    &key
                                    http-params
                                    method
                                    oauth-token
                                    oauth-token-secret
                                    ;; testing params
                                    oauth-timestamp
                                    oauth-nonce)
  "Private function implementing oauth header construction."
  (match-let
   (((list signature-base oauth-sign-params sign-params-str)
     (twaddle/oauth1-get-sig-base
      method url http-params
      :oauth-token oauth-token
      :oauth-timestamp oauth-timestamp
      :oauth-nonce oauth-nonce)))
   (let* ((signing-key (concat
                        (url-hexify-string twaddle-consumer-secret)
                        "&"
                        (when (or oauth-token oauth-token-secret)
                          (concat
                           (url-hexify-string (or oauth-token-secret oauth-token))))))
          (oauth-sig (base64-encode-string
                      (twaddle/hmac-sha1 signing-key signature-base)))
          (oauth-sig-params (list (cons "oauth_signature" oauth-sig)))
          (oauth-header (append oauth-sign-params oauth-sig-params))
          (oauth-header-cons (cons (propertize
                                    "Authorization"
                                    :sign-params sign-params-str
                                    :signature-base signature-base
                                    :signing-key signing-key)
                                   (format "OAuth %s"
                                           (twaddle/join oauth-header ", " t)))))
     (twaddle/log "%S" (cdr oauth-header-cons))
     oauth-header-cons)))

(cl-defun twaddle/oauth1-header (url
                                 &key
                                 http-params
                                 (method "GET")
                                 oauth-token
                                 oauth-token-secret
                                 oauth-timestamp
                                 oauth-nonce)
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
`twaddle/oauth1-header-do'.

The return value is the string OAuth header."
  (twaddle/oauth1-header-do url
                            :http-params http-params
                            :method method
                            :oauth-token oauth-token
                            :oauth-token-secret oauth-token-secret
                            :oauth-timestamp oauth-timestamp
                            :oauth-nonce oauth-nonce))

(defvar twaddle/auth-details nil
  "Stores the twaddle auth details.")

(defconst twaddle/access-token-url "https://api.twitter.com/oauth/access_token")

(defun twaddle-callback-handler (httpcon)
  "Twaddle OAUTH callback handler.

It fires off the access token confirmation request to twitter and
then sends HTML back to eww."
  (twaddle/log "elnode got: %S"
               (elnode-http-params httpcon))
  (match-let (((alist "oauth_verifier" verifier
                      "oauth_token" oauth-token)
               (elnode-http-params httpcon)))
    (twaddle/web
     (lambda (con hdr data)
       (let ((alist (elnode-http-query-to-alist data)))
         (setq twaddle/auth-details alist)))
     twaddle/access-token-url `(("oauth_verifier" . ,verifier))
     :oauth-token oauth-token)
    (elnode-send-html
     httpcon
     (format
      "<h1>thanks! twaddle should be working in your emacs now!</h1><pre>%S</pre>"
      (list verifier oauth-token)))))

(defun twaddle/auth-handle (con hdr data)
  (case (string-to-int (gethash 'status-code hdr))
    (200
     (let ((oauth-resp (url-parse-query-string data)))
       (twaddle/log "%s %S %s" con oauth-resp data)
       (eww
        (format
         "https://api.twitter.com/oauth/authenticate?oauth_token=%s"
         (cadr (assoc "oauth_token" oauth-resp))))))
    (401 
     (twaddle/log "%S %s" (kvhash->alist hdr) data))))

(defconst twaddle-request-token-url "https://api.twitter.com/oauth/request_token")

(defun twaddle/auth-start ()
  (let ((url twaddle-request-token-url)
        (callback "http://localhost:8091/emacs_twaddle"))
    (twaddle/web 'twaddle/auth-handle url `(("oauth_callback" . ,callback)))))


;;; Timeline functions

(defvar twaddle/twitter-result nil
  "A buffer-local of the last result from twitter.")

(defvar twaddle/twitter-timeline nil
  "A buffer-local for the timeline you're viewing.")

(defvar twaddle/twitter-last-marker nil
  "A buffer-local for the position before the next results.")

(defun fill-string (str)
  (with-temp-buffer
    (insert str)
    (fill-paragraph)
    (buffer-string)))

(defun twaddle/get-twitter-buffer ()
  (let ((buf (get-buffer "*twaddle-twitter*")))
    (unless buf
      (with-current-buffer (setq buf (get-buffer-create "*twaddle-twitter*"))
        (twaddle-timeline-mode)))
    buf))

(defun twaddle/text-munge (text)
  "Do some basic conversions for text."
  (when text
    (let ((replacements '(("&amp;" . "&")
                          ("&lt;" . "<")
                          ("&gt;" . ">")))
          (decoded (decode-coding-string text 'utf-8)))
      (fill-string
       (replace-regexp-in-string
        "&amp;\\|&lt;\\|&gt;"
        (lambda (s) (kva s replacements))
        decoded)))))

(defun twaddle-timeline-source ()
  "Display the source of the current twitter view.

The JSON source is pretty printed into another buffer which is
popped for you.

This is mostly useful for debugging."
  (interactive)
  (let ((src twaddle/twitter-result))
    (with-current-buffer (get-buffer-create "*twaddle-twitter-source*")
      (insert (pp-to-string src))
      (pop-to-buffer (current-buffer)))))

(defun twaddle/twitter-buffer (timeline json)
  "Display the JSON for TIMELINE."
  (with-current-buffer (twaddle/get-twitter-buffer)
    (let ((buffer-read-only nil)
          (results (json-read-from-string json)))
      (setq twaddle/twitter-result results)
      (setq twaddle/twitter-timeline timeline)
      (save-excursion
        (goto-char (point-min))
        (setq twaddle/twitter-last-marker (point-marker))
        (set-marker-insertion-type twaddle/twitter-last-marker t)
        (--each (append results nil)
          (match it
            ((alist 'text text
                    'id_str tweet-id
                    'user (alist 'screen_name username
                                 'profile_image_url avatar-url))
             (insert
              (propertize
               (s-format
                "\n${text}¶\nː${user}\n"  ;; unicode here
                'aget
                `(("text" . ,(twaddle/text-munge text))
                  ("user" . ,username)))
               :tweet-id tweet-id))
             (let ((img-insert (point-marker)))
               (web-http-get
                (lambda (con hdr data)
                  (with-current-buffer (get-buffer "*twaddle-twitter*")
                    (save-excursion
                      (goto-char img-insert)
                      (forward-line -1)
                      (goto-char (line-beginning-position))
                      (let ((buffer-read-only nil))
                        (insert-image
                         (create-image
                          (string-as-unibyte data)
                          (kva (file-name-extension avatar-url)
                               '(("png" . png)
                                 ("jpg" . jpeg)
                                 ("jpeg" . jpeg)
                                 ("gif" . 'gif))) t))
                        (insert "  ")))))
                :url avatar-url)))))))
    (pop-to-buffer (current-buffer))))

(defun twaddle-timeline-next-link ()
  "Move to the next link in the timeline view."
  (interactive)
  ;; letn is from noflet
  (letn seek ((pt (next-single-property-change (point) 'face)))
    (if pt
        (if (eq (get-text-property pt 'face) 'link)
            (goto-char pt)
            (seek (next-single-property-change pt 'face)))
        (goto-char (point-min))
        (seek (next-single-property-change (point) 'face)))))

(defun twaddle-timeline-home ()
  "Move to the top of the timeline view."
  (interactive)
  (set-window-point (selected-window) (point-min)))

(defun twaddle-timeline-last ()
  (interactive)
  (goto-char twaddle/twitter-last-marker))

(defun twaddle-timeline-pull-next ()
  "Pull the next tweets."
  (interactive)
  (twaddle/status-get twaddle/twitter-timeline (current-buffer)))

(defconst twaddle/timeline-mode-map
  (let ((map (make-keymap)))
    (define-key map (kbd "RET") 'browse-url-at-point)
    (define-key map (kbd "TAB") 'twaddle-timeline-next-link)
    (define-key map (kbd "H") 'twaddle-timeline-home)
    (define-key map (kbd " ") 'twaddle-timeline-last)
    (define-key map (kbd "S") 'twaddle-timeline-source)
    (define-key map (kbd "g") 'twaddle-timeline-pull-next)
    map)
  "The timeline mode map.")

(define-derived-mode twaddle-timeline-mode
    special-mode "Twaddle"
    "Twitter timelines

\\{twaddle/timeline-mode-map}"
    (make-variable-buffer-local 'twaddle/twitter-result)
    (make-variable-buffer-local 'twaddle/twitter-timeline)
    (make-variable-buffer-local 'twaddle/twitter-last-marker)
    (setq buffer-read-only t)
    (setq font-lock-defaults
          '((("\\(http\\(s\\)*://[^ ¶\n]+\\)" . 'link)
             ("\\(@[^A-Za-z0-9_]+\\)" . 'bold)
             ("\\(\"[^¶\"]+[\"¶]\\)" . 'font-lock-string-face) ; make strings terminate on tweet end
             ("¶" . 'shadow)
             ("ː[^\n]+\n" . 'shadow))
            t))
    (use-local-map twaddle/timeline-mode-map))

(defconst twaddle/twitter-status-home
  "https://api.twitter.com/1.1/statuses/%s.json"
  "Format string for status requests.

Possible values for the %s are \"user_timeline\",
\"mentions_timeline\", \"home_timeline\".

See
`https://dev.twitter.com/rest/reference/get/statuses/mentions_timeline'
for more details.")

(defun twaddle/status-get (timeline &optional since-buffer)
  (twaddle/web
   (lambda (con hdr data) (twaddle/twitter-buffer timeline data))
   (format twaddle/twitter-status-home timeline)
   (-filter
    #'identity
    `(("screen_name" . ,(kva "screen_name" twaddle/auth-details))
      ,(if since-buffer
           (with-current-buffer since-buffer
             (cons "since-id"
                   (kva 'id_str (elt twaddle/twitter-result 0))))
           '("count" . "10"))))
   :method "GET"
   :oauth-token (kva "oauth_token" twaddle/auth-details)
   :oauth-token-secret (kva "oauth_token_secret" twaddle/auth-details)))

(defconst twaddle/twitter-update "https://api.twitter.com/1.1/statuses/update.json"
  "The update URL.")

(defun twaddle-post (status &optional reply)
  (interactive (list (read-from-minibuffer "Status: ")))
  (twaddle/web
   (lambda (con hdr data)
     (with-current-buffer (get-buffer-create "*twaddle-update*")
       (goto-char (point-min))
       (insert (format "%S" data))
       (pop-to-buffer (current-buffer))))
   twaddle/twitter-update
   `(("status" . ,status))
   :oauth-token (kva "oauth_token" twaddle/auth-details)
   :oauth-token-secret (kva "oauth_token_secret" twaddle/auth-details)))

(defun twaddle-init ()
  (interactive)
  ;; we start elnode to collect the callback
  (elnode-start 'twaddle-callback-handler :port 8091)
  (twaddle/auth-start))

(defun twaddle ()
  (interactive)
  (twaddle/status-get "home_timeline"))

;;; twaddle.el ends here
