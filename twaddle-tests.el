
;; This is an example from http://oauth.net/core/1.0/#encoding_parameters
(defun twaddle/test-oauth-spec-encoding ()
  (let ((signature-base "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal")
        (signing-key "kd94hf93k423kf44&pfkkdhi9sl3r4s00"))
    (assert
     (equal
      (base64-encode-string
       (twaddle/hmac-sha1 signing-key signature-base))
      "tR3+Ty81lMeYAr/Fid0kMTYa/WM="))))


;; example from here: https://dev.twitter.com/docs/auth/implementing-sign-twitter

;; POST /oauth/request_token HTTP/1.1
;; User-Agent: themattharris' HTTP Client
;; Host: api.twitter.com
;; Accept: */*
;; Authorization: 
;; OAuth oauth_callback="http%3A%2F%2Flocalhost%2Fsign-in-with-twitter%2F",
;;       oauth_consumer_key="cChZNFj6T5R0TigYB9yd1w",
;;       oauth_nonce="ea9ec8429b68d6b77cd5600adbbb0456",
;;       oauth_signature="F1Li3tvehgcraF8DMJ7OyxO4w9Y%3D",
;;       oauth_signature_method="HMAC-SHA1",
;;       oauth_timestamp="1318467427",
;;       oauth_version="1.0"

;; Here's some code - we're struggling to generate the same signature
(princ
 (let* ((twaddle-consumer-secret "L8qq9PZyRg6ieKGEKhZolGC0vJWLw8iEJ88DRdyOg")
        (twaddle-consumer-key "cChZNFj6T5R0TigYB9yd1w")
        (hdr-cons 
         (twaddle/oauth1-header
          "http://api.twitter.com/oauth/request"
          :method "POST"
          :http-params '(("oauth_callback" . "http://localhost/sign-in-with-twitter/"))
          :oauth-nonce "ea9ec8429b68d6b77cd5600adbbb0456"
          :oauth-timestamp "1318467427")))
   (format "%s:\n\t %s\n%S\n%S\n%S\n"
           (car hdr-cons)
           (cdr hdr-cons)
           (get-text-property 0 :sign-params (car hdr-cons))
           (get-text-property 0 :signature-base (car hdr-cons))
           (get-text-property 0 :signing-key (car hdr-cons))))
 (current-buffer))

Authorization:
OAuth
oauth_consumer_key="cChZNFj6T5R0TigYB9yd1w",
oauth_nonce="ea9ec8429b68d6b77cd5600adbbb0456",
oauth_signature="iYMxGdJBph5OXkK%2Fj%2F4ZOzKFuvk%3D",
oauth_signature_method="HMAC-SHA1",
oauth_timestamp="1318467427",
oauth_version="1.0"

"oauth_callback=http%3A%2F%2Flocalhost%2Fsign-in-with-twitter%2F&oauth_consumer_key=cChZNFj6T5R0TigYB9yd1w&oauth_nonce=ea9ec8429b68d6b77cd5600adbbb0456&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1318467427&oauth_version=1.0"

"POST&http%3A%2F%2Fapi.twitter.com%2Foauth%2Frequest&oauth_callback%3Dhttp%253A%252F%252Flocalhost%252Fsign-in-with-twitter%252F%26oauth_consumer_key%3DcChZNFj6T5R0TigYB9yd1w%26oauth_nonce%3Dea9ec8429b68d6b77cd5600adbbb0456%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318467427%26oauth_version%3D1.0"
"L8qq9PZyRg6ieKGEKhZolGC0vJWLw8iEJ88DRdyOg&"




