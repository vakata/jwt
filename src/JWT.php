<?php

namespace vakata\jwt;

/**
 * A class for handling JWT
 */
class JWT implements TokenInterface
{
    protected $headers = [];
    protected $claims = [];
    protected $signature = null;

    public function __construct(array $claims = [], $algo = 'HS256', $validity = 86400)
    {
        $this->headers['typ'] = 'JWT';
        $this->headers['alg'] = $algo;

        $this->setIssuedAt(time());
        $this->setExpiration(time() + $validity);
        foreach ($claims as $claim => $value) {
            $this->setClaim($claim, $value);
        }
    }

    protected function getPayload()
    {
        $head = static::base64UrlEncode(json_encode($this->headers));
        $body = static::base64UrlEncode(json_encode($this->claims));
        return $head . '.' . $body;
    }

    /**
     * Create an instance from a string token.
     * @method fromString
     * @param  string     $data the token string
     * @return \vakata\JWT\JWT           the new JWT instance
     */
    public static function fromString($data, $decryptionKey = null)
    {
        $parts = explode('.', $data);
        $head = json_decode(static::base64UrlDecode($parts[0]), true);
        
        if (isset($head['enc'])) {
            $data = static::decrypt($data, $decryptionKey);
            $parts = explode('.', $data);
        }

        if (count($parts) != 3) {
            throw new TokenException("Token must have three parts");
        }
        $head = static::base64UrlDecode($parts[0]);
        $claims = static::base64UrlDecode($parts[1]);
        $signature = static::base64UrlDecode($parts[2]);

        $token = new static();
        $token->headers = json_decode($head, true);
        $token->claims = json_decode($claims, true);
        $token->signature = $signature === '' ? null : $signature;
        return $token;
    }
    /**
     * Get all claims.
     * @method getClaims
     * @return array    all claims in the token (key-value pairs)
     */
    public function getClaims()
    {
        return $this->claims;
    }
    /**
     * Returns if a claim is present in the token.
     * @method hasClaim
     * @param  string   $key the claim name
     * @return boolean       whether the claim is present
     */
    public function hasClaim($key)
    {
        return isset($this->claims[$key]);
    }
    /**
     * Get a claim value.
     * @method getClaim
     * @param  string   $key     the claim name
     * @param  mixed   $default  optional default value to use if the claim is not present
     * @return mixed             the claim value
     */
    public function getClaim($key, $default = null)
    {
        return $this->hasClaim($key) ? $this->claims[$key] : $default;
    }
    /**
     * Set a claim on the token.
     * @method setClaim
     * @param  string   $key      the claim name
     * @param  mixed   $value     the claim value
     * @param  boolean  $asHeader optional parameter indicating if the claim should be copied in the header section
     * @return  self
     */
    public function setClaim($key, $value, $asHeader = false)
    {
        $this->claims[$key] = $value;
        if ($asHeader) {
            $this->setHeader($key, $value);
        }
        return $this;
    }
    /**
     * Set claims on the token.
     * @method setClaims
     * @param  array    $claims    the claims to set (key => value)
     * @param  boolean  $asHeader  optional parameter indicating if the claims should be copied in the header section
     * @return  self
     */
    public function setClaims(array $claims, $asHeader = false)
    {
        foreach ($claims as $claim => $value) {
            $this->setClaim($claim, $value, $asHeader);
        }
        return $this;
    }
    /**
     * Get all token headers.
     * @method getHeaders
     * @return array     all headers
     */
    public function getHeaders()
    {
        return $this->headers;
    }
    /**
     * Is a specific header present in the token.
     * @method hasHeader
     * @param  string    $key the header name
     * @return boolean        whether the header is present
     */
    public function hasHeader($key)
    {
        return isset($this->headers[$key]);
    }
    /**
     * Get a specific header value.
     * @method getHeader
     * @param  string    $key     the header name
     * @param  mixed     $default optional default value to return if the header is not present
     * @return mixed              the header value
     */
    public function getHeader($key, $default = null)
    {
        return $this->hasHeader($key) ? $this->headers[$key] : $default;
    }
    /**
     * Set a header on the token.
     * @method setHeader
     * @param  string    $key   the header name
     * @param  mixed     $value the header value
     * @return  self
     */
    public function setHeader($key, $value)
    {
        $this->headers[$key] = $value;
        return $this;
    }
    /**
     * Set the aud claim.
     * @method setAudience
     * @param  mixed       $value    the aud claim value
     * @param  boolean     $asHeader optional parameter indicating if the claim should be copied in the header section
     * @return  self
     */
    public function setAudience($value, $asHeader = false)
    {
        return $this->setClaim('aud', $value, $asHeader);
    }
    /**
     * Set the exp claim.
     * @method setExpiration
     * @param  mixed       $value    the exp claim value (should either be a timestamp or strtotime expression)
     * @param  boolean     $asHeader optional parameter indicating if the claim should be copied in the header section
     * @return  self
     */
    public function setExpiration($value, $asHeader = false)
    {
        return $this->setClaim('exp', is_string($value) ? strtotime($value) : $value, $asHeader);
    }
    /**
     * Set the jti claim.
     * @method setId
     * @param  mixed   $value    the jti claim value
     * @param  boolean $asHeader optional parameter indicating if the claim should be copied in the header section
     * @return  self
     */
    public function setId($value, $asHeader = false)
    {
        return $this->setClaim('jti', $value, $asHeader);
    }
    /**
     * Set the iat claim.
     * @method setIssuedAt
     * @param  mixed       $value    the iat claim value (should either be a timestamp or a strtotime expression)
     * @param  boolean     $asHeader optional parameter indicating if the claim should be copied in the header section
     * @return self
     */
    public function setIssuedAt($value, $asHeader = false)
    {
        return $this->setClaim('iat', is_string($value) ? strtotime($value) : $value, $asHeader);
    }
    /**
     * Set the iss claim value.
     * @method setIssuer
     * @param  mixed     $value    the iss claim value
     * @param  boolean   $asHeader optional parameter indicating if the claim should be copied in the header section
     * @return self
     */
    public function setIssuer($value, $asHeader = false)
    {
        return $this->setClaim('iss', $value, $asHeader);
    }
    /**
     * Set the nbf claim.
     * @method setNotBefore
     * @param  mixed        $value    the nbf claim value (should either be a timestamp or a strtotime expression)
     * @param  boolean      $asHeader optional parameter indicating if the claim should be copied in the header section
     * @return self
     */
    public function setNotBefore($value, $asHeader = false)
    {
        return $this->setClaim('nbf', is_string($value) ? strtotime($value) : $value, $asHeader);
    }
    /**
     * Set the sub claim.
     * @method setSubject
     * @param  mixed      $value    the sub claim value
     * @param  boolean    $asHeader optional parameter indicating if the claim should be copied in the header section
     * @return  self
     */
    public function setSubject($value, $asHeader = false)
    {
        return $this->setClaim('sub', $value, $asHeader);
    }
    /**
     * Returns if the token is already signed.
     * @method isSigned
     * @return boolean  is the token signed
     */
    public function isSigned()
    {
        return $this->signature !== null;
    }
    /**
     * Sign (or re-sign) the token
     * @method sign
     * @param  mixed  $key  the key to sign with (either a secret expression or the location of a private key)
     * @param  string $pass if a private key is used - the password for it
     * @param  string $kid  if an array of keys is passed in, this determines which key ID should be used
     * @return self
     */
    public function sign($key, $pass = '', $kid = null)
    {
        if (is_array($key)) {
            if ($kid === null) {
                $kid = $this->getHeader('kid', array_rand($key));
            }
            if (is_array($key)) {
                $key = $key[$kid];
            }
            $this->setHeader('kid', $kid);
        }
        $data = $this->getPayload();
        $algo = $this->getHeader('alg', 'none');
        switch ($this->getHeader('alg')) {
            case 'none':
                break;
            case 'ES256':
            case 'ES384':
            case 'ES512':
                $key = openssl_get_privatekey($key, $pass);
                $details = openssl_pkey_get_details($key);
                if (!isset($details['key']) || $details['type'] !== OPENSSL_KEYTYPE_EC) {
                    throw new TokenException('The key is not compatible with RSA signatures');
                }
                openssl_sign($data, $this->signature, $key, str_replace('ES', 'SHA', $algo));
                break;
            case 'RS256':
            case 'RS384':
            case 'RS512':
                $key = openssl_get_privatekey($key, $pass);
                $details = openssl_pkey_get_details($key);
                if (!isset($details['key']) || $details['type'] !== OPENSSL_KEYTYPE_RSA) {
                    throw new TokenException('The key is not compatible with RSA signatures');
                }
                openssl_sign($data, $this->signature, $key, str_replace('RS', 'SHA', $algo));
                break;
            case 'HS256':
            case 'HS384':
            case 'HS512':
                $this->signature = hash_hmac(str_replace('HS', 'SHA', $algo), $data, $key, true);
                break;
            default:
                throw new TokenException('Unsupported alg');
        }
        return $this;
    }
    /**
     * Verify the signature on a hash_hmac signed token.
     * @method verifyHash
     * @param  string     $key the key to verify with
     * @return boolean    is the signature valid
     */
    public function verifyHash($key)
    {
        if (!in_array($this->getHeader('alg', 'none'), ['HS256','HS384','HS512'])) {
            throw new TokenException('Invalid alg header');
        }
        return $this->verify($key);
    }
    /**
     * Verify the signature on a asymmetrically signed token.
     * @method verifySignature
     * @param  string          $key the location to the public key
     * @return boolean         is the signature valid
     */
    public function verifySignature($key)
    {
        if (!in_array($this->getHeader('alg', 'none'), ['RS256','RS384','RS512','ES256','ES384','ES512'])) {
            throw new TokenException('Invalid alg header');
        }
        return $this->verify($key);
    }
    /**
     * Verify the token signature.
     * @method verify
     * @param  string $key  the preshared secret, or the location to a public key
     * @param  string $algo optionally force to use this alg (instead of reading from the token headers)
     * @return boolean      is the signature valid
     */
    public function verify($key, $algo = null)
    {
        if (is_array($key)) {
            $kid = $this->getHeader('kid');
            if (!isset($key[$kid])) {
                return false;
            }
            $key = $key[$kid];
        }
        $data = $this->getPayload();
        $algo = $algo ? $algo : $this->getHeader('alg', 'none');
        switch ($algo) {
            case 'none':
                return $key ? false : true;
            case 'ES256':
            case 'ES384':
            case 'ES512':
                $key = openssl_get_publickey($key);
                $details = openssl_pkey_get_details($key);
                if (!isset($details['key']) || $details['type'] !== OPENSSL_KEYTYPE_EC) {
                    throw new TokenException('The key is not compatible with RSA signatures');
                }
                return openssl_verify($data, $this->signature, $key, str_replace('ES', 'SHA', $algo)) === 1;
            case 'RS256':
            case 'RS384':
            case 'RS512':
                $key = openssl_get_publickey($key);
                $details = openssl_pkey_get_details($key);
                if (!isset($details['key']) || $details['type'] !== OPENSSL_KEYTYPE_RSA) {
                    throw new TokenException('The key is not compatible with RSA signatures');
                }
                return openssl_verify($data, $this->signature, $key, str_replace('RS', 'SHA', $algo)) === 1;
            case 'HS256':
            case 'HS384':
            case 'HS512':
                return $this->signature === hash_hmac(str_replace('HS', 'SHA', $algo), $data, $key, true);
            default:
                throw new TokenException('Unsupported alg');
        }
    }
    /**
     * Is the token valid - this methods checks the claims, not the signature.
     * @method isValid
     * @param  array   $claims optional array of claim values to compare against
     * @return boolean         is the token valid
     */
    public function isValid(array $claims = [])
    {
        if (!in_array(
            $this->getHeader('alg', 'none'),
            ['HS256','HS384','HS512','RS256','RS384','RS512','ES256','ES384','ES512']
        )) {
            return false;
        }
        if ($this->getClaim('iat', time()) > time()) {
            return false;
        }
        if ($this->getClaim('nbf', time()) > time()) {
            return false;
        }
        if ($this->getClaim('exp', time()) < time()) {
            return false;
        }
        foreach ($claims as $key => $value) {
            $data = $this->getClaim($key, $value);
            if (is_string($value) && is_array($data) && in_array($value, $data)) {
                return false;
            } elseif ($data !== $value) {
                return false;
            }
        }
        return true;
    }
    /**
     * Get the string representation of the token.
     * @method toString
     * @return string     the token
     */
    public function toString($encryptionKey = null, $encryptionAlgo = 'A128CBC-HS256')
    {
        $data = $this->getPayload();
        $sign = $this->signature === null ? '' : static::base64UrlEncode($this->signature);
        $token = $data . '.' . $sign;
        if ($encryptionKey) {
            $token = static::encrypt($token, $encryptionKey, $encryptionAlgo);
        }
        return $token;
    }
    /**
     * Get the string representation of the token.
     * @method __toString
     * @return string     the token
     */
    public function __toString()
    {
        return $this->toString();
    }

    public static function base64UrlDecode($data)
    {
        return base64_decode(strtr($data, '-_', '+/'));
    }
    public static function base64UrlEncode($data)
    {
        return trim(strtr(base64_encode($data), '-_', '+/'), '=');
    }

    public static function encrypt($payload, $key, $algorithm = 'A128CBC-HS256')
    {
        if (empty($payload) || (is_string($payload) && trim($payload) == '')) {
            throw new TokenException('Payload can not be empty');
        }

        $header = static::base64UrlEncode(json_encode([
            'alg' => 'dir',
            'enc' => $algorithm,
            'typ' => 'JWT',
        ]));
        $enckey = static::base64UrlEncode('');

        switch ($algorithm) {
            case 'A128CBC-HS256':
                $keybit = 256;
                if (strlen($key) * 8 != $keybit) {
                    throw new TokenException("Encryption key is the wrong size");
                }
                $hmac = substr($key, 0, $keybit / 2);
                $aes = substr($key, $keybit / 2);
                $method = sprintf('AES-%d-CBC', $keybit / 2);
                $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($method));
                $encrypted = openssl_encrypt($payload, $method, $aes, true, $iv);

                $length = strlen($header);
                $input = implode('', [
                    $header,
                    $iv,
                    $encrypted,
                    pack('N2', ($length / 2147483647) * 8, ($length % 2147483647) * 8),
                ]);
                $auth = hash_hmac('SHA256', $input, $hmac, true);
                $auth = substr($auth, 0, strlen($auth) / 2);
                break;
            default:
                throw new TokenException('Unsupported encryption algorithm');
        }

        return implode('.', [
            $header,
            $enckey,
            static::base64UrlEncode($iv),
            static::base64UrlEncode($encrypted),
            static::base64UrlEncode($auth)
        ]);
    }
    public static function decrypt($data, $key, $algorithm = 'A128CBC-HS256')
    {
        $parts = explode('.', $data);
        if (count($parts) != 5) {
            throw new TokenException("Invalid JWE");
        }
        
        $header = json_decode(static::base64UrlDecode($parts[0]), true);
        $iv = static::base64UrlDecode($parts[2]);
        $encrypted = static::base64UrlDecode($parts[3]);
        $auth = static::base64UrlDecode($parts[4]);

        if (!isset($header['enc'])) {
            throw new TokenException("Invalid JWE");
        }

        switch ($header['enc']) {
            case 'A128CBC-HS256':
                $keybit = 256;
                if (strlen($key) * 8 != $keybit) {
                    throw new TokenException("Encryption key is the wrong size");
                }
                $hmac = substr($key, 0, $keybit / 2);
                $aes = substr($key, $keybit / 2);
                $method = sprintf('AES-%d-CBC', $keybit / 2);

                $length = strlen($parts[0]);
                $input = implode('', [
                    $parts[0],
                    $iv,
                    $encrypted,
                    pack('N2', ($length / 2147483647) * 8, ($length % 2147483647) * 8),
                ]);
                $temp = hash_hmac('SHA256', $input, $hmac, true);
                $temp = substr($temp, 0, strlen($temp) / 2);
                if ($temp !== $auth) {
                    throw new TokenException('Invalid JWE signature');
                }
                return openssl_decrypt($encrypted, $method, $aes, true, $iv);
            default:
                throw new TokenException("Unsupported algorithm");
        }
    }
}
