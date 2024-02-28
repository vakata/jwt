<?php

namespace vakata\jwt;

/**
 * A class for handling JWT
 */
class JWT implements TokenInterface
{
    protected $payload = null;
    protected $headers = [];
    protected $claims = [];
    protected $signature = null;

    public function __construct(array $claims = [], $algo = 'HS256')
    {
        $this->headers['typ'] = 'JWT';
        $this->headers['alg'] = $algo;

        $this->setClaims($claims);
    }

    protected function getPayload()
    {
        if ($this->payload) {
            return $this->payload;
        }
        $head = static::base64UrlEncode(json_encode($this->headers));
        $body = static::base64UrlEncode(json_encode($this->claims));
        return $head . '.' . $body;
    }

    /**
     * Create an instance from a string token.
     * @param  string     $data the token string
     * @return self             the new JWT instance
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
        $token->payload = $parts[0] . '.' . $parts[1];
        return $token;
    }
    /**
     * Get all claims.
     * @return array    all claims in the token (key-value pairs)
     */
    public function getClaims()
    {
        return $this->claims;
    }
    /**
     * Returns if a claim is present in the token.
     * @param  string   $key the claim name
     * @return boolean       whether the claim is present
     */
    public function hasClaim($key)
    {
        return isset($this->claims[$key]);
    }
    /**
     * Get a claim value.
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
     * @param  string   $key      the claim name
     * @param  mixed   $value     the claim value
     * @param  boolean  $asHeader optional parameter indicating if the claim should be copied in the header section
     * @return  self
     */
    public function setClaim($key, $value, $asHeader = false)
    {
        $this->payload = null;
        $this->claims[$key] = $value;
        if ($asHeader) {
            $this->setHeader($key, $value);
        }
        return $this;
    }
    /**
     * Set claims on the token.
     * @param  array    $claims    the claims to set (key => value)
     * @param  boolean  $asHeader  optional parameter indicating if the claims should be copied in the header section
     * @return  self
     */
    public function setClaims(array $claims, $asHeader = false)
    {
        $this->payload = null;
        foreach ($claims as $claim => $value) {
            $this->setClaim($claim, $value, $asHeader);
        }
        return $this;
    }
    /**
     * Get all token headers.
     * @return array     all headers
     */
    public function getHeaders()
    {
        return $this->headers;
    }
    /**
     * Is a specific header present in the token.
     * @param  string    $key the header name
     * @return boolean        whether the header is present
     */
    public function hasHeader($key)
    {
        return isset($this->headers[$key]);
    }
    /**
     * Get a specific header value.
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
     * @param  string    $key   the header name
     * @param  mixed     $value the header value
     * @return  self
     */
    public function setHeader($key, $value)
    {
        $this->payload = null;
        $this->headers[$key] = $value;
        return $this;
    }
    /**
     * Set the aud claim.
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
     * @return boolean  is the token signed
     */
    public function isSigned()
    {
        return $this->signature !== null;
    }
    /**
     * Sign (or re-sign) the token
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
                openssl_sign($data, $signature, $key, str_replace('ES', 'SHA', $algo));
                $this->signature = static::signatureFromDER($signature, (int)str_replace('ES', '', $algo));
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

    protected static function signatureToDER(string $sig): string
    {
        $length = max(1, (int) (\strlen($sig) / 2));
        list($r, $s) = \str_split($sig, $length);
        $r = \ltrim($r, "\x00");
        $s = \ltrim($s, "\x00");
        if (\ord($r[0]) > 0x7f) {
            $r = "\x00" . $r;
        }
        if (\ord($s[0]) > 0x7f) {
            $s = "\x00" . $s;
        }
        return self::encodeDER(
            0x10,
            self::encodeDER(0x02, $r) .
            self::encodeDER(0x02, $s)
        );
    }
    protected static function encodeDER(int $type, string $value): string
    {
        $tag_header = 0;
        if ($type === 0x10) {
            $tag_header |= 0x20;
        }
        $der = \chr($tag_header | $type);
        $der .= \chr(\strlen($value));
        return $der . $value;
    }
    private static function signatureFromDER(string $der, int $keySize): string
    {
        list($offset, $_) = self::readDER($der);
        list($offset, $r) = self::readDER($der, $offset);
        list($offset, $s) = self::readDER($der, $offset);
        $r = \ltrim($r, "\x00");
        $s = \ltrim($s, "\x00");
        $r = \str_pad($r, $keySize / 8, "\x00", STR_PAD_LEFT);
        $s = \str_pad($s, $keySize / 8, "\x00", STR_PAD_LEFT);
        return $r . $s;
    }
    private static function readDER(string $der, int $offset = 0): array
    {
        $pos = $offset;
        $size = \strlen($der);
        $constructed = (\ord($der[$pos]) >> 5) & 0x01;
        $type = \ord($der[$pos++]) & 0x1f;
        $len = \ord($der[$pos++]);
        if ($len & 0x80) {
            $n = $len & 0x1f;
            $len = 0;
            while ($n-- && $pos < $size) {
                $len = ($len << 8) | \ord($der[$pos++]);
            }
        }
        if ($type === 0x03) {
            $pos++;
            $data = \substr($der, $pos, $len - 1);
            $pos += $len - 1;
        } elseif (!$constructed) {
            $data = \substr($der, $pos, $len);
            $pos += $len;
        } else {
            $data = null;
        }
        return [$pos, $data];
    }


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
                $signature = static::signatureToDER($this->signature);
                return openssl_verify($data, $signature, $key, str_replace('ES', 'SHA', $algo)) === 1;
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
        $tm = time();
        if ($this->getClaim('iat', $tm) > $tm) {
            return false;
        }
        if ($this->getClaim('nbf', $tm) > $tm) {
            return false;
        }
        if ($this->getClaim('exp', $tm) < $tm) {
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
        return trim(strtr(base64_encode($data), '+/', '-_'), '=');
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
