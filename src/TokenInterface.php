<?php

namespace vakata\jwt;

interface TokenInterface
{
    public static function fromString($token);

    public function getClaims();
    public function hasClaim($key);
    public function getClaim($key, $default = null);
    public function setClaim($key, $value, $asHeader = false);

    public function getHeaders();
    public function hasHeader($key);
    public function getHeader($key, $default = null);
    public function setHeader($key, $value);

    public function setAudience($value, $asHeader = false);
    public function setExpiration($value, $asHeader = false);
    public function setId($value, $asHeader = false);
    public function setIssuedAt($value, $asHeader = false);
    public function setIssuer($value, $asHeader = false);
    public function setNotBefore($value, $asHeader = false);
    public function setSubject($value, $asHeader = false);

    public function isSigned();
    public function sign($key, $pass = '', $kid = null);
    public function verifyHash($key);
    public function verifySignature($key);
    public function verify($key, $algo = null);

    public function isValid(array $claims = []);

    public function __toString();

    /*
    public function isEncrypted();
    public function encrypt($key);
    public function decrypt($key);
    */
}
