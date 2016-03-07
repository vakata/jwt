# vakata\JWT\JWT
A class for handling JWT

## Methods

| Name | Description |
|------|-------------|
|[fromString](#vakata\jwt\jwtfromstring)|Create an instance from a string token.|
|[getClaims](#vakata\jwt\jwtgetclaims)|Get all claims.|
|[hasClaim](#vakata\jwt\jwthasclaim)|Returns if a claim is present in the token.|
|[getClaim](#vakata\jwt\jwtgetclaim)|Get a claim value.|
|[setClaim](#vakata\jwt\jwtsetclaim)|Set a claim on the token.|
|[getHeaders](#vakata\jwt\jwtgetheaders)|Get all token headers.|
|[hasHeader](#vakata\jwt\jwthasheader)|Is a specific header present in the token.|
|[getHeader](#vakata\jwt\jwtgetheader)|Get a specific header value.|
|[setHeader](#vakata\jwt\jwtsetheader)|Set a header on the token.|
|[setAudience](#vakata\jwt\jwtsetaudience)|Set the aud claim.|
|[setExpiration](#vakata\jwt\jwtsetexpiration)|Set the exp claim.|
|[setId](#vakata\jwt\jwtsetid)|Set the jti claim.|
|[setIssuedAt](#vakata\jwt\jwtsetissuedat)|Set the iat claim.|
|[setIssuer](#vakata\jwt\jwtsetissuer)|Set the iss claim value.|
|[setNotBefore](#vakata\jwt\jwtsetnotbefore)|Set the nbf claim.|
|[setSubject](#vakata\jwt\jwtsetsubject)|Set the sub claim.|
|[isSigned](#vakata\jwt\jwtissigned)|Returns if the token is already signed.|
|[sign](#vakata\jwt\jwtsign)|Sign (or re-sign) the token|
|[verifyHash](#vakata\jwt\jwtverifyhash)|Verify the signature on a hash_hmac signed token.|
|[verifySignature](#vakata\jwt\jwtverifysignature)|Verify the signature on a asymmetrically signed token.|
|[verify](#vakata\jwt\jwtverify)|Verify the token signature.|
|[isValid](#vakata\jwt\jwtisvalid)|Is the token valid - this methods checks the claims, not the signature.|
|[__toString](#vakata\jwt\jwt__tostring)|Get the string representation of the token.|

---



### vakata\JWT\JWT::fromString
Create an instance from a string token.  


```php
public static function fromString (  
    string $data  
) : \vakata\JWT\JWT    
```

|  | Type | Description |
|-----|-----|-----|
| `$data` | `string` | the token string |
|  |  |  |
| `return` | `\vakata\JWT\JWT` | the new JWT instance |

---


### vakata\JWT\JWT::getClaims
Get all claims.  


```php
public function getClaims () : array    
```

|  | Type | Description |
|-----|-----|-----|
|  |  |  |
| `return` | `array` | all claims in the token (key-value pairs) |

---


### vakata\JWT\JWT::hasClaim
Returns if a claim is present in the token.  


```php
public function hasClaim (  
    string $key  
) : boolean    
```

|  | Type | Description |
|-----|-----|-----|
| `$key` | `string` | the claim name |
|  |  |  |
| `return` | `boolean` | whether the claim is present |

---


### vakata\JWT\JWT::getClaim
Get a claim value.  


```php
public function getClaim (  
    string $key,  
    mixed $default  
) : mixed    
```

|  | Type | Description |
|-----|-----|-----|
| `$key` | `string` | the claim name |
| `$default` | `mixed` | optional default value to use if the claim is not present |
|  |  |  |
| `return` | `mixed` | the claim value |

---


### vakata\JWT\JWT::setClaim
Set a claim on the token.  


```php
public function setClaim (  
    string $key,  
    mixed $value,  
    boolean $asHeader  
) : self    
```

|  | Type | Description |
|-----|-----|-----|
| `$key` | `string` | the claim name |
| `$value` | `mixed` | the claim value |
| `$asHeader` | `boolean` | optional parameter indicating if the claim should be copied in the header section |
|  |  |  |
| `return` | `self` |  |

---


### vakata\JWT\JWT::getHeaders
Get all token headers.  


```php
public function getHeaders () : array    
```

|  | Type | Description |
|-----|-----|-----|
|  |  |  |
| `return` | `array` | all headers |

---


### vakata\JWT\JWT::hasHeader
Is a specific header present in the token.  


```php
public function hasHeader (  
    string $key  
) : boolean    
```

|  | Type | Description |
|-----|-----|-----|
| `$key` | `string` | the header name |
|  |  |  |
| `return` | `boolean` | whether the header is present |

---


### vakata\JWT\JWT::getHeader
Get a specific header value.  


```php
public function getHeader (  
    string $key,  
    mixed $default  
) : mixed    
```

|  | Type | Description |
|-----|-----|-----|
| `$key` | `string` | the header name |
| `$default` | `mixed` | optional default value to return if the header is not present |
|  |  |  |
| `return` | `mixed` | the header value |

---


### vakata\JWT\JWT::setHeader
Set a header on the token.  


```php
public function setHeader (  
    string $key,  
    mixed $value  
) : self    
```

|  | Type | Description |
|-----|-----|-----|
| `$key` | `string` | the header name |
| `$value` | `mixed` | the header value |
|  |  |  |
| `return` | `self` |  |

---


### vakata\JWT\JWT::setAudience
Set the aud claim.  


```php
public function setAudience (  
    mixed $value,  
    boolean $asHeader  
) : self    
```

|  | Type | Description |
|-----|-----|-----|
| `$value` | `mixed` | the aud claim value |
| `$asHeader` | `boolean` | optional parameter indicating if the claim should be copied in the header section |
|  |  |  |
| `return` | `self` |  |

---


### vakata\JWT\JWT::setExpiration
Set the exp claim.  


```php
public function setExpiration (  
    mixed $value,  
    boolean $asHeader  
) : self    
```

|  | Type | Description |
|-----|-----|-----|
| `$value` | `mixed` | the exp claim value (should either be a timestamp or strtotime expression) |
| `$asHeader` | `boolean` | optional parameter indicating if the claim should be copied in the header section |
|  |  |  |
| `return` | `self` |  |

---


### vakata\JWT\JWT::setId
Set the jti claim.  


```php
public function setId (  
    mixed $value,  
    boolean $asHeader  
) : self    
```

|  | Type | Description |
|-----|-----|-----|
| `$value` | `mixed` | the jti claim value |
| `$asHeader` | `boolean` | optional parameter indicating if the claim should be copied in the header section |
|  |  |  |
| `return` | `self` |  |

---


### vakata\JWT\JWT::setIssuedAt
Set the iat claim.  


```php
public function setIssuedAt (  
    mixed $value,  
    boolean $asHeader  
) : self    
```

|  | Type | Description |
|-----|-----|-----|
| `$value` | `mixed` | the iat claim value (should either be a timestamp or a strtotime expression) |
| `$asHeader` | `boolean` | optional parameter indicating if the claim should be copied in the header section |
|  |  |  |
| `return` | `self` |  |

---


### vakata\JWT\JWT::setIssuer
Set the iss claim value.  


```php
public function setIssuer (  
    mixed $value,  
    boolean $asHeader  
) : self    
```

|  | Type | Description |
|-----|-----|-----|
| `$value` | `mixed` | the iss claim value |
| `$asHeader` | `boolean` | optional parameter indicating if the claim should be copied in the header section |
|  |  |  |
| `return` | `self` |  |

---


### vakata\JWT\JWT::setNotBefore
Set the nbf claim.  


```php
public function setNotBefore (  
    mixed $value,  
    boolean $asHeader  
) : self    
```

|  | Type | Description |
|-----|-----|-----|
| `$value` | `mixed` | the nbf claim value (should either be a timestamp or a strtotime expression) |
| `$asHeader` | `boolean` | optional parameter indicating if the claim should be copied in the header section |
|  |  |  |
| `return` | `self` |  |

---


### vakata\JWT\JWT::setSubject
Set the sub claim.  


```php
public function setSubject (  
    mixed $value,  
    boolean $asHeader  
) : self    
```

|  | Type | Description |
|-----|-----|-----|
| `$value` | `mixed` | the sub claim value |
| `$asHeader` | `boolean` | optional parameter indicating if the claim should be copied in the header section |
|  |  |  |
| `return` | `self` |  |

---


### vakata\JWT\JWT::isSigned
Returns if the token is already signed.  


```php
public function isSigned () : boolean    
```

|  | Type | Description |
|-----|-----|-----|
|  |  |  |
| `return` | `boolean` | is the token signed |

---


### vakata\JWT\JWT::sign
Sign (or re-sign) the token  


```php
public function sign (  
    mixed $key,  
    string $pass,  
    string $kid  
) : self    
```

|  | Type | Description |
|-----|-----|-----|
| `$key` | `mixed` | the key to sign with (either a secret expression or the location of a private key) |
| `$pass` | `string` | if a private key is used - the password for it |
| `$kid` | `string` | if an array of keys is passed in, this determines which key ID should be used |
|  |  |  |
| `return` | `self` |  |

---


### vakata\JWT\JWT::verifyHash
Verify the signature on a hash_hmac signed token.  


```php
public function verifyHash (  
    string $key  
) : boolean    
```

|  | Type | Description |
|-----|-----|-----|
| `$key` | `string` | the key to verify with |
|  |  |  |
| `return` | `boolean` | is the signature valid |

---


### vakata\JWT\JWT::verifySignature
Verify the signature on a asymmetrically signed token.  


```php
public function verifySignature (  
    string $key  
) : boolean    
```

|  | Type | Description |
|-----|-----|-----|
| `$key` | `string` | the location to the public key |
|  |  |  |
| `return` | `boolean` | is the signature valid |

---


### vakata\JWT\JWT::verify
Verify the token signature.  


```php
public function verify (  
    string $key,  
    string $algo  
) : boolean    
```

|  | Type | Description |
|-----|-----|-----|
| `$key` | `string` | the preshared secret, or the location to a public key |
| `$algo` | `string` | optionally force to use this alg (instead of reading from the token headers) |
|  |  |  |
| `return` | `boolean` | is the signature valid |

---


### vakata\JWT\JWT::isValid
Is the token valid - this methods checks the claims, not the signature.  


```php
public function isValid (  
    array $claims  
) : boolean    
```

|  | Type | Description |
|-----|-----|-----|
| `$claims` | `array` | optional array of claim values to compare against |
|  |  |  |
| `return` | `boolean` | is the token valid |

---


### vakata\JWT\JWT::__toString
Get the string representation of the token.  


```php
public function __toString ()   
```

|  | Type | Description |
|-----|-----|-----|

---

