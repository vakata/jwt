# JWT

[![Latest Version on Packagist][ico-version]][link-packagist]
[![Software License][ico-license]](LICENSE.md)
[![Build Status][ico-travis]][link-travis]
[![Code Climate][ico-cc]][link-cc]
[![Tests Coverage][ico-cc-coverage]][link-cc]

JWT token handling.

## Install

Via Composer

``` bash
$ composer require vakata/jwt
```

## Usage

``` php
$token = new \vakata\jwt\JWT();
$token
    ->setClaim("key", "value")
    ->setExpiration("+30 days")
    ->setIssuer("System")
    ->sign("secretKey");

$stringified = (string)$token;
$parsed = \vakata\jwt\JWT::fromString($stringified);
var_dump($parsed->isValid()); // true
var_dump($parsed->isSigned()); // true
var_dump($parsed->verifyHash("secretKey")); // true
var_dump($parsed->getClaim("key")); // "value"
```

Read more in the [API docs](docs/README.md)

## Testing

``` bash
$ composer test
```


## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

## Security

If you discover any security related issues, please email github@vakata.com instead of using the issue tracker.

## Credits

- [vakata][link-author]
- [All Contributors][link-contributors]

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information. 

[ico-version]: https://img.shields.io/packagist/v/vakata/jwt.svg?style=flat-square
[ico-license]: https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square
[ico-travis]: https://img.shields.io/travis/vakata/jwt/master.svg?style=flat-square
[ico-scrutinizer]: https://img.shields.io/scrutinizer/coverage/g/vakata/jwt.svg?style=flat-square
[ico-code-quality]: https://img.shields.io/scrutinizer/g/vakata/jwt.svg?style=flat-square
[ico-downloads]: https://img.shields.io/packagist/dt/vakata/jwt.svg?style=flat-square
[ico-cc]: https://img.shields.io/codeclimate/github/vakata/jwt.svg?style=flat-square
[ico-cc-coverage]: https://img.shields.io/codeclimate/coverage/github/vakata/jwt.svg?style=flat-square

[link-packagist]: https://packagist.org/packages/vakata/jwt
[link-travis]: https://travis-ci.org/vakata/jwt
[link-scrutinizer]: https://scrutinizer-ci.com/g/vakata/jwt/code-structure
[link-code-quality]: https://scrutinizer-ci.com/g/vakata/jwt
[link-downloads]: https://packagist.org/packages/vakata/jwt
[link-author]: https://github.com/vakata
[link-contributors]: ../../contributors
[link-cc]: https://codeclimate.com/github/vakata/jwt

