[![Build Status](https://travis-ci.org/brandonlamb/php-jwt.png?branch=master)](https://travis-ci.org/brandonlamb/php-jwt)

PHP-JWT
=======
A simple library to encode and decode JSON Web Tokens (JWT) in PHP. Should
conform to the [current spec](http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-06)

Installation
------------

Use composer to manage your dependencies and download PHP-JWT:

```bash
php composer require brandonlamb/php-jwt
```

Example
-------
```php
<?php

$token = new Jwt\Token();
$token
	->setKey('app_key')
	->setClaim('iss', 'http://example.com')
	->setClaim('aud', 'http://example.com')
	->setClaim('iat', 1356999524)
	->setClaim('nbf', 1357000000);

$jwt = Jwt\Writer::encode($token);
$jwt = Jwt\Writer::encode($token, 'app_key', 'HS256');

$token = Jwt\Reader::decode($jwt, 'app_key');

print_r($decoded);
?>
```

Tests
-----
Run the tests using phpunit:

```bash
$ pear install PHPUnit
$ phpunit --configuration phpunit.xml.dist
PHPUnit 3.7.10 by Sebastian Bergmann.
.....
Time: 0 seconds, Memory: 2.50Mb
OK (5 tests, 5 assertions)
```

License
-------
[3-Clause BSD](http://opensource.org/licenses/BSD-3-Clause).
