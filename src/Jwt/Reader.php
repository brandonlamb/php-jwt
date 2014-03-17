<?php

/**
 * JSON Web Token Reader
 * @package \Jwt
 * @author Brandon Lamb <brandon@brandonlamb.com>
 */

/**
 * JSON Web Token implementation, based on this spec:
 * http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-06
 *
 * PHP version 5
 *
 * @category Authentication
 * @package  Authentication_JWT
 * @author   Neuman Vong <neuman@twilio.com>
 * @author   Anant Narayanan <anant@php.net>
 * @license  http://opensource.org/licenses/BSD-3-Clause 3-clause BSD
 * @link     https://github.com/firebase/php-jwt
 */

namespace Jwt;

abstract class Reader
{
	/**
	 * @var array, json errors
	 */
    protected static $messages = [
        \JSON_ERROR_DEPTH		=> 'Maximum stack depth exceeded',
        \JSON_ERROR_CTRL_CHAR	=> 'Unexpected control character found',
        \JSON_ERROR_SYNTAX		=> 'Syntax error, malformed JSON'
    ];

    /**
     * @var array, encryption methods
     */
    protected static $methods = [
        'HS256' => 'sha256',
        'HS384' => 'sha384',
        'HS512' => 'sha512',
    ];

    /**
     * Decodes a JWT string into a PHP object.
     *
     * @param string $jwt The JWT
     * @param string|null $key The secret key
     * @param bool $verify Don't skip verification process
     * @return object The JWT's payload as a PHP object
     * @throws \UnexpectedValueException Provided JWT was invalid
     * @throws \DomainException Algorithm was not provided
     */
    public static function decode($jwt, $key = null, $verify = true)
    {
        $tks = explode('.', $jwt);

        if (count($tks) != 3) {
            throw new \UnexpectedValueException('Wrong number of segments');
        }

        list($headb64, $bodyb64, $cryptob64) = $tks;

        if (null === ($header = self::jsonDecode(self::urlsafeB64Decode($headb64)))) {
            throw new \UnexpectedValueException('Invalid segment encoding');
        }

        if (null === ($payload = self::jsonDecode(self::urlsafeB64Decode($bodyb64)))) {
            throw new \UnexpectedValueException('Invalid segment encoding');
        }

        if ($verify) {
            if (empty($header['alg'])) {
                throw new \DomainException('Empty algorithm');
            }

            if (self::urlsafeB64Decode($cryptob64) != self::sign("{$headb64}.{$bodyb64}", $key, $header['alg'])) {
                throw new \UnexpectedValueException('Signature verification failed');
            }
        }

        return (new Token())
            ->setHeaders($header)
            ->setClaims($payload);
    }

    /**
     * Decode a string with URL-safe Base64.
     *
     * @param string $input A Base64 encoded string
     * @return string A decoded string
     */
    public static function urlsafeB64Decode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    /**
     * Decode a JSON string into a PHP object.
     *
     * @param string $input JSON string
     * @return object Object representation of JSON string
     * @throws \DomainException Provided string was invalid JSON
     */
    public static function jsonDecode($input)
    {
        $obj = json_decode($input, true);

        if (function_exists('json_last_error') && ($errno = json_last_error())) {
            self::handleJsonError($errno);
        } else if ($obj === null && $input !== 'null') {
            throw new \DomainException('Null result with non-null input');
        }

        return $obj;
    }

    /**
     * Helper method to create a JSON error.
     *
     * @param int $errno An error number from json_last_error()
     * @throws \DomainException
     */
    protected static function handleJsonError($errno)
    {
        throw new \DomainException(
            isset(self::$messages[$errno]) ? self::$messages[$errno] : 'Unknown JSON error: ' . $errno
        );
    }

    /**
     * Sign a string with a given key and algorithm.
     *
     * @param string $msg The message to sign
     * @param string $key The secret key
     * @param string $method The signing algorithm. Supported algorithms are 'HS256', 'HS384' and 'HS512'
     * @return string An encrypted message
     * @throws \DomainException Unsupported algorithm was specified
     */
    public static function sign($msg, $key, $method = 'HS256')
    {
        if (!isset(self::$methods[$method])) {
            throw new \DomainException('Algorithm not supported');
        }
        return hash_hmac(self::$methods[$method], $msg, $key, true);
    }
}
