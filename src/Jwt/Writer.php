<?php

/**
 * JSON Web Token Writer
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

abstract class Writer
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
     * Converts and signs a PHP object or array into a JWT string.
     *
     * @param \Jwt\Toekn $token
     * @param string $key The secret key
     * @param string $algo The signing algorithm. Supported algorithms are 'HS256', 'HS384' and 'HS512'
     *
     * @return string A signed JWT
     * @uses jsonEncode
     * @uses urlsafeB64Encode
     */
    public static function encode(Token $token, $key = null, $algo = null)
    {
    	null !== $key && $token->setKey($key);
    	null !== $algo && $token->setHeader('alg', $algo);
        #$header = ['typ' => 'JWT', 'alg' => $algo];

        $segments = [
        	self::urlsafeB64Encode(self::jsonEncode($token->getHeaders())),
        	self::urlsafeB64Encode(self::jsonEncode($token->getClaims())),
    	];

        $signing = implode('.', $segments);
        $signature = self::sign($signing, $token->getKey(), $token->getHeader('algo'));
        $segments[] = self::urlsafeB64Encode($signature);

        return implode('.', $segments);
    }

    /**
     * Encode a string with URL-safe Base64.
     *
     * @param string $input The string you want encoded
     * @return string The base64 encode of what you passed in
     */
    public static function urlsafeB64Encode($input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    /**
     * Encode a PHP object into a JSON string.
     *
     * @param object|array $input A PHP object or array
     * @return string JSON representation of the PHP object or array
     * @throws \DomainException Provided object could not be encoded to valid JSON
     */
    public static function jsonEncode($input)
    {
        $json = json_encode($input);

        if (function_exists('json_last_error') && ($errno = json_last_error())) {
            self::handleJsonError($errno);
        } else if ($json === 'null' && $input !== null) {
            throw new \DomainException('Null result with non-null input');
        }

        return $json;
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
