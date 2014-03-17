<?php

/**
 * JSON Web Token
 *
 * Represents a container of claims
 *
 * @package Jwt
 * @author Brandon Lamb <brandon@brandonlamb.com>
 */

namespace Jwt;

use ArrayAccess;

class Token implements ArrayAccess
{
	/**
	 * @var array, internal header storage
	 */
	protected $headers;

	/**
	 * @var array, internal claims storage
	 */
	protected $claims;

	/**
	 * @var string, token key
	 */
	protected $key;

	/**
	 * Token constructor
	 */
	public function __construct()
	{
		$this->headers = ['typ' => 'JWT', 'alg' => 'HS256'];
		$this->claims = [];
	}

	/**
	 * Magic getter
	 * @param string $offset
	 * @return mixed
	 */
	public function __get($offset)
	{
		return $this->offsetGet($offset);
	}

	/**
	 * Magic setter
	 * @param string $offset
	 * @param mixed $value
	 */
	public function __set($offset, $value)
	{
		$this->offsetSet($offset, $value);
	}

	/**
	 * {@inheritDoc}
	 */
	public function offsetExists($offset)
	{
		return isset($this->claims[(string) $offset]);
	}

	/**
	 * {@inheritDoc}
	 */
	public function offsetGet($offset)
	{
		if (!$this->offsetExists($offset)) {
			throw new \OutOfBoundsException($offset . ' is not a valid value');
		}
		return $this->claims[(string) $offset];
	}

	/**
	 * {@inheritDoc}
	 */
	public function offsetSet($offset, $value)
	{
		$this->claims[(string) $offset] = $value;
	}

	/**
	 * {@inheritDoc}
	 */
	public function offsetUnset($offset)
	{
		unset($this->claims[$offset]);
	}

	/**
	 * Get a header
	 * @param string $offset
	 * @return mixed
	 */
	public function getHeader($offset)
	{
		if (!isset($this->headers[(string) $offset])) {
			throw new \OutOfBoundsException($offset . ' is not a valid value');
		}
		return $this->headers[(string) $offset];
	}

	/**
	 * Get all headers
	 * @return array
	 */
	public function getHeaders()
	{
		return $this->headers;
	}

	/**
	 * Set a header value
	 * @param string $offset
	 * @param mixed $value
	 * @return \Jwt\Token
	 */
	public function setHeader($offset, $value)
	{
		$this->headers[(string) $offset] = $value;
		return $this;
	}

	/**
	 * Set array of headers
	 * @param array $headers
	 * @return \Jwt\Token
	 */
	public function setHeaders(array $headers)
	{
		foreach ($headers as $key => $value) {
			$this->setHeader($key, $value);
		}
		return $this;
	}

	/**
	 * Get a claim
	 * @param string $offset
	 * @return mixed
	 */
	public function getClaim($offset)
	{
		if (!$this->offsetExists($offset)) {
			throw new \OutOfBoundsException($offset . ' is not a valid value');
		}
		return $this->claims[(string) $offset];
	}

	/**
	 * Get all claims
	 * @return array
	 */
	public function getClaims()
	{
		return $this->claims;
	}

	/**
	 * Set a claim
	 * @param string $offset
	 * @param mixed $value
	 * @return \Jwt\Token
	 */
	public function setClaim($offset, $value)
	{
		$this->claims[(string) $offset] = $value;
		return $this;
	}

	/**
	 * Set array of claim
	 * @param array $claims
	 * @return \Jwt\Token
	 */
	public function setClaims(array $claims)
	{
		foreach ($claims as $key => $value) {
			$this->setClaim($key, $value);
		}
		return $this;
	}

	/**
	 * Remove a claim
	 * @param string $offset
	 * @return \Jwt\Token
	 */
	public function removeClaim($offset)
	{
		$this->offsetUnset($offset);
		return $this;
	}

	/**
	 * Get the key
	 * @return string
	 */
	public function getKey()
	{
		return (string) $this->key;
	}

	/**
	 * Set the key
	 * @param string $key
	 * @return \Jwt\Token
	 */
	public function setKey($key)
	{
		$this->key = (string) $key;
		return $this;
	}
}
