<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Sheikh0775\JWTAuth\Test\Validators;

use Sheikh0775\JWTAuth\Claims\Collection;
use Sheikh0775\JWTAuth\Claims\Expiration;
use Sheikh0775\JWTAuth\Claims\IssuedAt;
use Sheikh0775\JWTAuth\Claims\Issuer;
use Sheikh0775\JWTAuth\Claims\JwtId;
use Sheikh0775\JWTAuth\Claims\NotBefore;
use Sheikh0775\JWTAuth\Claims\Subject;
use Sheikh0775\JWTAuth\Exceptions\InvalidClaimException;
use Sheikh0775\JWTAuth\Exceptions\TokenExpiredException;
use Sheikh0775\JWTAuth\Exceptions\TokenInvalidException;
use Sheikh0775\JWTAuth\Test\AbstractTestCase;
use Sheikh0775\JWTAuth\Validators\PayloadValidator;

class PayloadValidatorTest extends AbstractTestCase
{
    /**
     * @var \Sheikh0775\JWTAuth\Validators\PayloadValidator
     */
    protected $validator;

    public function setUp(): void
    {
        parent::setUp();

        $this->validator = new PayloadValidator;
    }

    /** @test */
    public function it_should_return_true_when_providing_a_valid_payload()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ];

        $collection = Collection::make($claims);

        $this->assertTrue($this->validator->isValid($collection));
    }

    /** @test */
    public function it_should_throw_an_exception_when_providing_an_expired_payload()
    {
        $this->expectException(TokenExpiredException::class);
        $this->expectExceptionMessage('Token has expired');

        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp - 1440),
            new NotBefore($this->testNowTimestamp - 3660),
            new IssuedAt($this->testNowTimestamp - 3660),
            new JwtId('foo'),
        ];

        $collection = Collection::make($claims);

        $this->validator->check($collection);
    }

    /** @test */
    public function it_should_throw_an_exception_when_providing_an_invalid_nbf_claim()
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Not Before (nbf) timestamp cannot be in the future');

        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 1440),
            new NotBefore($this->testNowTimestamp + 3660),
            new IssuedAt($this->testNowTimestamp - 3660),
            new JwtId('foo'),
        ];

        $collection = Collection::make($claims);

        $this->validator->check($collection);
    }

    /** @test */
    public function it_should_throw_an_exception_when_providing_an_invalid_iat_claim()
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('Invalid value provided for claim [iat]');

        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 1440),
            new NotBefore($this->testNowTimestamp - 3660),
            new IssuedAt($this->testNowTimestamp + 3660),
            new JwtId('foo'),
        ];

        $collection = Collection::make($claims);

        $this->validator->check($collection);
    }

    /** @test */
    public function it_should_throw_an_exception_when_providing_an_invalid_payload()
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('JWT payload does not contain the required claims');

        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
        ];

        $collection = Collection::make($claims);

        $this->validator->check($collection);
    }

    /** @test */
    public function it_should_throw_an_exception_when_providing_an_invalid_expiry()
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('Invalid value provided for claim [exp]');

        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration('foo'),
            new NotBefore($this->testNowTimestamp - 3660),
            new IssuedAt($this->testNowTimestamp + 3660),
            new JwtId('foo'),
        ];

        $collection = Collection::make($claims);

        $this->validator->check($collection);
    }

    /** @test */
    public function it_should_set_the_required_claims()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
        ];

        $collection = Collection::make($claims);

        $this->assertTrue($this->validator->setRequiredClaims(['iss', 'sub'])->isValid($collection));
    }

    /** @test */
    public function it_should_check_the_token_in_the_refresh_context()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp - 1000),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp - 2600), // this is LESS than the refresh ttl at 1 hour
            new JwtId('foo'),
        ];

        $collection = Collection::make($claims);

        $this->assertTrue(
            $this->validator->setRefreshFlow()->setRefreshTTL(60)->isValid($collection)
        );
    }

    /** @test */
    public function it_should_return_true_if_the_refresh_ttl_is_null()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp - 1000),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp - 2600), // this is LESS than the refresh ttl at 1 hour
            new JwtId('foo'),
        ];

        $collection = Collection::make($claims);

        $this->assertTrue(
            $this->validator->setRefreshFlow()->setRefreshTTL(null)->isValid($collection)
        );
    }

    /** @test */
    public function it_should_throw_an_exception_if_the_token_cannot_be_refreshed()
    {
        $this->expectException(TokenExpiredException::class);
        $this->expectExceptionMessage('Token has expired and can no longer be refreshed');

        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp - 5000), // this is MORE than the refresh ttl at 1 hour, so is invalid
            new JwtId('foo'),
        ];

        $collection = Collection::make($claims);

        $this->validator->setRefreshFlow()->setRefreshTTL(60)->check($collection);
    }
}
