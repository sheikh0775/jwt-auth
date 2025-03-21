<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Sheikh0775\JWTAuth\Test\Middleware;

use Mockery;
use Sheikh0775\JWTAuth\Exceptions\TokenInvalidException;
use Sheikh0775\JWTAuth\Http\Middleware\Check;
use Sheikh0775\JWTAuth\Http\Parser\Parser;
use Sheikh0775\JWTAuth\Test\Stubs\UserStub;

class CheckTest extends AbstractMiddlewareTest
{
    /**
     * @var \Sheikh0775\JWTAuth\Http\Middleware\Check
     */
    protected $middleware;

    public function setUp(): void
    {
        parent::setUp();

        $this->middleware = new Check($this->auth);
    }

    /** @test */
    public function it_should_authenticate_a_user_if_a_token_is_present()
    {
        $parser = Mockery::mock(Parser::class);
        $parser->shouldReceive('hasToken')->once()->andReturn(true);

        $this->auth->shouldReceive('parser')->andReturn($parser);

        $this->auth->parser()->shouldReceive('setRequest')->once()->with($this->request)->andReturn($this->auth->parser());
        $this->auth->shouldReceive('parseToken->authenticate')->once()->andReturn(new UserStub);

        $this->middleware->handle($this->request, function () {
            //
        });
    }

    /** @test */
    public function it_should_unset_the_exception_if_a_token_is_present()
    {
        $parser = Mockery::mock(Parser::class);
        $parser->shouldReceive('hasToken')->once()->andReturn(true);

        $this->auth->shouldReceive('parser')->andReturn($parser);

        $this->auth->parser()->shouldReceive('setRequest')->once()->with($this->request)->andReturn($this->auth->parser());
        $this->auth->shouldReceive('parseToken->authenticate')->once()->andThrow(new TokenInvalidException);

        $this->middleware->handle($this->request, function () {
            //
        });
    }

    /** @test */
    public function it_should_do_nothing_if_a_token_is_not_present()
    {
        $parser = Mockery::mock(Parser::class);
        $parser->shouldReceive('hasToken')->once()->andReturn(false);

        $this->auth->shouldReceive('parser')->andReturn($parser);

        $this->auth->parser()->shouldReceive('setRequest')->once()->with($this->request)->andReturn($this->auth->parser());
        $this->auth->shouldReceive('parseToken->authenticate')->never();

        $this->middleware->handle($this->request, function () {
            //
        });
    }
}
