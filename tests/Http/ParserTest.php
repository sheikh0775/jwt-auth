<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Sheikh0775\JWTAuth\Test\Http;

use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use Illuminate\Support\Facades\Crypt;
use Mockery;
use Sheikh0775\JWTAuth\Contracts\Http\Parser as ParserContract;
use Sheikh0775\JWTAuth\Http\Parser\AuthHeaders;
use Sheikh0775\JWTAuth\Http\Parser\Cookies;
use Sheikh0775\JWTAuth\Http\Parser\InputSource;
use Sheikh0775\JWTAuth\Http\Parser\LumenRouteParams;
use Sheikh0775\JWTAuth\Http\Parser\Parser;
use Sheikh0775\JWTAuth\Http\Parser\QueryString;
use Sheikh0775\JWTAuth\Http\Parser\RouteParams;
use Sheikh0775\JWTAuth\Test\AbstractTestCase;

class ParserTest extends AbstractTestCase
{
    /** @test */
    public function it_should_return_the_token_from_the_authorization_header()
    {
        $request = Request::create('foo', 'POST');
        $request->headers->set('Authorization', 'Bearer foobar');

        $parser = new Parser($request);

        $parser->setChain([
            new QueryString,
            new InputSource,
            new AuthHeaders,
            new RouteParams,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_the_prefixed_authentication_header()
    {
        $request = Request::create('foo', 'POST');
        $request->headers->set('Authorization', 'Custom foobar');

        $parser = new Parser($request);

        $parser->setChain([
            new QueryString,
            new InputSource,
            (new AuthHeaders)->setHeaderPrefix('Custom'),
            new RouteParams,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_the_custom_authentication_header()
    {
        $request = Request::create('foo', 'POST');
        $request->headers->set('custom_authorization', 'Bearer foobar');

        $parser = new Parser($request);

        $parser->setChain([
            new QueryString,
            new InputSource,
            (new AuthHeaders)->setHeaderName('custom_authorization'),
            new RouteParams,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_the_alt_authorization_headers()
    {
        $request1 = Request::create('foo', 'POST');
        $request1->server->set('HTTP_AUTHORIZATION', 'Bearer foobar');

        $request2 = Request::create('foo', 'POST');
        $request2->server->set('REDIRECT_HTTP_AUTHORIZATION', 'Bearer foobarbaz');

        $parser = new Parser($request1, [
            new AuthHeaders,
            new QueryString,
            new InputSource,
            new RouteParams,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());

        $parser->setRequest($request2);
        $this->assertSame($parser->parseToken(), 'foobarbaz');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_ignore_non_bearer_tokens()
    {
        $request = Request::create('foo', 'POST');
        $request->headers->set('Authorization', 'Basic OnBhc3N3b3Jk');

        $parser = new Parser($request);

        $parser->setChain([
            new QueryString,
            new InputSource,
            new AuthHeaders,
            new RouteParams,
        ]);

        $this->assertNull($parser->parseToken());
        $this->assertFalse($parser->hasToken());
    }

    /** @test */
    public function it_should_not_strip_trailing_hyphens_from_the_authorization_header()
    {
        $request = Request::create('foo', 'POST');
        $request->headers->set('Authorization', 'Bearer foobar--');

        $parser = new Parser($request);

        $parser->setChain([
            new QueryString,
            new InputSource,
            new AuthHeaders,
            new RouteParams,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar--');
        $this->assertTrue($parser->hasToken());
    }

    /**
     * @test
     *
     * @dataProvider whitespaceProvider
     */
    public function it_should_handle_excess_whitespace_from_the_authorization_header($whitespace)
    {
        $request = Request::create('foo', 'POST');
        $request->headers->set('Authorization', "Bearer{$whitespace}foobar{$whitespace}");

        $parser = new Parser($request);

        $parser->setChain([
            new QueryString,
            new InputSource,
            new AuthHeaders,
            new RouteParams,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    public function whitespaceProvider()
    {
        return [
            'space' => [' '],
            'multiple spaces' => ['    '],
            'tab' => ["\t"],
            'multiple tabs' => ["\t\t\t"],
            'new line' => ["\n"],
            'multiple new lines' => ["\n\n\n"],
            'carriage return' => ["\r"],
            'carriage returns' => ["\r\r\r"],
            'mixture of whitespace' => ["\t \n \r \t \n"],
        ];
    }

    /** @test */
    public function it_should_return_the_token_from_query_string()
    {
        $request = Request::create('foo', 'GET', ['token' => 'foobar']);

        $parser = new Parser($request);
        $parser->setChain([
            new AuthHeaders,
            new QueryString,
            new InputSource,
            new RouteParams,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_the_custom_query_string()
    {
        $request = Request::create('foo', 'GET', ['custom_token_key' => 'foobar']);

        $parser = new Parser($request);
        $parser->setChain([
            new AuthHeaders,
            (new QueryString)->setKey('custom_token_key'),
            new InputSource,
            new RouteParams,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_the_query_string_not_the_input_source()
    {
        $request = Request::create('foo?token=foobar', 'POST', [], [], [], [], json_encode(['token' => 'foobarbaz']));

        $parser = new Parser($request);
        $parser->setChain([
            new AuthHeaders,
            new QueryString,
            new InputSource,
            new RouteParams,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_the_custom_query_string_not_the_custom_input_source()
    {
        $request = Request::create('foo?custom_token_key=foobar', 'POST', [], [], [], [], json_encode(['custom_token_key' => 'foobarbaz']));

        $parser = new Parser($request);
        $parser->setChain([
            new AuthHeaders,
            (new QueryString)->setKey('custom_token_key'),
            (new InputSource)->setKey('custom_token_key'),
            new RouteParams,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_input_source()
    {
        $request = Request::create('foo', 'POST', [], [], [], [], json_encode(['token' => 'foobar']));
        $request->headers->set('Content-Type', 'application/json');

        $parser = new Parser($request);
        $parser->setChain([
            new AuthHeaders,
            new QueryString,
            new InputSource,
            new RouteParams,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_the_custom_input_source()
    {
        $request = Request::create('foo', 'POST', [], [], [], [], json_encode(['custom_token_key' => 'foobar']));
        $request->headers->set('Content-Type', 'application/json');

        $parser = new Parser($request);
        $parser->setChain([
            new AuthHeaders,
            new QueryString,
            (new InputSource)->setKey('custom_token_key'),
            new RouteParams,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_an_unencrypted_cookie()
    {
        $request = Request::create('foo', 'POST', [], ['token' => 'foobar']);

        $parser = new Parser($request);
        $parser->setChain([
            new AuthHeaders,
            new QueryString,
            new InputSource,
            new RouteParams,
            new Cookies(false),
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_a_crypted_cookie()
    {
        Crypt::shouldReceive('encrypt')
            ->with('foobar')
            ->once()
            ->andReturn('cryptedFoobar');

        $request = Request::create('foo', 'POST', [], ['token' => Crypt::encrypt('foobar')]);

        $parser = new Parser($request);
        $parser->setChain([
            new AuthHeaders,
            new QueryString,
            new InputSource,
            new RouteParams,
            new Cookies(true),
        ]);

        Crypt::shouldReceive('decrypt')
            ->with('cryptedFoobar')
            ->times(2)
            ->andReturn('foobar');

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_route()
    {
        $request = Request::create('foo', 'GET', ['foo' => 'bar']);
        $request->setRouteResolver(function () {
            return $this->getRouteMock('foobar');
        });

        $parser = new Parser($request);
        $parser->setChain([
            new AuthHeaders,
            new QueryString,
            new InputSource,
            new RouteParams,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_route_with_a_custom_param()
    {
        $request = Request::create('foo', 'GET', ['foo' => 'bar']);
        $request->setRouteResolver(function () {
            return $this->getRouteMock('foobar', 'custom_route_param');
        });

        $parser = new Parser($request);
        $parser->setChain([
            new AuthHeaders,
            new QueryString,
            new InputSource,
            (new RouteParams)->setKey('custom_route_param'),
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_ignore_routeless_requests()
    {
        $request = Request::create('foo', 'GET', ['foo' => 'bar']);
        $request->setRouteResolver(function () {
            //
        });

        $parser = new Parser($request);
        $parser->setChain([
            new AuthHeaders,
            new QueryString,
            new InputSource,
            new RouteParams,
        ]);

        $this->assertNull($parser->parseToken());
        $this->assertFalse($parser->hasToken());
    }

    /** @test */
    public function it_should_ignore_lumen_request_arrays()
    {
        $request = Request::create('foo', 'GET', ['foo' => 'bar']);
        $request->setRouteResolver(function () {
            return [false, ['uses' => 'someController'], ['token' => 'foobar']];
        });

        $parser = new Parser($request);
        $parser->setChain([
            new AuthHeaders,
            new QueryString,
            new InputSource,
            new RouteParams,
        ]);

        $this->assertNull($parser->parseToken());
        $this->assertFalse($parser->hasToken());
    }

    /** @test */
    public function it_should_accept_lumen_request_arrays_with_special_class()
    {
        $request = Request::create('foo', 'GET', ['foo' => 'bar']);
        $request->setRouteResolver(function () {
            return [false, ['uses' => 'someController'], ['token' => 'foo.bar.baz']];
        });

        $parser = new Parser($request);
        $parser->setChain([
            new AuthHeaders,
            new QueryString,
            new InputSource,
            new LumenRouteParams,
        ]);

        $this->assertSame($parser->parseToken(), 'foo.bar.baz');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_null_if_no_token_in_request()
    {
        $request = Request::create('foo', 'GET', ['foo' => 'bar']);
        $request->setRouteResolver(function () {
            return $this->getRouteMock();
        });

        $parser = new Parser($request);
        $parser->setChain([
            new AuthHeaders,
            new QueryString,
            new InputSource,
            new RouteParams,
        ]);

        $this->assertNull($parser->parseToken());
        $this->assertFalse($parser->hasToken());
    }

    /** @test */
    public function it_should_retrieve_the_chain()
    {
        $chain = [
            new AuthHeaders,
            new QueryString,
            new InputSource,
            new RouteParams,
        ];

        $parser = new Parser(Mockery::mock(Request::class));
        $parser->setChain($chain);

        $this->assertSame($parser->getChain(), $chain);
    }

    /** @test */
    public function it_should_retrieve_the_chain_with_alias()
    {
        $chain = [
            new AuthHeaders,
            new QueryString,
            new InputSource,
            new RouteParams,
        ];

        /* @var \Illuminate\Http\Request $request */
        $request = Mockery::mock(Request::class);

        $parser = new Parser($request);
        $parser->setChainOrder($chain);

        $this->assertSame($parser->getChain(), $chain);
    }

    /** @test */
    public function it_should_set_the_cookie_key()
    {
        $cookies = (new Cookies)->setKey('test');
        $this->assertInstanceOf(Cookies::class, $cookies);
    }

    /** @test */
    public function it_should_add_custom_parser()
    {
        $request = Request::create('foo', 'GET', ['foo' => 'bar']);

        $customParser = Mockery::mock(ParserContract::class);
        $customParser->shouldReceive('parse')->with($request)->andReturn('foobar');

        $parser = new Parser($request);
        $parser->addParser($customParser);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_add_multiple_custom_parser()
    {
        $request = Request::create('foo', 'GET', ['foo' => 'bar']);

        $customParser1 = Mockery::mock(ParserContract::class);
        $customParser1->shouldReceive('parse')->with($request)->andReturn(false);

        $customParser2 = Mockery::mock(ParserContract::class);
        $customParser2->shouldReceive('parse')->with($request)->andReturn('foobar');

        $parser = new Parser($request);
        $parser->addParser([$customParser1, $customParser2]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    protected function getRouteMock($expectedParameterValue = null, $expectedParameterName = 'token')
    {
        return Mockery::mock(Route::class)
            ->shouldReceive('parameter')
            ->with($expectedParameterName)
            ->andReturn($expectedParameterValue)
            ->getMock();
    }
}
