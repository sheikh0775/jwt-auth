<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Sheikh0775\JWTAuth\Test\Stubs;

use Sheikh0775\JWTAuth\Providers\JWT\Provider;

class JWTProviderStub extends Provider
{
    /**
     * {@inheritdoc}
     */
    protected function isAsymmetric()
    {
        return false;
    }
}
