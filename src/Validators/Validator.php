<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Sheikh0775\JWTAuth\Validators;

use Sheikh0775\JWTAuth\Contracts\Validator as ValidatorContract;
use Sheikh0775\JWTAuth\Exceptions\JWTException;
use Sheikh0775\JWTAuth\Support\RefreshFlow;

abstract class Validator implements ValidatorContract
{
    use RefreshFlow;

    /**
     * Helper function to return a boolean.
     *
     * @param  array  $value
     * @return bool
     */
    public function isValid($value)
    {
        try {
            $this->check($value);
        } catch (JWTException $e) {
            return false;
        }

        return true;
    }

    /**
     * Run the validation.
     *
     * @param  array  $value
     * @return void
     */
    abstract public function check($value);
}
