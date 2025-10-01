<?php

namespace App\Service;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class JwtService
{
    private string $jwtSecret;

    public function __construct(string $jwtSecret)
    {
        $this->jwtSecret = $jwtSecret;
    }

    public function generateToken(array $payload, int $expirySeconds = 3600): string
    {
        $issuedAt = time();
        $expire = $issuedAt + $expirySeconds;

        $token = [
            "iat" => $issuedAt,
            "exp" => $expire,
            "data" => $payload
        ];

        return JWT::encode($token, $this->jwtSecret, 'HS256');
    }

    public function validateToken(string $token): ?array
    {
        try {
            $decoded = JWT::decode($token, new Key($this->jwtSecret, 'HS256'));
            return (array)$decoded->data;
        } catch (\Exception $e) {
            return null;
        }
    }
}
