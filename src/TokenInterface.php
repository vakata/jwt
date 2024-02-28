<?php

namespace vakata\jwt;

interface TokenInterface
{
    public static function fromString(string $token): self;

    /**
     * @return array<string,mixed>
     */
    public function getClaims(): array;
    public function hasClaim(string $key): bool;
    public function getClaim(string $key, mixed $default = null): mixed;
    public function setClaim(string $key, mixed $value, bool $asHeader = false): self;
    /**
     * @param array<string,mixed> $claims
     * @param bool $asHeader
     * @return $this
     */
    public function setClaims(array $claims, bool $asHeader = false): self;
    /**
     * @return array<string,mixed>
     */
    public function getHeaders(): array;
    public function hasHeader(string $key): bool;
    public function getHeader(string $key, mixed $default = null): mixed;
    public function setHeader(string $key, mixed $value): self;

    public function setAudience(mixed $value, bool $asHeader = false): self;
    public function setExpiration(int|string $value, bool $asHeader = false): self;
    public function setId(mixed $value, bool $asHeader = false): self;
    public function setIssuedAt(int|string $value, bool $asHeader = false): self;
    public function setIssuer(mixed $value, bool $asHeader = false): self;
    public function setNotBefore(int|string $value, bool $asHeader = false): self;
    public function setSubject(mixed $value, bool $asHeader = false): self;

    public function isSigned(): bool;
    public function sign(mixed $key, string $pass = '', ?string $kid = null): self;
    public function verifyHash(string $key): bool;
    public function verifySignature(string $key): bool;
    public function verify(string $key, ?string $algo = null): bool;

    /**
     * @param array<string,mixed> $claims
     * @return bool
     */
    public function isValid(array $claims = []): bool;

    public function __toString(): string;
}
