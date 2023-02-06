<?php

namespace Appwrite\Auth\OAuth2;

use Appwrite\Auth\OAuth2;


class Mirea extends OAuth2
{
    /**
     * @var array
     */
    protected array $user = [];

    /**
     * @var array
     */
    protected array $tokens = [];

    /**
     * @var array
     */
    protected array $scopes = [
        'profile',
    ];

    /**
     * @return string
     */
    public function getName(): string
    {
        return 'mirea';
    }

    /**
     * @return string
     */
    public function getLoginURL(): string
    {
        return 'https://lks.mirea.ninja/oauth/authorize?' . \http_build_query([
            'client_id' => $this->appID,
            'redirect_uri' => $this->callback,
            'response_type' => 'code',
            'scope' => $this->getScopes(),
            'state' => \json_encode($this->state)
        ]);
    }

    /**
     * @param string $code
     *
     * @return array
     */
    protected function getTokens(string $code): array
    {
        if (empty($this->tokens)) {
            $this->tokens = \json_decode($this->request(
                'POST',
                'https://lks.mirea.ninja/oauth/token',
                [],
                \http_build_query([
                    'client_id' => $this->appID,
                    'redirect_uri' => $this->callback,
                    'client_secret' => $this->appSecret,
                    'grant_type' => 'authorization_code',
                    'code' => $code
                ])
            ), true);
        }

        return $this->tokens;
    }

    /**
     * @param string $refreshToken
     *
     * @return array
     */
    public function refreshTokens(string $refreshToken): array
    {
        $this->tokens = \json_decode($this->request(
            'POST',
            'https://lks.mirea.ninja/oauth/token',
            [],
            \http_build_query([
                'client_id' => $this->appID,
                'client_secret' => $this->appSecret,
                'grant_type' => 'refresh_token',
                'refresh_token' => $refreshToken
            ])
        ), true);

        if (empty($this->tokens['refresh_token'])) {
            $this->tokens['refresh_token'] = $refreshToken;
        }

        return $this->tokens;
    }

    /**
     * @param string $accessToken
     *
     * @return string
     */
    public function getUserID(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        return $user['ID'] ?? '';
    }

    /**
     * @param string $accessToken
     *
     * @return string
     */
    public function getUserEmail(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        return $user['arUser']['LOGIN'] ?? '';
    }

    /**
     * Always returns true for Mirea.
     *
     * @param string $accessToken
     *
     * @return bool
     */
    public function isEmailVerified(string $accessToken): bool
    {
        $user = $this->getUser($accessToken);

        return $user['arUser']['LOGIN'] ?? false;
    }

    /**
     * Returns the user first, second and last name. If second name is not set, returns only first and last name.
     * If first name is not set, returns email as username.
     * 
     * @param string $accessToken
     *
     * @return string
     */
    public function getUserName(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        if (empty($user['arUser']['NAME']) || $user['arUser']['NAME'] == '') {
            return $user['arUser']['EMAIL'];
        }

        if (empty($user['arUser']['SECOND_NAME']) || $user['arUser']['SECOND_NAME'] == '') {
            return $user['arUser']['NAME'] . ' ' . $user['arUser']['LAST_NAME'];
        }

        return $user['arUser']['NAME'] . ' ' . $user['arUser']['SECOND_NAME'] . ' ' . $user['arUser']['LAST_NAME'];
    }

    /**
     * @param string $accessToken
     *
     * @return array
     */
    protected function getUser(string $accessToken)
    {
        if (empty($this->user)) {
            $this->user = \json_decode($this->request('GET', 'https://lks.mirea.ninja/api/?action=getData&url=https://lk.mirea.ru/profile/', ['Authorization: Bearer ' . $accessToken]), true);
        }

        return $this->user;
    }
}
