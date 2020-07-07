<?php

namespace Shae\IdentityProviderClient;

use LogicException;
use Illuminate\Http\Request;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;

/**
 * Class IDPClientServiceProvider
 *
 * @package Shae\IdentityProviderClient
 */
class IDPClientServiceProvider
{
    /** @var \Lcobucci\JWT\Parser */
    protected $parser;
    /** @var \Lcobucci\JWT\ValidationData */
    protected $validationData;
    /** @var \Lcobucci\JWT\Signer\Rsa\Sha256 */
    protected $algorithm;
    /** @var string */
    protected $publicKeyPath;

    /**
     * IDPClientServiceProvider constructor.
     *
     * @param \Lcobucci\JWT\Parser $parser
     * @param \Lcobucci\JWT\ValidationData $validationData
     * @param \Lcobucci\JWT\Signer\Rsa\Sha256 $algorithm
     */
    public function __construct(
        Parser $parser,
        ValidationData $validationData,
        Sha256 $algorithm
    )
    {
        $this->parser = $parser;
        $this->algorithm = $algorithm;
        $this->validationData = $validationData;

        $this->setPublicKeyPath();
    }

    /**
     * @return string
     */
    public function getPublicKeyPath(): string
    {
        return $this->publicKeyPath;
    }

    /**
     * @param string $publicKeyPath
     */
    public function setPublicKeyPath(string $publicKeyPath = ''): void
    {
        if (empty($publicKeyPath)){
            $publicKeyPath = config('auth.guards.api.public_key');
        }

        if (strpos($publicKeyPath, 'file://') !== 0) {
            $publicKeyPath = 'file://' . $publicKeyPath;
        }

        if (!file_exists($publicKeyPath) || !is_readable($publicKeyPath)) {
            throw new LogicException(sprintf('Key path "%s" does not exist or is not readable', $publicKeyPath));
        }

        // Verify the permissions of the key
        $keyPathPerms = decoct(fileperms($publicKeyPath) & 0777);
        if (in_array($keyPathPerms, ['400', '440', '600', '640', '660'], true) === false) {
            trigger_error(sprintf(
                'Key file "%s" permissions are not correct, recommend changing to 600 or 660 instead of %s',
                $publicKeyPath,
                $keyPathPerms
            ), E_USER_NOTICE);
        }

        $this->publicKeyPath = $publicKeyPath;
    }

    /**
     * Getting user info from JWT and generating User model
     *
     * @param \Illuminate\Http\Request $request
     *
     * @return array|null
     */
    public function userInfo(Request $request): ?array
    {
        $token = $this->getToken($request);

        return $this->getUserInfo($token);
    }

    /**
     * @param \Illuminate\Http\Request $request
     *
     * @return \Lcobucci\JWT\Token
     */
    private function getToken(Request $request): Token
    {
        if ($request->hasHeader('authorization') === false) {
            abort(401, 'Missing "Authorization" header');
        }

        $header = $request->header('authorization');
        $jwt = trim((string) preg_replace('/^(?:\s+)?Bearer\s/', '', $header));
        $token = $this->parser->parse($jwt);

        if ($token->verify($this->algorithm, $this->getPublicKeyPath()) === false) {
            abort(401, 'Jwt token could not be verified');
        }

        // Ensure access token hasn't expired
        $data = new ValidationData();
        $data->setCurrentTime(time());

        if ($token->validate($data) === false) {
            abort(401, 'Jwt token is invalid');
        }

        return $token;
    }

    /**
     * @param \Lcobucci\JWT\Token $token
     *
     * @return array
     */
    private function getUserInfo(Token $token): array
    {
        return (array) $token->getClaim('userinfo');
    }
}
