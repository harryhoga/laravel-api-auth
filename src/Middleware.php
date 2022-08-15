<?php

namespace Hoga\LaravelApiAuth;

use Carbon\Exceptions\InvalidIntervalException;
use Closure;
use Exception;
use Illuminate\Http\Request;
use Hoga\LaravelApiAuth\Exceptions\AccessKeyException;
use Hoga\LaravelApiAuth\Exceptions\InvalidTokenException;
use Hoga\LaravelApiAuth\Exceptions\SignatureMethodException;
use Hoga\LaravelApiAuth\Signatures\SignatureInterface;
use Illuminate\Support\Facades\Log;
use phpDocumentor\Reflection\DocBlock\Tags\InvalidTag;

class Middleware
{
    const STATUS_ON = 'on';
    const STATUS_OFF = 'off';

    const LOG_ON = 'on';
    const LOG_OFF = 'off';

    const Error_Throw = 'Error_Throw';
    const Error_403 = 'Error_403';

    const AccessKeyException = 'AccessKeyException';
    const InvalidTokenException = 'InvalidTokenException';
    const SignatureMethodException = 'SignatureMethodException';

    public function __construct()
    {
        $this->config = config('apiauth');
        $this->error403 = $this->config['error_handler'] == static::Error_403;
        $this->logOn = $this->config['log'] == static::LOG_ON;
    }

    /**
     * @param Request  $request
     *
     * @return mixed
     * @throws \Hoga\LaravelApiAuth\Exceptions\AccessKeyException
     * @throws \Hoga\LaravelApiAuth\Exceptions\InvalidTokenException
     * @throws \Hoga\LaravelApiAuth\Exceptions\SignatureMethodException
     */
    private function error_handler($err_msg, $errException)
    {
        if ($this->error403 || !$errException)
            abort(403, $err_msg);
        else {
            switch ($errException) {
                case static::AccessKeyException:
                    throw new AccessKeyException($err_msg);
                case static::InvalidTokenException:
                    throw new InvalidTokenException($err_msg);
                case static::SignatureMethodException:
                    throw new SignatureMethodException($err_msg);
            }
        }
    }

    /**
     * @param Request  $request
     * @param \Closure $next
     *
     * @return mixed
     * @throws \Hoga\LaravelApiAuth\Exceptions\AccessKeyException
     * @throws \Hoga\LaravelApiAuth\Exceptions\InvalidTokenException
     * @throws \Hoga\LaravelApiAuth\Exceptions\SignatureMethodException
     */
    public function handle($request, Closure $next)
    {
        if ($request->getMethod() === 'OPTIONS') {
            return $next($request);
        }

        if ($this->config['status'] === static::STATUS_ON && !$this->is_skip($request)) {
            // 得到 api token
            $token = $request->hasHeader('api-token') ? $request->header('api-token') : $request->get('api-token');

            if($this->logOn) Log::channel('apiAuthLog')->info("------------apiauth开始---------------") ;
            if($this->logOn) Log::channel('apiAuthLog')->info($token);
            // 检查是否存在token
            $this->tokenExistCheck($token);

            // 得到 header 、 payload 、 signature 三段字符串
            list($header_string, $payload_string, $signature) = explode(".", $token);
            if($this->logOn) Log::channel('apiAuthLog')->info(['header_string', $header_string, 'payload_string', $payload_string, 'base64decode_payloadstring', base64_decode($payload_string), 'signature', $signature]);

            list($header, $payload, $alg) = array_values($this->parseParams($header_string, $payload_string));

            if($this->logOn) Log::channel('apiAuthLog')->info(['header', $header, 'payload', $payload, 'alg', $alg]);

            $role = $this->config['roles'][$payload['ak']];
            if($this->logOn) Log::channel('apiAuthLog')->info(['role', $role]);

            if (isset($payload["paramData"]) && count($payload["paramData"])) {
                if($this->logOn) Log::channel('apiAuthLog')->info('参数检查');
                foreach ($payload["paramData"] as $k => $v) {
                    if($this->logOn) Log::channel('apiAuthLog')->info([$k, substr($request->get($k), 0, 100), $v]);
                    if (substr($request->get($k), 0, 100) != $v) {
                        $this->error_handler('token param error!', static::InvalidTokenException);
                    }
                }
            }

            // $my_payload_string = base64_encode(json_encode($payload, true));
            // dump('$my_payload_string', $my_payload_string);
            // 检查签名是否正确
            if($this->logOn) Log::channel('apiAuthLog')->info("$header_string.$payload_string");
            if($this->logOn) Log::channel('apiAuthLog')->info(md5("$header_string.$payload_string"));

            $this->signatureCheck($alg, "$header_string.$payload_string", $role['secret_key'], $signature);

            $request = $this->bindParamsToRequest($request, $role['name'], $payload);
        }

        return $next($request);
    }


    /**
     * 检查是否存在token
     *
     * @param string  $token
     *
     * @throws InvalidTokenException
     */
    public function tokenExistCheck($token)
    {
        if (!$token) {
            $this->error_handler('require token !', static::InvalidTokenException);
        }
    }

    /**
     * 各种参数校验和解析
     *
     * @param string $header_string
     * @param string $payload_string
     *
     * @return array
     * @throws AccessKeyException
     * @throws InvalidTokenException
     * @throws SignatureMethodException
     */
    public function parseParams(string $header_string, string $payload_string): array
    {
        // 检查参数 --begin
        $header  = @json_decode(base64_decode($header_string), true);
        $payload = @json_decode(base64_decode($payload_string), true);

        if (
            !is_array($header) ||
            !isset($header['alg']) ||
            !is_array($payload) ||
            !isset($payload['timestamp']) ||
            !isset($payload['echostr']) ||
            !isset($payload['ak'])
        ) {
            $this->error_handler('invalid token !', static::InvalidTokenException);
        }

        if (!isset($this->config['roles'][$payload['ak']])) {
            $this->error_handler('access key invalid !', new AccessKeyException);
        }

        if (!isset($this->config['signature_methods'][$header['alg']])) {
            $this->error_handler($header['alg'] . ' signatures are not supported !', static::SignatureMethodException);
        }

        $alg = $this->config['signature_methods'][$header['alg']];

        if (!class_exists($alg)) {
            $this->error_handler($header['alg'] . ' signatures method configuration error !', static::SignatureMethodException);
        }

        $alg = new $alg;

        if (!$alg instanceof SignatureInterface) {
            $this->error_handler($header['alg'] . ' signatures method configuration error !', static::SignatureMethodException);
        }

        // 检查参数 --end
        return compact('header', 'payload', 'alg');
    }

    /**
     * 校验签名是否正确
     *
     * @param SignatureInterface $alg
     * @param string             $signature_string
     * @param string             $secret
     * @param                    $signature
     *
     * @throws InvalidTokenException
     */
    public function signatureCheck(SignatureInterface $alg, string $signature_string, string $secret, $signature): void
    {
        if($this->logOn) Log::channel('apiAuthLog')->info(["md5 sign:", md5($signature_string . $secret), '$signature', $signature, 'result', md5($signature_string . $secret) === $signature]);
        if (!$alg::check($signature_string, $secret, $signature)) {
            $this->error_handler('invalid token !', static::InvalidTokenException);
        }
    }

    /**
     * @param Request $request
     * @param string  $role_name
     * @param array   $payload
     *
     * @return Request
     */
    public function bindParamsToRequest($request, string $role_name, array $payload)
    {
        // 添加 role_name 到 $request 中
        if ($request->has('client_role')) {
            $request->offsetSet('_client_role', $request->get('client_role'));
        }
        $request->offsetSet('client_role', $role_name);

        // 添加 api_payload 到 $request 中
        if ($request->has('api_payload')) {
            $request->offsetSet('_api_payload', $request->get('api_payload'));
        }
        $request->offsetSet('api_payload', $payload);

        return $request;
    }

    public function is_skip(Request $request): bool
    {
        $handler = [static::class, 'default_skip_handler'];

        if (is_callable($this->config['skip']['is'])) {
            $handler = $this->config['skip']['is'];
        }

        return call_user_func_array($handler, [$request, $this->config['skip']['urls']]);
    }

    /**
     * @param Request $request
     * @param array   $urls
     *
     * @return bool
     */
    public static function default_skip_handler(Request $request, array $urls = []): bool
    {
        if (in_array($request->url(), $urls)) {
            return true;
        }

        return false;
    }
}
