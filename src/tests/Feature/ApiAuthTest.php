<?php

namespace Hoga\LaravelApiAuth\Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Foundation\Testing\WithFaker;
use Tests\TestCase;
use Illuminate\Support\Carbon;

use Faker;

class ApiAuthTest extends TestCase
{
    public $access_key = 'IvTBg8eetJQasbkzELnknObmUmzeBtqb';
    public $secret_key = 'KGQtV42DkjTOypJGaYP5uwJMhkduN4c7';  // 服务端生成的 secret_key
    /**
     * A basic feature test example.
     *
     * @return void
     */
    public function test_auth_result()
    {
        $faker = Faker\Factory::create();
        $params = [
            'openid' => 124,
            'name'=>$faker->name(),
            'email' => $faker->freeEmail(),
            'sentence' =>$faker->sentence(),
            'text'=>$faker->text,
            'textlong'=>$faker->text($maxNbChars = 200),
            'words'=>json_encode($faker->words($nb = 3, $asText = false), JSON_UNESCAPED_SLASHES| JSON_UNESCAPED_UNICODE),
            'phonenumber'=>$faker->tollFreePhoneNumber.$faker->phoneNumber(),
            'company'=>$faker->catchPhrase(),
            'dateTime'=>$faker->iso8601($max = 'now'),
            'url'=>$faker->url(),
        ];
        $response = $this->ajaxPost($params);
        // dd($response);
        $response->assertStatus(200);
    }

    private function ajaxPost($params)
    {
        $header = base64_encode(json_encode([
            "alg" => "md5",
            "type" => "jwt"
        ], JSON_UNESCAPED_UNICODE));
        $ak = [
            "timestamp" => Carbon::now()->timestamp,
            "echostr" => str_rand(16),
            "ak" => $this->access_key,
            "paramData" => []
        ];
        foreach ($params as $k => $v) {
            $ak["paramData"][$k] = substr($v, 0, 100);
        }
        // dd(json_encode($ak,JSON_UNESCAPED_SLASHES| JSON_UNESCAPED_UNICODE));
        $payload = base64_encode(json_encode($ak, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        $signature_string = "{$header}.{$payload}";
        $api_token = $signature_string . '.' . md5($signature_string . $this->secret_key);

        // dd( md5($signature_string, $this->secret_key));

        $response = $this->withHeaders([
            "api-token" => $api_token,
        ])
            ->post('http://laravel-api-auth.cn/api/testauth', $params);
        return $response;
    }
}
