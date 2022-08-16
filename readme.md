# laravel-api-auth
laravel API 鉴权

修改自sunding0308/laravel-api-auth,添加了对post参数的验证,避免穷举法暴力调用api.

这是一个 laravel 的 API 鉴权包， `laravel-api-auth` 采用 `jwt token` 的鉴权方式，只要客户端不被反编译从而泄露密钥，该鉴权方式理论上来说是安全的。
PS: web 前端 API 没有绝对的安全，该项目的本意是给不暴露源码的客户端提供一种鉴权方案(如 service、APP客户端)。

## 安装  
```bash
composer require hoga/laravel-api-auth
```

## 配置
1. 注册 `ServiceProvider`: 
    ```php
    Hoga\LaravelApiAuth\ServiceProvider::class,
    ```
    > laravel 5.5+ 版本不需要手动注册

2. 发布配置文件
    ```php
    php artisan vendor:publish --provider="Hoga\LaravelApiAuth\ServiceProvider"
    ```

3. 在 `App\Http\Kernal` 中注册中间件 
    ```php
    protected $routeMiddleware = [
        'apiauth' => \Hoga\LaravelApiAuth\Middleware::class,
        // other ...
    ];
    ```
    
4. 添加 `role` 
    ```php
    php artisan apiauth
    ```
    然后按照格式把 `access_key` 和 `secret_key` 添加到, `config/apiauth.php` 里面的 `roles` 数组中。
    ```php
    'roles' => [
        '{access_key}' => [
            'name' => '{role_name}',        // 角色名字，例如 android
            'secret_key' => '{secret_key}',
        ],
    ],
    ```

5. 自定义签名方法 (可选)
    `config/apiauth.php` 中的 `signature_methods` 可以添加自定义的签名类，该类需要继承自 `Hoga\LaravelApiAuth\Signatures\SignatureInterface` 接口 
    ```php
   <?php
    /**
     * User: hoga
     * Date: 2022/8/16
     * Time: 下午3:22
     */
    
    namespace Hoga\LaravelApiAuth\Signatures;

    class Md5 implements SignatureInterface
    {
        public static function sign(string $string, string $secret): string
        {
            return md5($string . $secret);
        }
    
        public static function check(string $string, string $secret, string $signature): bool
        {
            return static::sign($string, $secret) === $signature;
        }
    
    }
    ```
7. 自定义错误处理
    token 校验不通过的情况下会抛异常，请在 `Handler` 捕获后自行处理。
    目前有三种异常 ： 
    1. AccessKeyException
    2. InvalidTokenException
    3. SignatureMethodException
     
## 使用

### 路由中
```php
Route::get('api/example', function(Request $request){
    // $request->get('client_role');
    // todo...
})->middleware(['apiauth']);

\\ or

Route::group(['middleware'=>'apiauth'], function(){
    // routes...
});
```
> 通过验证后 `$request` 会添加一个 `client_role` 字段，该字段为客户端的角色名称。

### 前端
```javascript
import axios from 'axios';
import { Base64 } from 'js-base64';
import md5 from 'js-md5'; // md5 库自行引入
import qs from 'qs';

const md5Sign = (string, secret) => {
  return md5(string + secret);
}

const randomString = (length) => {
  var str = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  var result = '';
  for (var i = length; i > 0; --i)
    result += str[Math.floor(Math.random() * str.length)];
  return result;
}

axios.defaults.withCredentials = true
const access_key = 'x08HATF5hNgRGYHJ83ngAuAmFsippzxf';  // 服务端生成的 access_key
const secret_key = 'GDNU17l6egiFryJpOSRzx0KUruTufDoO';  // 服务端生成的 secret_key

const header = Base64.encode(JSON.stringify({
  "alg": "md5",
  "type": "jwt"
}));

const ajaxPost = (params) => {
  const timestamp = Date.parse(new Date()) / 1000;    // 取时间戳
  let ak = {
    "timestamp": timestamp.toString(),
    "echostr": randomString(16),
    "ak": access_key,
    "paramData": {}
  };
  //checkparam 需要检验的参数, 长度过长需缩减
  for (let key in params) 
    ak.paramData[key] = params[key] && params[key].length>100 ? params[key].slice(0, 100) : params[key];
  const payload = Base64.encode(JSON.stringify(ak));
  const signature_string = header + '.' + payload;
  const api_token = signature_string + '.' + md5Sign(signature_string, secret_key);

  let requestConfig = {
    headers: {
      "api-token": api_token
    }
  };

  axios.post('{api-url}', params, requestConfig)
    .then(res => {
      console.log(res.data);
    }, err => {
      console.log(err)
    });
}
let data = { xxx : val};
ajaxPost(data);

```
> 本例子为 `web` 前端的例子，其他客户端同理，生成签名并且带上指定参数即可正常请求。
> 通过自定义签名方法和自定义校验方法，可以使用其他加密方法进行签名，例如 `哈希` 等其他加密算法。
