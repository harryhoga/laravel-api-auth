<?php

use Hoga\LaravelApiAuth\Middleware;

return [
    'status' => Middleware::STATUS_ON, // 状态开启或关闭，LaravelApiAuth::STATUS_ON  或者 LaravelApiAuth::STATUS_OFF
    'error_handler' => Middleware::Error_403,//错误处理方式,LaravelApiAuth::Error_Throw 或者 LaravelApiAuth::Error_403
    'log' => Middleware::LOG_OFF,//记录日志,需手工添加日志channel,LaravelApiAuth::LOG_ON 或者 LaravelApiAuth::LOG_OFF
    'roles' => [
        //        '{access_key}' => [
        //            'name' => '{role_name}',        // 角色名字，例如 android
        //            'secret_key' => '{secret_key}',
        //        ],
    ],

    'signature_methods' => [
        'md5' => \Hoga\LaravelApiAuth\Signatures\Md5::class,
    ],

    'skip' => [
        'is' => [Middleware::class, 'default_excludes_handler'],
        'urls'    => [],
    ],

    'timeout' => 60, // 签名失效时间，单位: 秒
];