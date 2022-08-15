<?php

namespace Hoga\LaravelApiAuth;

use Illuminate\Support\ServiceProvider as LaravelServiceProvider;
use Illuminate\Foundation\Application as LaravelApplication;
use Laravel\Lumen\Application as LumenApplication;

class ServiceProvider extends LaravelServiceProvider
{
    public function register()
    {
        $this->setupConfig();
    }

    /**
     * Setup the config.
     */
    protected function setupConfig()
    {
        $configSource = realpath(__DIR__ . '/config.php');
        if ($this->app instanceof LaravelApplication && $this->app->runningInConsole()) {
            $this->publishes([
                $configSource => config_path('apiauth.php')
            ]);
        } elseif ($this->app instanceof LumenApplication) {
            $this->app->configure('apiauth');
        }
        $this->mergeConfigFrom($configSource, 'apiauth');
        $this->commands([
            Command::class,
        ]);
    }
}
