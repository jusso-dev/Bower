<?php

declare(strict_types=1);

namespace App\Providers;

use App\Listeners\BowerAuthListener;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;

final class AppServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        Event::subscribe(BowerAuthListener::class);
    }
}
