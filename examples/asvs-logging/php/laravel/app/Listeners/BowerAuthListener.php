<?php

declare(strict_types=1);

namespace App\Listeners;

use App\BowerSecurity;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Events\Dispatcher;

/** Laravel authentication events to Bower (ASVS 5.0 V16.3.1, V6.4.3, V7.4.1). */
final class BowerAuthListener
{
    public function subscribe(Dispatcher $events): void
    {
        $events->listen(Login::class, function (Login $e): void {
            BowerSecurity::emit(request(), ['eventCategory' => 'authentication', 'eventType' => 'authentication_success',
                'eventAction' => 'authentication.login', 'eventResult' => 'success',
                'actor' => ['userId' => (string) $e->user->getAuthIdentifier(), 'username' => $e->user->email ?? null],
                'labels' => ['authMethod' => 'password', 'guard' => $e->guard]]);
        });
        $events->listen(Failed::class, function (Failed $e): void {
            // $e->credentials holds the submitted password: only the username is read.
            BowerSecurity::emit(request(), ['eventCategory' => 'authentication', 'eventType' => 'authentication_failure',
                'eventAction' => 'authentication.attempt', 'eventResult' => 'failure', 'eventSeverity' => 'low',
                'reason' => $e->user === null ? 'UnknownAccount' : 'InvalidCredentials',
                'actor' => ['username' => (string) ($e->credentials['email'] ?? $e->credentials['username'] ?? '')]]);
        });
        $events->listen(Lockout::class, function (Lockout $e): void {
            BowerSecurity::emit($e->request, ['eventCategory' => 'authentication', 'eventType' => 'account_lockout',
                'eventAction' => 'authentication.lockout', 'eventResult' => 'failure', 'eventSeverity' => 'medium',
                'reason' => 'TooManyAttempts', 'actor' => ['username' => (string) $e->request->input('email', '')]]);
        });
        $events->listen(Logout::class, function (Logout $e): void {
            if ($e->user !== null) {
                BowerSecurity::emit(request(), ['eventCategory' => 'authentication', 'eventType' => 'session_terminated',
                    'eventAction' => 'session.logout', 'eventResult' => 'success',
                    'actor' => ['userId' => (string) $e->user->getAuthIdentifier()]]);
            }
        });
        $events->listen(PasswordReset::class, function (PasswordReset $e): void {
            BowerSecurity::emit(request(), ['eventCategory' => 'identity-management', 'eventType' => 'password_reset_completed',
                'eventAction' => 'password.reset_complete', 'eventResult' => 'success',
                'actor' => ['userId' => (string) $e->user->getAuthIdentifier()],
                'target' => ['type' => 'user', 'id' => (string) $e->user->getAuthIdentifier()]]);
        });
    }
}
