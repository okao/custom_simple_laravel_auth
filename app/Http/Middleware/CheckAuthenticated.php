<?php

namespace App\Http\Middleware;

use App\Models\AuthModel;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

class CheckAuthenticated
{
    private $cookie_name = 'user_session';
    // private $login_cookie_name = 'login_cookie';

    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $authModel = new AuthModel();
        $get_user = $authModel->get_user($request);

        try {
            Log::info('CHECKAUTH_MIDDLEWARE USER' . json_encode($get_user));

            //if user array is empty, redirect to login
            if (empty($get_user)) {
                session()->forget('user_session');
                session()->forget('request_code');

                return redirect('/api/auth/login')
                // ->withCookie(Cookie::forget($this->login_cookie_name))
                    ->with('error', 'User not authenticated');
            }

            //TODO update the session expiry

            return $next($request);
        } catch (\Exception $e) {
            session()->forget('user_session');
            session()->forget('request_code');

            Log::error('CheckAuthenticated: ' . $e->getMessage());

            return redirect('/api/auth/login')
            // ->withCookie(Cookie::forget($this->login_cookie_name))
                ->with('error', 'User not authenticated');
        }
    }
}
