<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

class CheckAuthenticated
{
    private $cookie_name = 'user_session';
    private $login_cookie_name = 'login_cookie';

    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $get_user = $this->get_user($request);

        try {
            Log::info('CHECKAUTH_MIDDLEWARE USER' . json_encode($get_user));

            //if user array is empty, redirect to login
            if (empty($get_user)) {
                return redirect('/api/auth/login')
                    ->withCookie(Cookie::forget($this->login_cookie_name))
                    ->with('error', 'User not authenticated');
            }

            //TODO update the session expiry

            return $next($request);
        } catch (\Exception $e) {

            Log::error('CheckAuthenticated: ' . $e->getMessage());

            return redirect('/api/auth/login')
                ->withCookie(Cookie::forget($this->login_cookie_name))
                ->with('error', 'User not authenticated');
        }
    }


    //get user using session id
    public function get_user(Request $request)
    {
        $session_id = $request->cookie('user_session');

        if (!$session_id) {
            return [];
        }

        if (!$this->check_session($session_id)) {
            return [];
        }

        $session = DB::table('sessions')->where('session_id', $session_id)->first();

        $user_id = $session->user_id;

        $user = DB::table('users')->where('id', $user_id)->first();

        //remove the password from the user
        unset($user->password);

        return $user;
    }

    private function check_session($session_id)
    {
        $session = DB::table('sessions')->where('session_id', $session_id)
            ->where('valid_until', '>', date('Y-m-d H:i:s'))
            ->first();

        if (!$session) {
            return false;
        }

        return true;
    }
}
