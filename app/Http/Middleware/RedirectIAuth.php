<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Facades\DB;

class RedirectIAuth
{
    private $home_path = '/api/home';

    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $get_user = $this->get_user($request);

        try {
            if (!$get_user) {
                return $next($request);
            }

            return redirect($this->home_path);
        } catch (\Exception $e) {
            return $next($request);
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
