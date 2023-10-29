<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie;
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
                    ->with('error', 'User not authenticated');
            }


            Cookie::queue(Cookie::forget($this->login_cookie_name));

            //TODO update the session expiry

            return $next($request);
        } catch (\Exception $e) {

            Log::error('CheckAuthenticated: ' . $e->getMessage());

            return redirect('/api/auth/login')
                ->with('error', 'User not authenticated');

            // return redirect('/api/auth/login')
            //     ->withCookie(Cookie::forget($this->cookie_name))
            //     ->with('error', 'User not authenticated');
        }
    }


    //get user using session id
    public function get_user(Request $request)
    {
        $session_id = $request->cookie($this->cookie_name);

        Log::info('CHECKAUTH_MIDDLEWARE SESSION ID' . $session_id);

        if (!$session_id) {
            return [];
        }

        if (!$this->check_session($session_id)) {
            return [];
        }

        $db = new \PDO(env('DB_CONNECTION') . ':' . env('DB_DATABASE'));

        $query = $db->prepare('SELECT * FROM sessions WHERE session_id = ?');

        $query->execute([$session_id]);

        $session = $query->fetch(\PDO::FETCH_ASSOC);

        $user_id = $session['user_id'];

        $query = $db->prepare('SELECT * FROM users WHERE id = ?');

        $query->execute([$user_id]);

        $user = $query->fetch(\PDO::FETCH_ASSOC);

        //remove the password from the user
        unset($user['password']);

        return $user;
    }

    private function check_session($session_id)
    {
        $db = new \PDO(env('DB_CONNECTION') . ':' . env('DB_DATABASE'));
        $now_time = date('Y-m-d H:i:s');

        //and session_expiry >
        $query = $db->prepare('SELECT * FROM sessions WHERE session_id = ?');

        $query->execute([$session_id]);

        $session = $query->fetch(\PDO::FETCH_ASSOC);

        if (!$session) {
            return false;
        }

        return true;
    }
}
