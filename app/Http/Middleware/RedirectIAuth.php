<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie;
use Symfony\Component\HttpFoundation\Response;

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

        $query = $db->prepare('SELECT * FROM sessions WHERE session_id = ?');

        $query->execute([$session_id]);

        $session = $query->fetch(\PDO::FETCH_ASSOC);

        if (!$session) {
            return false;
        }

        return true;
    }
}
