<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Log;
use App\Models\AuthModel;

class AuthController extends Controller
{
    private $cookie_ttl = 5;
    private $session_ttl = 5; //5 minutes
    private $login_cookie_name = 'login_cookie';
    private $session_name = 'user_session';


    public function login(Request $request)
    {
        //from AuthModel call the initialize method
        $auth_model = new AuthModel();
        $auth_model->initialize();
        $cookie = $request->cookie($this->login_cookie_name);
        $credentials = json_decode($cookie, true);

        try {
            if ($auth_model->check_user_auth($credentials['username'], $credentials['password'])) {
                return redirect('/api/auth/consent')
                    ->cookie(
                        $this->login_cookie_name,
                        json_encode($credentials),
                        $this->cookie_ttl,
                        '/api/auth',
                        null,
                        false,
                        true
                    )
                    ->with('success', 'Login success');
            } else {
                Cookie::queue(Cookie::forget($this->login_cookie_name));
                return view('auth.login');
            }
        } catch (\Exception $e) {

            Cookie::queue(Cookie::forget('login_cookie'));
            return view('auth.login');
        }
    }

    public function submit_login(Request $request)
    {
        $auth_model = new AuthModel();

        $credentials = [
            'username' => $request->username,
            'password' => $request->password,
            'consent' => 'false',
            'two_fa' => 'false'
        ];

        try {
            if (!$auth_model->check_user_auth($credentials['username'], $credentials['password'])) {
                Cookie::queue(Cookie::forget('login_cookie'));

                return redirect('/api/auth/login')
                    ->with('error', 'Login failed')
                    ->withInput();
            }

            //send the user to the consent page with the cookie
            return redirect('/api/auth/consent')
                ->cookie($this->login_cookie_name, json_encode($credentials), $this->cookie_ttl, '/api/auth', null, false, true)
                ->with('success', 'Login success');
        } catch (\Exception $e) {
            Cookie::queue(Cookie::forget('login_cookie'));

            return redirect('/api/auth/login')
                ->with('error', 'Login failed')
                ->withInput();
        }
    }

    public function consent(Request $request)
    {
        $auth_model = new AuthModel();
        $get_user_from_login_cookie = $auth_model->get_user_from_login_cookie($request);

        try {
            if (!$get_user_from_login_cookie) {
                //forget the cookie from the request
                Cookie::queue(Cookie::forget('login_cookie'));

                return redirect('/api/auth/login')
                    ->with('error', 'Login failed')
                    ->withInput();
            }

            if ($get_user_from_login_cookie['consent'] == 'true') {
                return redirect('/api/auth/2fa')
                    ->cookie('login_cookie', json_encode($get_user_from_login_cookie), $this->cookie_ttl, '/api/auth', null, false, true)
                    ->with('success', 'Consent provided successfully');
            } else {
                Cookie::make('login_cookie', json_encode($get_user_from_login_cookie), $this->cookie_ttl, '/api/auth', null, false, true);

                return view('auth.consent');
            }
        } catch (\Exception $e) {
            Cookie::queue(Cookie::forget('login_cookie'));

            return redirect('/api/auth/login')
                ->with('error', 'Login failed')
                ->withInput();
        }
    }

    public function submit_consent(Request $request)
    {
        $auth_model = new AuthModel();
        $get_user_from_login_cookie = $auth_model->get_user_from_login_cookie($request);

        try {
            if (!$get_user_from_login_cookie) {
                //forget the cookie from the request
                Cookie::queue(Cookie::forget('login_cookie'));

                return redirect('/api/auth/login')
                    ->with('error', 'Login failed')
                    ->withInput();
            }

            $consent = 'true';
            $get_user_from_login_cookie['consent'] = $consent;

            //create 2fa code and send it to the user
            $auth_model->send_2fa_code($get_user_from_login_cookie['id']);

            //send the user to the consent page with the cookie
            return redirect('/api/auth/2fa')
                ->cookie('login_cookie', json_encode($get_user_from_login_cookie), $this->cookie_ttl, '/api/auth', null, false, true)
                ->with('success', 'Consent provided successfully');
        } catch (\Exception $e) {
            Cookie::queue(Cookie::forget('login_cookie'));

            return redirect('/api/auth/login')
                ->with('error', 'Login failed')
                ->withInput();
        }
    }

    public function two_factor(Request $request)
    {
        $auth_model = new AuthModel();
        $get_user_from_login_cookie = $auth_model->get_user_from_login_cookie($request);

        try {
            if (!$get_user_from_login_cookie) {
                //forget the cookie from the request
                Cookie::queue(Cookie::forget('login_cookie'));

                return redirect('/api/auth/login')
                    ->with('error', 'Login failed')
                    ->withInput();
            }

            if ($get_user_from_login_cookie['two_fa'] == 'true' && $get_user_from_login_cookie['consent'] == 'true') {
                return redirect('/api/home')
                    ->cookie('user_session', $auth_model->create_session_id($get_user_from_login_cookie['id'], 'true', date('Y-m-d H:i:s', time() + $this->session_ttl)), $this->cookie_ttl, '/api/auth', null, false, true)
                    ->with('success', '2FA provided successfully');
            } else {

                if ($get_user_from_login_cookie['consent'] == 'false') {

                    Cookie::queue(Cookie::forget('login_cookie'));
                    return redirect('/api/auth/login')
                        ->with('error', 'Login failed')
                        ->withInput();
                }

                Cookie::make('login_cookie', json_encode($get_user_from_login_cookie), $this->cookie_ttl, '/api/auth', null, false, true);

                return view('auth.2fa');
            }
        } catch (\Exception $e) {
            Cookie::queue(Cookie::forget('login_cookie'));

            return redirect('/api/auth/login')
                ->with('error', 'Login failed')
                ->withInput();
        }
    }


    public function submit_two_factor(Request $request)
    {
        $auth_model = new AuthModel();
        $get_user_from_login_cookie = $auth_model->get_user_from_login_cookie($request);

        try {
            if (!$get_user_from_login_cookie) {
                Cookie::queue(Cookie::forget('login_cookie'));
                return redirect('/api/auth/login')
                    ->with('error', 'Login failed')
                    ->withInput();
            }

            if (!$auth_model->verify_2fa($request)) {
                return redirect('/api/auth/2fa')
                    ->with('error', '2FA failed, Please try again')
                    ->withInput();
            }

            $two_factor = 'true';
            $get_user_from_login_cookie['two_fa'] = $two_factor;
            $id = $get_user_from_login_cookie['id'];

            //create the session id
            $session_id = $auth_model->create_session_id($id, 'true', date('Y-m-d H:i:s', time() + $this->session_ttl));

            return redirect('/api/home')
                ->cookie('user_session', $session_id, $this->cookie_ttl, '/api', null, false, true)
                ->with('success', 'Successfully logged in');
        } catch (\Exception $e) {

            Cookie::queue(Cookie::forget('login_cookie'));

            return redirect('/api/auth/login')
                ->with('error', 'Login failed')
                ->withInput();
        }
    }

    public function home(Request $request)
    {
        try {
            $auth_model = new AuthModel();
            $user = $auth_model->get_user($request);

            return view('home', ['user' => $user]);
        } catch (\Exception $e) {
            Log::info(['CredentialsH' => $e->getMessage()]);
        }
    }

    private function create_session($user_id, $session_id, $validity, $valid_until)
    {
        $db = new \PDO(env('DB_CONNECTION') . ':' . env('DB_DATABASE'));

        $query = $db->prepare('INSERT INTO sessions (user_id, session_id, validity, valid_until) VALUES (?, ?, ?, ?)');

        $query->execute([$user_id, $session_id, $validity, $valid_until]);
    }

    private function delete_user_sessions($user_id)
    {
        //delete the sessions
        $db = new \PDO(env('DB_CONNECTION') . ':' . env('DB_DATABASE'));

        $query = $db->prepare('DELETE FROM sessions WHERE user_id = ?');

        $query->execute([$user_id]);
    }


    // resend_verification
    public function resend_verification(Request $request)
    {
        //get the user from cookie
        $auth_model = new AuthModel();
        $user = $auth_model->get_user_from_login_cookie($request);

        if (!$user) {
            return response()->json(['message' => 'User not found, Therefore unauthorized'], 401);
        }

        //send the verification email
        $auth_model->send_2fa_code($user['id']);

        return response()->json(['message' => 'Verification email sent successfully'], 200);
    }

    //logout the user and delete the session from the db
    public function logout(Request $request)
    {
        $auth_model = new AuthModel();
        $auth_model->delete_session($request->cookie('user_session'));

        return redirect('/api/home')
            ->withCookie(Cookie::forget('user_session'))
            ->with('success', 'Successfully logged out');
    }
}
