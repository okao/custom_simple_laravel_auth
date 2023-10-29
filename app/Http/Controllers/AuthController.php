<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Log;

class AuthController extends Controller
{
    private $username = 'admin';
    private $password = 'admin';
    private $cookie_ttl = 5;
    private $session_ttl = 5; //5 minutes
    private $login_cookie_name = 'login_cookie';
    private $session_name = 'user_session';


    private function init()
    {
        //create the sqllite db if it does not exist in the root directory
        $db = new \PDO(env('DB_CONNECTION') . ':' . env('DB_DATABASE'));
        $db->exec('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT, consent TEXT, two_factor TEXT)');

        $hashed_password = password_hash($this->password, PASSWORD_DEFAULT);
        //add session table if it does not exist
        $db->exec(
            'CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            session_id TEXT,
            validity boolean DEFAULT false,
            valid_until DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id))'
        );

        //create two_factor table if it does not exist
        $db->exec(
            'CREATE TABLE IF NOT EXISTS two_factor (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            two_factor_code TEXT,
            method TEXT DEFAULT "mobile",
            valid_until DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id))'
        );

        //create user number of failed attempts table if it does not exist
        $db->exec(
            'CREATE TABLE IF NOT EXISTS user_failed_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            number_of_attempts INTEGER DEFAULT 0,
            temporary_lockout_status boolean DEFAULT false,
            temporary_lockout_until DATETIME DEFAULT CURRENT_TIMESTAMP,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id))'
        );

        //add the user to the db if it does not exist
        $query = $db->prepare('SELECT * FROM users WHERE username = ?');

        $query->execute([$this->username]);

        $user = $query->fetch(\PDO::FETCH_ASSOC);

        if (!$user) {
            $query = $db->prepare('INSERT INTO users (username, password, consent, two_factor) VALUES (?, ?, ?, ?)');

            $query->execute([$this->username, $hashed_password, 'false', 'false']);
        } else {
            $query = $db->prepare('UPDATE users SET password = ?, consent = ?, two_factor = ? WHERE username = ?');

            $query->execute([$hashed_password, 'false', 'false', $this->username]);
        }
    }

    public function login(Request $request)
    {
        $this->init();

        $cookie_name = 'login_cookie';
        $cookie = $request->cookie($cookie_name);
        $credentials = json_decode($cookie, true);

        try {
            if ($this->check_user_auth($credentials['username'], $credentials['password'])) {
                return redirect('/api/auth/consent')
                    ->cookie(
                        $cookie_name,
                        json_encode($credentials),
                        $this->cookie_ttl,
                        '/api/auth',
                        null,
                        false,
                        true
                    )
                    ->with('success', 'Login success');
            } else {
                Cookie::queue(Cookie::forget($cookie_name));
                return view('auth.login');
            }
        } catch (\Exception $e) {

            Cookie::queue(Cookie::forget('login_cookie'));

            //redirect to login page but if the request was from the login page then return the view
            return view('auth.login');
        }
    }

    public function submit_login(Request $request)
    {
        $cookie_name = 'login_cookie';
        $credentials = [
            'username' => $request->username,
            'password' => $request->password,
            'consent' => 'false',
            'two_fa' => 'false'
        ];

        try {
            //check if the user is authenticated successfully
            if (!$this->check_user_auth($credentials['username'], $credentials['password'])) {
                //forget the cookie from the request
                Cookie::queue(Cookie::forget('login_cookie'));

                return redirect('/api/auth/login')
                    ->with('error', 'Login failed')
                    ->withInput();
            }

            //send the user to the consent page with the cookie
            return redirect('/api/auth/consent')
                ->cookie($cookie_name, json_encode($credentials), $this->cookie_ttl, '/api/auth', null, false, true)
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
        $get_user_from_login_cookie = $this->get_user_from_login_cookie($request);

        try {
            if (!$get_user_from_login_cookie) {
                //forget the cookie from the request
                Cookie::queue(Cookie::forget('login_cookie'));

                return redirect('/api/auth/login')
                    ->with('error', 'Login failed')
                    ->withInput();
            }
            //to consent cookie

            if ($get_user_from_login_cookie['consent'] == 'true') {
                return redirect('/api/auth/2fa')
                    ->cookie('login_cookie', json_encode($get_user_from_login_cookie), $this->cookie_ttl, '/api/auth', null, false, true)
                    ->with('success', 'Consent provided successfully');
            } else {
                Cookie::queue(Cookie::forget('login_cookie'));

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
        $get_user_from_login_cookie = $this->get_user_from_login_cookie($request);

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
            $this->send_2fa_code($get_user_from_login_cookie['id']);

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
        $get_user_from_login_cookie = $this->get_user_from_login_cookie($request);

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
                    ->cookie('user_session', $this->create_session_id($get_user_from_login_cookie['id'], 'true', date('Y-m-d H:i:s', time() + $this->session_ttl)), $this->cookie_ttl, '/api/auth', null, false, true)
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
        $get_user_from_login_cookie = $this->get_user_from_login_cookie($request);

        try {
            if (!$get_user_from_login_cookie) {
                //forget the cookie from the request
                Cookie::queue(Cookie::forget('login_cookie'));

                return redirect('/api/auth/login')
                    ->with('error', 'Login failed')
                    ->withInput();
            }

            if (!$this->verify_2fa($request)) {
                return redirect('/api/auth/2fa')
                    ->with('error', '2FA failed, Please try again')
                    ->withInput();
                // Cookie::queue(Cookie::forget('login_cookie'));
            }

            $two_factor = 'true';
            $get_user_from_login_cookie['two_fa'] = $two_factor;
            $id = $get_user_from_login_cookie['id'];

            //create the session id
            $session_id = $this->create_session_id($id, 'true', date('Y-m-d H:i:s', time() + $this->session_ttl));

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
        //get the user from the session id
        $user = $this->get_user($request);

        Log::info(['USER HOME' => $user]);

        try {
            //show the home page with the user
            return view('home', ['user' => $user]);
        } catch (\Exception $e) {
            Log::info(['CredentialsH' => $e->getMessage()]);
        }
    }


    //get user from login cookie
    public function get_user_from_login_cookie(Request $request)
    {
        $login_cookie = $request->cookie($this->login_cookie_name);

        if (!$login_cookie) {
            return [];
        }

        $user = json_decode($login_cookie, true);

        if (!$user) {
            return [];
        }

        if (!$this->check_user_auth($user['username'], $user['password'])) {
            return [];
        }


        //get the user from the db
        $db = new \PDO(env('DB_CONNECTION') . ':' . env('DB_DATABASE'));

        $query = $db->prepare('SELECT * FROM users WHERE username = ?');

        $query->execute([$user['username']]);

        $db_user = $query->fetch(\PDO::FETCH_ASSOC);

        if (!$db_user) {
            return [];
        }

        //check if the user and db user passwords match
        if (!password_verify($user['password'], $db_user['password'])) {
            return [];
        }

        //to user append the id
        $user['id'] = $db_user['id'];

        return $user;
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

    private function create_session($user_id, $session_id, $validity, $valid_until)
    {
        $db = new \PDO(env('DB_CONNECTION') . ':' . env('DB_DATABASE'));

        $query = $db->prepare('INSERT INTO sessions (user_id, session_id, validity, valid_until) VALUES (?, ?, ?, ?)');

        $query->execute([$user_id, $session_id, $validity, $valid_until]);
    }

    private function create_session_id($user_id, $validity, $valid_until)
    {

        $session_id = bin2hex(random_bytes(32));

        $this->create_session($user_id, $session_id, $validity, $valid_until);

        return $session_id;
    }

    private function update_session_id($session_id, $validity, $valid_until)
    {
        $this->update_session($session_id, $validity, $valid_until);

        //update the cookie in the browser
        Cookie::queue($this->session_name, $session_id, $this->cookie_ttl, '/api/auth', null, false, true);

        return $session_id;
    }

    private function check_user_auth($username, $password)
    {
        $db = new \PDO(env('DB_CONNECTION') . ':' . env('DB_DATABASE'));

        $query = $db->prepare('SELECT * FROM users WHERE username = ?');

        $query->execute([$username]);

        $user = $query->fetch(\PDO::FETCH_ASSOC);

        if (!$user) {
            return false;
        }

        if (!password_verify($password, $user['password'])) {
            return false;
        }

        return true;
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

    private function update_session($session_id, $validity, $valid_until)
    {
        $db = new \PDO(env('DB_CONNECTION') . ':' . env('DB_DATABASE'));

        $query = $db->prepare('UPDATE sessions SET validity = ?, valid_until = ? WHERE session_id = ?');

        $query->execute([$validity, $valid_until, $session_id]);
    }

    private function delete_user_sessions($user_id)
    {
        //delete the sessions
        $db = new \PDO(env('DB_CONNECTION') . ':' . env('DB_DATABASE'));

        $query = $db->prepare('DELETE FROM sessions WHERE user_id = ?');

        $query->execute([$user_id]);
    }

    private function delete_session($session_id)
    {
        //delete the sessions
        $db = new \PDO(env('DB_CONNECTION') . ':' . env('DB_DATABASE'));

        $query = $db->prepare('DELETE FROM sessions WHERE session_id = ?');

        $query->execute([$session_id]);


        //also invalidate the cookie called user_session in the browser
        Cookie::queue(Cookie::forget('user_session'));
    }


    // resend_verification
    public function resend_verification(Request $request)
    {
        //get the user from cookie
        $user = $this->get_user_from_login_cookie($request);

        if (!$user) {
            return response()->json(['message' => 'User not found, Therefore unauthorized'], 401);
        }

        //send the verification email
        $this->send_2fa_code($user['id']);

        return response()->json(['message' => 'Verification email sent successfully'], 200);
    }

    //send 2fa code after creating it
    private function send_2fa_code($user_id)
    {
        //get the user from the db
        $db = new \PDO(env('DB_CONNECTION') . ':' . env('DB_DATABASE'));

        $query = $db->prepare('SELECT * FROM users WHERE id = ?');

        $query->execute([$user_id]);

        $user = $query->fetch(\PDO::FETCH_ASSOC);

        if (!$user) {
            return false;
        }

        //generate the 2fa code which is a random 6 digit number
        $two_factor_code = rand(100000, 999999);

        //create the two factor code in the db
        $valid_until = date('Y-m-d H:i:s', time() + 60 * 5); //5 minutes

        $query = $db->prepare('INSERT INTO two_factor (user_id, two_factor_code, valid_until) VALUES (?, ?, ?)');
        $query->execute([$user_id, $two_factor_code, $valid_until]);

        //TODO send the 2fa code to the user
        Log::info(['TwoFA Code' => $two_factor_code]);

        return true;
    }

    //verify 2fa code
    private function verify_2fa(Request $request)
    {
        Log::info("=======================TWO FACTOR VERIFICATION=======================");

        Log::info(['REQUEST' => $request->all()]);
        try {
            //get the user from cookie
            $user = $this->get_user_from_login_cookie($request);

            Log::info(['USER FROM COOKIE' => $user]);

            if (!$user) {
                return false;
            }

            //get the two factor code from the request
            $two_factor_code = $request->code;

            //get the two factor code from the db
            $db = new \PDO(env('DB_CONNECTION') . ':' . env('DB_DATABASE'));

            $query = $db->prepare('SELECT * FROM two_factor WHERE user_id = ? AND two_factor_code = ?');

            $query->execute([$user['id'], $two_factor_code]);

            $two_factor = $query->fetch(\PDO::FETCH_ASSOC);


            //check if the two factor code is expired
            $now_time = date('Y-m-d H:i:s');

            if ($two_factor['valid_until'] < $now_time) {
                return false;
            }

            if (!$two_factor) {

                //Increment the number of failed attempts
                $query = $db->prepare('SELECT * FROM user_failed_attempts WHERE user_id = ?');

                $query->execute([$user['id']]);

                $user_failed_attempts = $query->fetch(\PDO::FETCH_ASSOC);


                if (!$user_failed_attempts) {
                    //create the user failed attempts
                    $query = $db->prepare('INSERT INTO user_failed_attempts (user_id, number_of_attempts) VALUES (?, ?)');

                    $query->execute([$user['id'], 1]);
                } else {
                    //increment the number of attempts
                    $query = $db->prepare('UPDATE user_failed_attempts SET number_of_attempts = ? WHERE user_id = ?');

                    $query->execute([$user_failed_attempts['number_of_attempts'] + 1, $user['id']]);
                }


                //check if the number of attempts is greater than 3
                if ($user_failed_attempts['number_of_attempts'] >= 3) {
                    //lock the user out for 5 minutes
                    $query = $db->prepare('UPDATE user_failed_attempts SET temporary_lockout_status = ?, temporary_lockout_until = ? WHERE user_id = ?');
                    $query->execute(['true', date('Y-m-d H:i:s', time() + 60 * 5), $user['id']]);
                }

                return false;
            }


            //reset the number of failed attempts
            $query = $db->prepare('UPDATE user_failed_attempts SET number_of_attempts = ? WHERE user_id = ?');
            $query->execute([0, $user['id']]);



            //check if the two factor code is expired
            $now_time = date('Y-m-d H:i:s');

            if ($two_factor['valid_until'] < $now_time) {
                return false;
            }

            //update the user two factor column to true
            $query = $db->prepare('UPDATE users SET two_factor = ? WHERE id = ?');

            $query->execute(['true', $user['id']]);

            //delete the two factor code from the db
            $query = $db->prepare('DELETE FROM two_factor WHERE user_id = ?');

            $query->execute([$user['id']]);

            //send the user to the home page
            return true;
        } catch (\Exception $e) {
            Log::info(['' => $e->getMessage()]);

            return false;
        }
    }






    //logout the user and delete the session from the db
    public function logout(Request $request)
    {

        //get the user from the session id
        $user = $this->get_user($request);

        Log::info(['USER LOGOUT' => $user]);

        //delete the session from the browser
        $this->delete_session($request->cookie('user_session'));

        //remove the session from browser
        Cookie::queue(Cookie::forget('user_session'));


        return redirect('/api/home')
            ->withCookie(Cookie::forget('user_session'))
            ->with('success', 'Successfully logged out');
    }
}
