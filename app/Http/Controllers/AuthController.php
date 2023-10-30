<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Log;
use App\Models\AuthModel;
use App\Models\AuthRequest;
use App\Models\Client;

class AuthController extends Controller
{
    private $cookie_ttl = 5;
    private $session_ttl = 5; //5 minutes
    private $login_cookie_name = 'login_cookie';
    private $session_name = 'user_session';

    public function client_authorize(Request $request)
    {
        $auth_model = new AuthModel();
        $auth_model->initialize();

        $query = http_build_query($request->query());

        $client_id = $request->query('client_id');
        $redirect_uri = $request->query('redirect_uri');
        $state = $request->query('state');
        $code_challenge = $request->query('code_challenge');
        $scope = $request->query('scope');

        //check if the client id exists
        $client = Client::where('client_id', $client_id)->first();

        if (!$client) {
            // return redirect($redirect_uri . '?error=invalid_client_id&state=' . $state);
            return "invalid_client_id";
        }

        //check if the redirect uri is valid
        if (!$redirect_uri || $redirect_uri !== $client->redirect_uri) {
            // return redirect($redirect_uri . '?error=invalid_redirect_uri&state=' . $state);
            return "invalid_redirect_uri";
        }

        if (!$state) {
            // return redirect($redirect_uri . '?error=invalid_state&state=' . $state);
            return "invalid_state";
        }

        if (!$code_challenge) {
            // return redirect($redirect_uri . '?error=invalid_code_challege&state=' . $state);
            return "invalid_code_challege";
        }

        if (!$scope) {
            // return redirect($redirect_uri . '?error=invalid_scopes&state=' . $state);
            return "invalid_scopes";
        }


        //create AuthRequest
        $auth_request = new AuthRequest();
        $auth_request->request_code = $auth_model->generate_request_code();
        $auth_request->client_id = $client_id;
        $auth_request->request_session_id = $auth_model->generate_request_session_id();
        // $auth_request->redirect_uri = $redirect_uri;
        $auth_request->state = $state;
        // $auth_request->code_challege = $code_challenge;
        $auth_request->expires_at = date('Y-m-d H:i:s', time() + $this->cookie_ttl * 60);
        $auth_request->save();


        //check if usersession exists
        $user_session = $request->cookie($this->session_name);

        if (!$user_session) {
            //send the user to the login page
            return redirect('/api/auth/login')
                ->cookie($this->login_cookie_name, $auth_request->request_code, $this->cookie_ttl, '/api/auth', null, false, true)
                ->with('success', 'Please login to continue');
        }

        //get the user from the session
        $user = $auth_model->get_user($request);

        //generate the auth code
        // $user_id, $client_id, $request_session_id, $code_challenge, $redirect_uri, $scopes
        $auth_code = $auth_model->generate_auth_code(
            $user->id, 
            $client_id, 
            $auth_request->request_session_id, 
            $code_challenge,
            $redirect_uri,
            $scope
        );

        //remove the login cookie & session cookie
        setcookie($this->login_cookie_name, '', time() - 3600, '/api/auth', null, false, true);
        setcookie($this->session_name, '', time() - 3600, '/api', null, false, true);

        //redirect the user to the redirect uri with the auth code
        return redirect($redirect_uri . '?code=' . $auth_code . '&state=' . $state);
    }


    public function login(Request $request)
    {
        //from AuthModel call the initialize method
        $auth_model = new AuthModel();
        $auth_model->initialize();
        $cookie = $request->cookie($this->login_cookie_name);
        // $credentials = json_decode($cookie, true);

        try {
            // if ($auth_model->check_user_auth($credentials['username'], $credentials['password'])) {
            //     return redirect('/api/auth/consent')
            //         ->cookie(
            //             $this->login_cookie_name,
            //             json_encode($credentials),
            //             $this->cookie_ttl,
            //             '/api/auth',
            //             null,
            //             false,
            //             true
            //         )
            //         ->with('success', 'Login success');
            // } else {
            //     //set the cookie to expire in the past
            //     setcookie($this->login_cookie_name, '', time() - 3600, '/api/auth', null, false, true);
            //     return view('auth.login');
            // }

            $auth_request = AuthRequest::where('request_code', $cookie)->first();

            //add new AuthRequest
            // $auth_request = new AuthRequest();
            // $auth_request->request_code = $cookie;
            // $auth_request->client_id = $previous_auth_request->client_id;
            // $auth_request->request_session_id = $previous_auth_request->request_session_id;
            // $auth_request->state = $previous_auth_request->state;
            // $auth_request->scopes = $previous_auth_request->scopes;
            // // $auth_request->code_challenge = $previous_auth_request->code_challenge;
            // $auth_request->expires_at = date('Y-m-d H:i:s', time() + $this->cookie_ttl * 60);
            // $auth_request->save();

            //modify the cookie to add the new request code
            setcookie($this->login_cookie_name, $auth_request->request_code, $this->cookie_ttl, '/api/auth', null, false, true);

            // setcookie($this->login_cookie_name, '', time() - 3600, '/api/auth', null, false, true);
            return view('auth.login');
        } catch (\Exception $e) {

            setcookie($this->login_cookie_name, '', time() - 3600, '/api/auth', null, false, true);
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
                setcookie($this->login_cookie_name, '', time() - 3600, '/api/auth', null, false, true);

                return redirect('/api/auth/login')
                    ->with('error', 'Login failed')
                    ->withInput();
            }

            //send the user to the consent page with the cookie
            return redirect('/api/auth/consent')
                ->cookie($this->login_cookie_name, json_encode($credentials), $this->cookie_ttl, '/api/auth', null, false, true)
                ->with('success', 'Login success');
        } catch (\Exception $e) {
            setcookie($this->login_cookie_name, '', time() - 3600, '/api/auth', null, false, true);

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
                setcookie($this->login_cookie_name, '', time() - 3600, '/api/auth', null, false, true);

                return redirect('/api/auth/login')
                    ->with('error', 'Login failed')
                    ->withInput();
            }

            // if ($get_user_from_login_cookie['consent'] == 'true') {
            //     return redirect('/api/auth/2fa')
            //         ->cookie('login_cookie', json_encode($get_user_from_login_cookie), $this->cookie_ttl, '/api/auth', null, false, true)
            //         ->with('success', 'Consent provided successfully');
            // } else {
            //     Cookie::make('login_cookie', json_encode($get_user_from_login_cookie), $this->cookie_ttl, '/api/auth', null, false, true);

            //     return view('auth.consent');
            // }

            Cookie::make('login_cookie', json_encode($get_user_from_login_cookie), $this->cookie_ttl, '/api/auth', null, false, true);

            return view('auth.consent');
        } catch (\Exception $e) {
            setcookie($this->login_cookie_name, '', time() - 3600, '/api/auth', null, false, true);

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
                setcookie($this->login_cookie_name, '', time() - 3600, '/api/auth', null, false, true);

                return redirect('/api/auth/login')
                    ->with('error', 'Login failed')
                    ->withInput();
            }

            $consent = 'true';
            $get_user_from_login_cookie['consent'] = $consent;

            //create 2fa code and send it to the user
            // $auth_model->send_2fa_code($get_user_from_login_cookie['id']);

            //send the user to the consent page with the cookie
            return redirect('/api/auth/2fa')
                ->cookie('login_cookie', json_encode($get_user_from_login_cookie), $this->cookie_ttl, '/api/auth', null, false, true)
                ->with('success', 'Consent provided successfully');
        } catch (\Exception $e) {
            setcookie($this->login_cookie_name, '', time() - 3600, '/api/auth', null, false, true);

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
                setcookie($this->login_cookie_name, '', time() - 3600, '/api/auth', null, false, true);

                return redirect('/api/auth/login')
                    ->with('error', 'Login failed')
                    ->withInput();
            }

            // if ($get_user_from_login_cookie['two_fa'] == 'true' && $get_user_from_login_cookie['consent'] == 'true') {
            //     return redirect('/api/home')
            //         ->cookie($this->session_name, $auth_model->create_session_id($get_user_from_login_cookie['id'], 'true', date('Y-m-d H:i:s', time() + $this->session_ttl)), $this->cookie_ttl, '/api/auth', null, false, true)
            //         ->with('success', '2FA provided successfully');
            // } else {

            //     if ($get_user_from_login_cookie['consent'] == 'false') {

            //         setcookie($this->login_cookie_name, '', time() - 3600, '/api/auth', null, false, true);
            //         return redirect('/api/auth/login')
            //             ->with('error', 'Login failed')
            //             ->withInput();
            //     }

            //     Cookie::make('login_cookie', json_encode($get_user_from_login_cookie), $this->cookie_ttl, '/api/auth', null, false, true);

            //     return view('auth.2fa');
            // }

            if ($get_user_from_login_cookie['consent'] == 'false') {

                setcookie($this->login_cookie_name, '', time() - 3600, '/api/auth', null, false, true);
                return redirect('/api/auth/login')
                    ->with('error', 'Login failed')
                    ->withInput();
            }

            Cookie::make('login_cookie', json_encode($get_user_from_login_cookie), $this->cookie_ttl, '/api/auth', null, false, true);

            return view('auth.2fa');
        } catch (\Exception $e) {
            setcookie($this->login_cookie_name, '', time() - 3600, '/api/auth', null, false, true);

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
                //forget the cookie from the request
                setcookie('login_cookie', '', time() - 3600, '/api/auth', null, false, true);

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
                ->cookie($this->session_name, $session_id, $this->cookie_ttl, '/api', null, false, true)
                ->with('success', 'Successfully logged in');
        } catch (\Exception $e) {

            setcookie('login_cookie', '', time() - 3600, '/api/auth', null, false, true);

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
        $auth_model->delete_session($request->cookie($this->session_name));

        //php set cookie to expire in the past
        setcookie($this->session_name, '', time() - 3600, '/api', null, false, true);
        setcookie($this->login_cookie_name, '', time() - 3600, '/api/auth', null, false, true);

        return redirect('/api/auth/login')
            ->with('success', 'Successfully logged out');
    }
}
