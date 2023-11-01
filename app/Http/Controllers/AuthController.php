<?php

namespace App\Http\Controllers;

use App\Models\AuthCode;
use App\Models\AuthModel;
use App\Models\AuthRequest;
use App\Models\AuthUser;
use App\Models\Client;
use App\Models\Session as ModelsSession;
use Carbon\Carbon;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Session;

class AuthController extends Controller
{
    private $cookie_ttl = 5;
    private $session_ttl = 15; //15 minutes
    private $login_cookie_name = 'login_cookie';
    private $session_name = 'user_session';

    public function client_authorize(Request $request)
    {
        Log::info(['request' => $request->query()]);
        $auth_model = new AuthModel();
        $auth_model->initialize();

        $query = http_build_query($request->query());

        // return $query;

        $client_id = $request->query('client_id');
        $redirect_uri = $request->query('redirect_uri');
        $state = $request->query('state');
        $code_challenge = $request->query('code_challenge');
        $scope = $request->query('scope');

        //check if the client id exists
        $client = Client::where('client_id', $client_id)->first();

        //create new session which lasts for 10 minutes

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

        $session = $auth_model->get_session_from_session_cookie($request);

        //check if usersession exists
        // $user_session = session()->get('user_session');
        //check for the cookie
        // $login_cookie = $request->cookie($this->session_name);

        // if (!$user_session) {
        //     //set session lifetime to 10 minutes
        //     config(['session.lifetime' => $this->session_ttl]);
        //     session()->put('request_code', $auth_request->id);
        //     //send the user to the login page
        //     return redirect('/api/auth/login')
        //         ->with('success', 'Please login to continue');
        // }

        //get the Session from the db

        //check if session array is empty
        if (empty($session)) {

            //create AuthRequest
            $auth_request = new AuthRequest();
            $auth_request->request_code = $auth_model->generate_request_code();
            $auth_request->client_id = $client_id;
            $auth_request->request_session_id = "";
            // $auth_request->redirect_uri = $redirect_uri;
            $auth_request->state = $state;
            $auth_request->code_challenge = $code_challenge;
            $auth_request->expires_at = date('Y-m-d H:i:s', time() + $this->cookie_ttl * 60);
            $auth_request->save();

            //set session lifetime to 10 minutes
            config(['session.lifetime' => $this->session_ttl]);
            session()->put('request_code', $auth_request->id);
            //remove the cookie
            setcookie($this->session_name, '', time() - 3600, '/api', null, false, true);

            //send the user to the login page
            return redirect('/api/auth/login')
                ->with('success', 'Please login to continue');
        }

        Log::info(['session_done' => $session['session_id']]);

        //get the user from the session
        $user = $session['user'];
        $sesion_id = $session['session_id'];

        if (!$user) {
            //set session lifetime to 10 minutes
            config(['session.lifetime' => $this->session_ttl]);
            //remove the cookie
            setcookie($this->session_name, '', time() - 3600, '/api', null, false, true);
            //send the user to the login page
            return redirect('/api/auth/login')
                ->with('success', 'Please login to continue');
        }

        //get the session from the db
        $session_retrieved = ModelsSession::find($sesion_id);
        //update the session expiry
        $session_retrieved->validity = false;
        $session_retrieved->last_used_at = date('Y-m-d H:i:s');
        $session_retrieved->update();

        //generate the auth code
        // $user_id, $client_id, $request_session_id, $code_challenge, $redirect_uri, $scopes
        $auth_code = $auth_model->generate_auth_code(
            $session['session_id'],
        );

        //remove the login cookie & session cookie
        // setcookie($this->login_cookie_name, '', time() - 3600, '/api/auth', null, false, true);
        setcookie($this->session_name, '', time() - 3600, '/api', null, false, true);

        //add the auth code to the db
        $auth_code_record = new AuthCode();
        $auth_code_record->code = urlencode($auth_code);
        $auth_code_record->client_id = $client->client_id;
        $auth_code_record->session_id = $session['session_id'];
        $auth_code_record->user_id = $user->id;
        $auth_code_record->code_challenge = $code_challenge;
        $auth_code_record->scopes = $scope;
        $auth_code_record->redirect_uri = $redirect_uri;
        $auth_code_record->expires_at = date('Y-m-d H:i:s', time() + $client->auth_code_ttl * 60);
        $auth_code_record->save();

        //redirect the user to the redirect uri with the auth code
        return redirect($redirect_uri . '?code=' . $auth_code . '&state=' . $state);
    }

    public function login(Request $request)
    {
        //from AuthModel call the initialize method
        $auth_model = new AuthModel();
        $auth_model->initialize();
        $cookie = $request->cookie($this->login_cookie_name);
        $session = session()->get('request_code');

        try {
            $auth_request = AuthRequest::find($session);

            if ($auth_request) {
                //modify the cookie to add the new request code
                // setcookie($this->login_cookie_name, $auth_request->request_code, $this->cookie_ttl, '/api/auth', null, false, true);

                // setcookie($this->login_cookie_name, '', time() - 3600, '/api/auth', null, false, true);
                return view('auth.login');
            } else {
                //not coming from the authorize endpoint
                return view('auth.login');
            }
        } catch (\Exception $e) {

            setcookie($this->login_cookie_name, '', time() - 3600, '/api/auth', null, false, true);
            return view('auth.login');
        }
    }

    public function submit_login(Request $request)
    {
        $auth_model = new AuthModel();
        $session = session()->get('request_code');
        $credentials = [
            'username' => $request->username,
            'password' => $request->password,
            'consent' => 'false',
            'two_fa' => 'false',
        ];

        try {
            $auth_request = AuthRequest::find($session);

            if (!$auth_request) {
                //forget the cookie from the request
                // setcookie($this->login_cookie_name, '', time() - 3600, '/api/auth', null, false, true);
                //remove the session
                session()->forget('request_code');

                //return to authorize endpoint with error
                return redirect('/api/auth/login')
                    ->with('error', 'Login failed')
                    ->withInput();
            }

            // if (!$auth_model->check_user_auth($credentials['username'], $credentials['password'])) {
            //     setcookie($this->login_cookie_name, '', time() - 3600, '/api/auth', null, false, true);

            //     return redirect('/api/auth/login')
            //         ->with('error', 'Login failed')
            //         ->withInput();
            // }

            //modify the AuthRequest
            $auth_request->username = $credentials['username'];
            $auth_request->password_hash = encrypt($credentials['password']);
            $auth_request->update();

            //now get the AuthUser from the username
            $user = AuthUser::where('username', $credentials['username'])->first();

            //check if the user exists
            if (!$user || !password_verify($credentials['password'], $user->password_hash)) {
                // setcookie($this->login_cookie_name, '', time() - 3600, '/api/auth', null, false, true);

                return redirect('/api/auth/login')
                    ->with('error', 'Login failed')
                    ->withInput();
            }

            //send the user to the consent page with the cookie
            return redirect('/api/auth/consent')
            // ->cookie($this->login_cookie_name, json_encode($credentials), $this->cookie_ttl, '/api/auth', null, false, true)
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
        // $get_user_from_login_cookie = $auth_model->get_user_from_login_cookie($request);
        $session = session()->get('request_code');

        try {

            $auth_request = AuthRequest::find($session);

            if (!$auth_request) {
                //forget the cookie from the request
                setcookie($this->login_cookie_name, '', time() - 3600, '/api/auth', null, false, true);
                //remove the session
                session()->forget('request_code');

                //return to authorize endpoint with error
                return redirect('/api/auth/login')
                    ->with('error', 'Login failed')
                    ->withInput();
            }

            $user = AuthUser::where('username', $auth_request->username)->first();

            if (!$user || !password_verify(decrypt($auth_request->password_hash), $user->password_hash)) {
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

            // Cookie::make('login_cookie', json_encode($get_user_from_login_cookie), $this->cookie_ttl, '/api/auth', null, false, true);

            return view('auth.consent');
        } catch (\Exception $e) {
            // setcookie($this->login_cookie_name, '', time() - 3600, '/api/auth', null, false, true);

            return redirect('/api/auth/login')
                ->with('error', 'Login failed')
                ->withInput();
        }
    }

    public function submit_consent(Request $request)
    {
        $auth_model = new AuthModel();
        $get_user_from_login_cookie = $auth_model->get_user_from_login_cookie($request);

        $session = session()->get('request_code');

        try {
            $auth_request = AuthRequest::find($session);

            if (!$auth_request) {
                //forget the cookie from the request
                setcookie($this->login_cookie_name, '', time() - 3600, '/api/auth', null, false, true);
                //remove the session
                session()->forget('request_code');

                //return to authorize endpoint with error
                return redirect('/api/auth/login')
                    ->with('error', 'Login failed')
                    ->withInput();
            }

            $user = AuthUser::where('username', $auth_request->username)->first();

            if (!$user || !password_verify(decrypt($auth_request->password_hash), $user->password_hash)) {
                //forget the cookie from the request
                setcookie($this->login_cookie_name, '', time() - 3600, '/api/auth', null, false, true);

                return redirect('/api/auth/login')
                    ->with('error', 'Login failed')
                    ->withInput();
            }

            $consent = 'true';
            $get_user_from_login_cookie['consent'] = $consent;

            //update the AuthRequest
            $auth_request->consent_granted = true;
            $auth_request->update();

            //create 2fa code and send it to the user
            // $auth_model->send_2fa_code($get_user_from_login_cookie['id']);

            //send the user to the consent page with the cookie
            return redirect('/api/auth/2fa')
            // ->cookie('login_cookie', json_encode($get_user_from_login_cookie), $this->cookie_ttl, '/api/auth', null, false, true)
                ->with('success', 'Consent provided successfully');
        } catch (\Exception $e) {
            // setcookie($this->login_cookie_name, '', time() - 3600, '/api/auth', null, false, true);
            session()->forget('request_code');

            return redirect('/api/auth/login')
                ->with('error', 'Login failed')
                ->withInput();
        }
    }

    public function two_factor(Request $request)
    {
        $auth_model = new AuthModel();
        // $get_user_from_login_cookie = $auth_model->get_user_from_login_cookie($request);
        $session = session()->get('request_code');

        try {
            $auth_request = AuthRequest::find($session);

            if (!$auth_request) {
                //forget the cookie from the request
                // setcookie($this->login_cookie_name, '', time() - 3600, '/api/auth', null, false, true);
                //remove the session
                session()->forget('request_code');

                //return to authorize endpoint with error
                return redirect('/api/auth/login')
                    ->with('error', 'Login failed')
                    ->withInput();
            }

            $user = AuthUser::where('username', $auth_request->username)->first();

            if (!$user || !password_verify(decrypt($auth_request->password_hash), $user->password_hash)) {
                //forget the cookie from the request
                // setcookie($this->login_cookie_name, '', time() - 3600, '/api/auth', null, false, true);
                session()->forget('request_code');

                return redirect('/api/auth/login')
                    ->with('error', 'Login failed')
                    ->withInput();
            }

            if (!$auth_request->consent_granted) {

                // setcookie($this->login_cookie_name, '', time() - 3600, '/api/auth', null, false, true);
                session()->forget('request_code');

                return redirect('/api/auth/login')
                    ->with('error', 'Login failed')
                    ->withInput();
            }

            // Cookie::make('login_cookie', json_encode($get_user_from_login_cookie), $this->cookie_ttl, '/api/auth', null, false, true);

            return view('auth.2fa');
        } catch (\Exception $e) {
            setcookie($this->session_name, '', time() - 3600, '/api/auth', null, false, true);

            return redirect('/api/auth/login')
                ->with('error', 'Login failed')
                ->withInput();
        }
    }

    public function submit_two_factor(Request $request)
    {
        $auth_model = new AuthModel();
        $session = session()->get('request_code');

        try {
            $auth_request = AuthRequest::find($session);
            if (!$auth_request) {
                //forget the cookie from the request
                session()->forget('request_code');

                return redirect('/api/auth/login')
                    ->with('error', 'Login failed')
                    ->withInput();
            }

            $user = AuthUser::where('username', $auth_request->username)->first();

            if (!$user || !password_verify(decrypt($auth_request->password_hash), $user->password_hash)) {
                //forget the cookie from the request
                // setcookie($this->login_cookie_name, '', time() - 3600, '/api/auth', null, false, true);
                session()->forget('request_code');

                return redirect('/api/auth/login')
                    ->with('error', 'Login failed')
                    ->withInput();
            }

            if (!$auth_model->verify_2fa($request)) {
                return redirect('/api/auth/2fa')
                    ->with('error', '2FA failed, Please try again')
                    ->withInput();
            }

            // $two_factor = 'true';
            // $get_user_from_login_cookie['two_fa'] = $two_factor;
            // $id = $get_user_from_login_cookie['id'];

            //create the session id
            $session_id = $auth_model->create_session_id($user->id, 'true', date('Y-m-d H:i:s', time() + $this->session_ttl));
            //create the session
            session()->put('user_session', $session_id);

            //update the AuthRequest
            $auth_request->two_factor_granted = true;
            $auth_request->user_id = $user->id;
            $auth_request->request_session_id = $session_id;
            $auth_request->update();

            $client = Client::where('client_id', $auth_request->client_id)->first();

            $query_params = [
                // 'code' => $auth_request->request_code,
                'client_id' => $client->client_id,
                'redirect_uri' => urldecode($client->redirect_uri),
                'response_type' => 'code',
                'scope' => $client->scopes,
                'state' => $auth_request->state,
                'code_challenge' => $auth_request->code_challenge,
            ];
            $query = http_build_query($query_params);

            // Cookie::make(
            //     $this->session_name,
            //     $session_id,
            //     $this->cookie_ttl,
            //     '/api',
            //     null,
            //     false,
            //     true,
            //     false,
            //     'strict'
            // );
            Log::info(['Query To Authorize' => $query]);
            //redirect back to the authorize endpoint with query params
            return redirect('/api/auth/authorize?' . $query)
                ->cookie(
                    $this->session_name,
                    $session_id,
                    $this->cookie_ttl,
                    '/api', null,
                    false, true);

            // return redirect('/api/home')
            // // ->cookie($this->session_name, $session_id, $this->cookie_ttl, '/api', null, false, true)
            //     ->with('success', 'Successfully logged in');
        } catch (\Exception $e) {

            Log::info(['CredentialsH' => $e->getMessage()]);

            // setcookie('login_cookie', '', time() - 3600, '/api/auth', null, false, true);
            session()->forget('request_code');

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
        $auth_model = new AuthModel();
        //get the user from cookie
        $auth_request = AuthRequest::find(session()->get('request_code'));

        if (!$auth_request) {
            return response()->json(['message' => 'User not found, Therefore unauthorized'], 401);
        }

        $user = AuthUser::where('username', $auth_request->username)->first();

        if (!$user || !password_verify(decrypt($auth_request->password_hash), $user->password_hash) || !$auth_request->consent_granted) {
            return response()->json(['message' => 'User not found, Therefore unauthorized'], 401);
        }

        //send the verification email
        $auth_model->send_2fa_code($user->id);

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

    //Token
    public function token(Request $request)
    {
        $auth_model = new AuthModel();
        $logCapture = $request->log;

        // $log = OauthLog::find($logCapture['id']);

        // Validate the client
        $client_id = $request->input('client_id');
        $client_secret = $request->input('client_secret');
        $code_verifier = $request->input('code_verifier');

        $client = Client::where('client_id', $client_id)->first();

        // Check the grant type
        $grant_type = $request->input('grant_type');

        if ($grant_type === 'authorization_code') {
            // dD($client);
            if (!$client || $client->client_secret !== $client_secret) {
                $response = [
                    'error' => 'invalid_client',
                    'error_description' => 'The client credentials are invalid',
                ];

                // $log->response = json_encode($response);
                // $log->update();

                return response()->json($response, 400);
            }
            //if no code verifier is provided, return error
            if (!$code_verifier) {
                $response = [
                    'error' => 'invalid_grant',
                    'error_description' => 'code_verifier is required',
                ];

                // $log->response = json_encode($response);
                // $log->update();

                return response()->json($response, 400);
            }

            // Verify the authorization code
            $auth_code = urldecode($request->input('code'));

            $auth_code_decrypted = $auth_model->decrypt($auth_code, $client_secret);

            $auth_code_record = AuthCode::where('auth_code', $auth_code)
                ->where('client_id', $client->id)
                ->where('expires_at', '>', now())
                ->first();

            if (!$auth_code_record) {
                return response()->json([
                    'error' => 'invalid_grant',
                    'error_description' => 'The authorization code is invalid',
                ], 400);
            }

            //check if code verifier matches the code challenge
            $code_challenge = $auth_code_record->code_challenge;

            //new check if the code verifier matches the code challenge
            if (!$auth_model->verifyCodeChallenge($code_challenge, $code_verifier)) {
                return response()->json([
                    'status_message' => 'invalid_grant',
                    'status_description' => 'code_verifier does not match code_challenge',
                ], 400);
            }

            //check if the auth code matches the client session id + redirect uri + scopes + expires at + auth code + state
            $auth_code_details = AuthCode::where('auth_code', urlencode($auth_code))
                ->where('client_id', $client->id)
                ->where('session_id', $auth_code_record->session_id)
                ->where('scopes', $auth_code_record->scopes)
                ->where('user_id', $auth_code_record->user_id)
                ->where('expires_at', '>', now())
                ->first();

            if (!$auth_code_details) {
                $response = [
                    'error' => 'invalid_grant',
                    'error_description' => 'The authorization code is invalid',
                ];

                // $log->response = json_encode($response);
                // $log->update();

                return response()->json($response, 400);
            }

            $ac_validity = now()->addMinutes($client->access_token_ttl);
            $rt_validity = now()->addMinutes($client->refresh_token_ttl);

            //client private key
            $privateKeyEncrypted = $client->privateKey_path;
            $client_secret = $client->client_secret;

            $access_payload = [
                'client_id' => $client->client_id,
                'scopes' => $auth_code_record->scopes,
                'expires_in' => $ac_validity->timestamp,
                'user_id' => $auth_code_record->user_id,
            ];

            $refresh_payload = [
                'client_id' => $client->client_id,
                'scopes' => $auth_code_record->scopes,
                'expires_in' => $rt_validity->timestamp,
                'user_id' => $auth_code_record->user_id,
            ];

            $privateKey = openssl_pkey_get_private($privateKeyEncrypted, $client_secret);
            $accessTokenNew = JWT::encode($access_payload, $privateKey, 'RS256', $client->id, [
                'alg' => 'RS256',
                'kid' => $client->id,
                'sub' => $client->client_id,
                'jti' => $auth_code_decrypted->user_id,
                'exp' => $ac_validity->timestamp,
            ]);
            $refreshTokenNew = JWT::encode($refresh_payload, $privateKey, 'RS256', $client->id, [
                'alg' => 'RS256',
                'kid' => $client->id,
                'sub' => $client->client_id,
                'jti' => $auth_code_decrypted->user_id,
                'exp' => $rt_validity->timestamp,
            ]);

            //accessToken and refreshToken
            $refresh_token = new OauthToken();
            $refresh_token->type = 'refresh_token';
            $refresh_token->user_id = $auth_code_record->user_id;
            $refresh_token->client_id = $auth_code_record->client_id;
            $refresh_token->for = $client->redirect_uri;
            $refresh_token->token = $refreshTokenNew;
            $refresh_token->scopes = $auth_code_record->scopes;
            $refresh_token->expires_in = $rt_validity->timestamp;
            $refresh_token->ip = $request->ip();
            $refresh_token->user_agent = $request->userAgent();
            $refresh_token->request_session_id = $auth_code_decrypted->user_session_id;
            $refresh_token->save();

            $access_token = new OauthToken();
            $access_token->type = 'access_token';
            $access_token->user_id = $auth_code_record->user_id;
            $access_token->client_id = $auth_code_record->client_id;
            $access_token->for = $client->redirect_uri;
            $access_token->token = $accessTokenNew;
            $access_token->scopes = $auth_code_record->scopes;
            $access_token->refresh_token_id = $refresh_token->id;
            $access_token->expires_in = $ac_validity->timestamp;
            $access_token->ip = $request->ip();
            $access_token->user_agent = $request->userAgent();
            $access_token->request_session_id = $auth_code_decrypted->user_session_id;
            $access_token->save();

            // Revoke the authorization code and user session
            $auth_code_record->delete();
            UserSession::where('session_id', $auth_code_record->user_session_id)->delete();

            $response = [
                'access_token' => $access_token->token,
                'token_type' => 'Bearer',
                'expires_in' => $access_token->expires_in,
                'refresh_token' => $refresh_token->token,
                'token_id' => $auth_code_decrypted->request_session_id,
            ];

            $log->response = json_encode($response);
            $log->update();

            return response()->json($response, 200);
            // Return the access token and refresh token
            // return response()->json();
        } else if ($grant_type === 'refresh_token') {
            // Verify the refresh token
            $refresh_token_value = $request->input('refresh_token');
            $public_key = $client->publicKey_path;

            $refresh_token_decrypted = JWT::decode($refresh_token_value, new Key($public_key, 'RS256'));

            if (!$refresh_token_decrypted) {
                $response = ['error' => 'invalid_grant'];

                $log->response = json_encode($response);
                $log->update();

                return response()->json($response, 400);
            }

            $verifyClient = Client::where('client_id', $refresh_token_decrypted->client_id)
                ->where('client_secret', $client_secret)
                ->first();

            if (!$verifyClient) {
                $response = ['error' => 'invalid_grant'];

                $log->response = json_encode($response);
                $log->update();

                return response()->json($response, 400);
            }

            $now = Carbon::now();

            if ($now->timestamp > $refresh_token_decrypted->expires_in) {
                $response = ['error' => 'invalid_grant'];

                $log->response = json_encode($response);
                $log->update();

                return response()->json($response, 400);
            }

            //check if refresh token is valid
            $refresh_token = OauthToken::where('token', $refresh_token_value)
                ->where('type', 'refresh_token')
                ->where('revoked', false)
                ->where('expires_in', '>', $now->timestamp)
                ->where('client_id', $verifyClient->id)
                ->first();

            if (!$refresh_token || $refresh_token->client_id !== $verifyClient->id) {
                $response = ['error' => 'invalid_grant'];

                $log->response = json_encode($response);
                $log->update();

                return response()->json($response, 400);
            }

            $accessToken = OauthToken::where('refresh_token_id', $refresh_token->id)
                ->where('type', 'access_token')
                ->first();

            if (!$accessToken) {
                $response = ['error' => 'invalid_grant'];

                $log->response = json_encode($response);
                $log->update();

                return response()->json($response, 400);
            }

            //client private key
            $privateKeyEncrypted = $verifyClient->privateKey_path;
            $client_secret = $verifyClient->client_secret;

            $ac_validity = now()->addMinutes($client->access_token_ttl);
            $rt_validity = now()->addMinutes($client->refresh_token_ttl);

            $payloadAccess = [
                'client_id' => $client->client_id,
                'scopes' => $refresh_token->scopes,
                'expires_in' => $ac_validity->timestamp,
                'user_id' => $refresh_token->user_id,
            ];

            $payloadRefresh = [
                'client_id' => $client->client_id,
                'scopes' => $refresh_token->scopes,
                'expires_in' => $rt_validity->timestamp,
                'user_id' => $refresh_token->user_id,
            ];

            $privateKey = openssl_pkey_get_private($privateKeyEncrypted, $client_secret);
            $accessTokenNew = JWT::encode($payloadAccess, $privateKey, 'RS256', $client->id, [
                'alg' => 'RS256',
                'kid' => $client->id,
                'sub' => $client->client_id,
                'jti' => $refresh_token->user_id,
                'exp' => $ac_validity->timestamp,
            ]);
            $refreshTokenNew = JWT::encode($payloadRefresh, $privateKey, 'RS256', $client->id, [
                'alg' => 'RS256',
                'kid' => $client->id,
                'sub' => $client->client_id,
                'jti' => $refresh_token->user_id,
                'exp' => $rt_validity->timestamp,
            ]);

            $new_refresh_token = new OauthToken();
            $new_refresh_token->type = 'refresh_token';
            $new_refresh_token->user_id = $refresh_token->user_id;
            $new_refresh_token->client_id = $refresh_token->client_id;
            $new_refresh_token->for = $verifyClient->redirect_uri;
            $new_refresh_token->token = $refreshTokenNew;
            $new_refresh_token->scopes = $refresh_token->scopes;
            $new_refresh_token->expires_in = $rt_validity->timestamp;
            $new_refresh_token->ip = $request->ip();
            $new_refresh_token->user_agent = $request->userAgent();
            $new_refresh_token->request_session_id = $auth_code_decrypted->request_session_id;
            $new_refresh_token->save();

            $new_access_token = new OauthToken();
            $new_access_token->type = 'access_token';
            $new_access_token->user_id = $new_refresh_token->user_id;
            $new_access_token->client_id = $new_refresh_token->client_id;
            $new_access_token->for = $verifyClient->redirect_uri;
            $new_access_token->token = $accessTokenNew;
            $new_access_token->scopes = $new_refresh_token->scopes;
            $new_access_token->refresh_token_id = $new_refresh_token->id;
            $new_access_token->expires_in = $ac_validity->timestamp;
            $new_access_token->ip = $request->ip();
            $new_access_token->user_agent = $request->userAgent();
            $new_access_token->request_session_id = $auth_code_decrypted->request_session_id;
            $new_access_token->save();

            OauthToken::where('id', $accessToken->id)
                ->update(['revoked' => true]);

            OauthToken::where('id', $refresh_token->id)
                ->update(['revoked' => true]);

            $response = [
                'access_token' => $new_access_token->token,
                'token_type' => 'Bearer',
                'expires_in' => $ac_validity->timestamp,
                'refresh_token' => $new_refresh_token->token,
                'token_id' => $auth_code_decrypted->request_session_id,
            ];

            $log->response = json_encode($response);
            $log->update();

            return response()->json($response, 200);
        }

        // Invalid grant type
        return response()->json(['error' => 'unsupported_grant_type'], 400);
    }
}
