<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

class AuthModel extends Model
{
    use HasFactory;

    private $username = 'admin';
    private $password = 'Welcome@123#';
    private $cookie_ttl = 5;
    private $session_ttl = 15; //5 minutes
    private $login_cookie_name = 'login_cookie';
    private $session_name = 'user_session';

    public function initialize()
    {
        //write below code using DB facade
        $hashed_password = password_hash($this->password, PASSWORD_DEFAULT);

        $user = AuthUser::where('username', $this->username)->first();

        $client_id = "0df3e5e6e872dff4b61d3f74dad43a7aa6c18aadf2d68e607f031db090db63c3";

        //sample client
        $client = Client::where('client_id', $client_id)->first();

        if (!$user) {
            // $query_insert_user = 'INSERT INTO users (username, password, consent, two_factor) VALUES (?, ?, ?, ?)';
            // $query = $db->prepare($query_insert_user);

            // $query->execute([$this->username, $hashed_password, 'false', 'false']);

            $new_user = new AuthUser();

            //generate a uique uuid for the user
            $new_user->uuid = (string) Str::orderedUuid();

            $new_user->username = $this->username;
            $new_user->password_hash = $hashed_password;
            $new_user->save();
        } else {

            AuthUser::where('username', $this->username)->update([
                'password_hash' => $hashed_password,
            ]);
        }

        if (!$client) {

            $client_secret = bin2hex(random_bytes(32));
            $redirect_uri = 'http://localhost:8000/api/redirect';
            $scopes = 'profile';
            $grant_types = 'authorization_code';
            $response_types = 'code';
            $privateKey_path = 'privateKey.pem';
            $publicKey_path = 'publicKey.pem';
            $auth_code_ttl = 5;
            $access_token_ttl = 10;
            $refresh_token_ttl = 1440;
            $max_attempts = 5;

            $new_client = new Client();
            $new_client->name = 'Test Client';
            $new_client->email = 'test@test.com';
            $new_client->logo = 'https://www.google.com/images/branding/googlelogo/1x/googlelogo_color_272x92dp.png';
            $new_client->description = 'Test Client';
            $new_client->domain = 'http://localhost:8000';
            $new_client->white_listed_ips = '127.0.0.1';
            $new_client->active = true;
            $new_client->client_id = $client_id;
            $new_client->client_secret = $client_secret;
            $new_client->logged_out_uri = 'http://localhost:8000/api/client_logged_out';
            $new_client->redirect_uri = $redirect_uri;
            $new_client->scopes = $scopes;
            $new_client->grant_types = $grant_types;
            $new_client->response_types = $response_types;
            $new_client->privateKey_path = $privateKey_path;
            $new_client->publicKey_path = $publicKey_path;
            $new_client->auth_code_ttl = $auth_code_ttl;
            $new_client->access_token_ttl = $access_token_ttl;
            $new_client->refresh_token_ttl = $refresh_token_ttl;
            $new_client->max_attempts = $max_attempts;
            $new_client->save();
        }
    }

    public function generate_request_code()
    {
        return bin2hex(random_bytes(32));
    }

    //generate_request_session_id
    public function generate_request_session_id()
    {
        return bin2hex(random_bytes(32));
    }

    public function check_user_auth($username, $password)
    {
        $user = DB::table('users')->where('username', $username)->first();

        if (!$user) {
            return false;
        }

        if (!password_verify($password, $user->password)) {
            return false;
        }

        return true;
    }

    private function check_session($session_id)
    {
        // $db = new \PDO(env('DB_CONNECTION') . ':' . env('DB_DATABASE'));
        // $now_time = date('Y-m-d H:i:s');

        // //and session_expiry >
        // $query = $db->prepare('SELECT * FROM sessions WHERE session_id = ?');

        // $query->execute([$session_id]);

        // $session = $query->fetch(\PDO::FETCH_ASSOC);

        // if (!$session) {
        //     return false;
        // }

        // return true;

        $session = DB::table('sessions')->where('session_id', $session_id)
            ->where('valid_until', '>', date('Y-m-d H:i:s'))
            ->first();

        if (!$session) {
            return false;
        }

        return true;
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

        $db_user = DB::table('users')->where('username', $user['username'])->first();

        if (!$db_user) {
            return [];
        }

        //check if the user and db user passwords match
        if (!password_verify($user['password'], $db_user->password)) {
            return [];
        }

        //to user append the id
        $user['id'] = $db_user->id;

        return $user;
    }

    //send 2fa code after creating it
    public function send_2fa_code($user_id)
    {
        $user = AuthUser::find($user_id);

        if (!$user) {
            return false;
        }

        //generate the 2fa code which is a random 6 digit number
        $two_factor_code = rand(100000, 999999);

        //create the two factor code in the db
        $valid_until = date('Y-m-d H:i:s', time() + 60 * 5); //5 minutes

        $new_two_factor = new TwoFactor();
        $new_two_factor->user_id = $user_id;
        $new_two_factor->two_factor_code = $two_factor_code;
        $new_two_factor->valid_until = $valid_until;
        $new_two_factor->save();

        //TODO send the 2fa code to the user
        Log::info(['TwoFA Code' => $two_factor_code]);

        return true;
    }

    //verify 2fa code
    public function verify_2fa(Request $request)
    {
        Log::info("=======================TWO FACTOR VERIFICATION=======================");
        Log::info(['REQUEST' => $request->all()]);
        try {
            $session = session()->get('request_code');
            $auth_request = AuthRequest::find($session);

            if (!$auth_request) {
                //forget the cookie from the request
                session()->forget('request_code');

                return redirect('/api/auth/login')
                    ->with('error', 'Login failed')
                    ->withInput();
            }

            $user = AuthUser::where('username', $auth_request->username)->first();

            // Log::info(['USER FROM SESSION' => $user]);

            if (!$user) {
                return false;
            }

            //get the two factor code from the request
            $two_factor_code = $request->code;
            $two_factor = TwoFactor::where('user_id', $user->id)
                ->where('two_factor_code', $two_factor_code)
                ->first();

            //check if the two factor code is expired
            $now_time = date('Y-m-d H:i:s');

            if ($two_factor->valid_until < $now_time) {
                return false;
            }

            $user_failed_attempts = UserFailedAttempt::where('user_id', $user->id)->first();
            if (!$two_factor) {
                if (!$user_failed_attempts) {
                    $new_failed_attempt = new UserFailedAttempt();
                    $new_failed_attempt->user_id = $user->id;
                    $new_failed_attempt->number_of_attempts = 1;
                    $new_failed_attempt->save();

                } else {

                    $user_failed_attempts->number_of_attempts = $user_failed_attempts->number_of_attempts + 1;
                    $user_failed_attempts->update();
                }

                if ($user_failed_attempts->number_of_attempts >= 3) {

                    $user_failed_attempts->temporary_lockout_status = true;
                    $user_failed_attempts->temporary_lockout_until = date('Y-m-d H:i:s', time() + 60 * 5);
                    $user_failed_attempts->update();
                }
                return false;
            }

            //reset the number of failed attempts
            if ($user_failed_attempts) {
                $user_failed_attempts->number_of_attempts = 0;
                $user_failed_attempts->update();
            }

            //check if the two factor code is expired
            $now_time = date('Y-m-d H:i:s');

            if ($two_factor->valid_until < $now_time) {
                return false;
            }

            TwoFactor::where('user_id', $user->id)->delete();

            Log::info("=======================TWO FACTOR VERIFICATION TRUE=======================");
            //send the user to the home page
            return true;
        } catch (\Exception $e) {
            Log::info(['' => $e->getMessage()]);

            return false;
        }
    }

    private function create_session($user_id, $session_id, $validity, $valid_until)
    {
        try {
            $valid = $validity == 'true' ? true : false;
            $new_session = new Session();
            $new_session->user_id = $user_id;
            $new_session->session_id = $session_id;
            $new_session->validity = $valid;
            $new_session->valid_until = $valid_until;
            $new_session->save();

            return $new_session;
        } catch (\Exception $e) {
            Log::info(['create_session: ' => $e->getMessage()]);

            return false;
        }
    }

    public function create_session_id($user_id, $validity, $valid_until)
    {
        try {
            Log::info("=======================CREATE SESSION=======================");
            $session_id = bin2hex(random_bytes(32));
            $session = $this->create_session($user_id, $session_id, $validity, $valid_until);

            Log::info(['SESSION Create' => $session_id]);
            return $session_id;
        } catch (\Exception $e) {
            Log::info(['create_session_id: ' => $e->getMessage()]);

            return false;
        }
    }

    public function get_user(Request $request)
    {
        $session_id = session()->get('user_session');

        if (!$session_id) {
            return [];
        }

        if (!$this->check_session($session_id)) {
            return [];
        }

        $session = Session::where('session_id', $session_id)->first();
        $user_id = $session->user_id;
        $user = AuthUser::find($user_id);

        //remove the password from the user
        unset($user->password);

        return $user;
    }

    public function update_session_id($session_id, $validity, $valid_until)
    {
        config(['session.lifetime' => $this->session_ttl]);
        $this->update_session($session_id, $validity, $valid_until);
        session()->put('user_session', $session_id);

        return $session_id;
    }

    private function update_session($session_id, $validity, $valid_until)
    {
        $session = Session::where('session_id', $session_id)->first();
        $session->validity = $validity;
        $session->valid_until = $valid_until;
        $session->update();

        return true;
    }

    public function delete_session($session_id)
    {
        Session::where('session_id', $session_id)->delete();
        session()->forget('user_session');
        return true;
    }

    //get_user_from_session
    public function get_user_from_session($request)
    {
        // $session_id = $request->cookie('user_session');
        //from session
        $session_id = session()->get('user_session');

        if (!$session_id) {
            return [];
        }

        if (!$this->check_session($session_id)) {
            return [];
        }

        $session = Session::where('session_id', $session_id)->first();
        $user_id = $session->user_id;
        $user = AuthUser::find($user_id);
        unset($user->password);

        return $user;
    }

    //encrypt using openssl HS256 algorithm and return the encrypted string
    public function encrypt($data, $key)
    {
        // $encrypted = base64_encode(openssl_encrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $key));

        // return $encrypted;

        $ivlen = openssl_cipher_iv_length($cipher = "AES-128-CBC");
        $iv = openssl_random_pseudo_bytes($ivlen);

        $encrypted = openssl_encrypt($data, $cipher, $key, $options = 0, $iv);

        return base64_encode($encrypted . '::' . $iv);

    }

    //decrypt using openssl HS256 algorithm and return the decrypted string
    public function decrypt($data, $key)
    {
        Log::info(['DECRYPT' => $data]);

        list($encrypted_data, $iv) = explode('::', base64_decode($data), 2);

        return openssl_decrypt($encrypted_data, "AES-128-CBC", $key, $options = 0, $iv);

    }

    //generate_auth_code
    public function generate_auth_code($request_session_id)
    {
        //generate the auth code
        $auth_code = bin2hex(random_bytes(32));
        $encrypted_auth_code = $this->encrypt($auth_code, $request_session_id);

        return urlencode($encrypted_auth_code);
    }

    //set session
    public function set_session($session_name, $session_value)
    {
        config(['session.lifetime' => $this->session_ttl]);
        //make session available for 15 minutes only
        session()->put($session_name, $session_value);

        session()->save();

        return true;
    }

    //get session
    public function get_session($session_name)
    {
        return session()->get($session_name);
    }

    //delete session
    public function delete_session_name($session_name)
    {
        session()->forget($session_name);

        return true;
    }

    //verifyCodeChallenge
    public function verifyCodeChallengeOauth2($codeChallenge, $codeVerifier)
    {
        $codeChallengeGenerated = base64_encode(hash('sha256', $codeVerifier, true));

        if ($codeChallengeGenerated == $codeChallenge) {
            return true;
        }

        return false;
    }

    //get_session from session cookie
    public function get_session_from_session_cookie(Request $request)
    {
        try {
            $session_cookie = $request->cookie($this->session_name);

            Log::info(['SESSION COOKIE' => $session_cookie]);

            if (!$session_cookie) {
                return [];
            }

            $session = Session::where('session_id', $session_cookie)
                ->where('validity', true)
                ->where('valid_until', '>', date('Y-m-d H:i:s'))
                ->first();

            // Log::info(['SESSION TABLE' => $session]);

            if (!$session) {
                return [];
            }

            //check the auth request
            $auth_request = AuthRequest::where('request_session_id', $session_cookie)->first();

            Log::info(['AUTHREQUEST_CODE' => $auth_request->request_code]);

            if (!$auth_request) {
                return [];
            }

            //check the client
            $client = Client::where('client_id', $auth_request->client_id)->first();
            Log::info(['AUTHREQUEST_CLIENT' => $client->client_id]);

            if (!$client) {
                return [];
            }

            $user = AuthUser::find($auth_request->user_id);

            if (!$user) {
                return [];
            }

            //return array with session and client
            return [
                'session_id' => $session->id,
                'client' => $client,
                'user' => $user,
            ];
        } catch (\Throwable $th) {

            Log::info(['get_session_from_session_cookie' => $th->getMessage()]);
            return [];
        }

    }
}
