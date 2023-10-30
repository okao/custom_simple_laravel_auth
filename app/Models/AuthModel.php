<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;


class AuthModel extends Model
{
    use HasFactory;

    private $username = 'admin';
    private $password = 'Welcome@123#';
    private $cookie_ttl = 5;
    private $session_ttl = 5; //5 minutes
    private $login_cookie_name = 'login_cookie';
    private $session_name = 'user_session';

    public function initialize()
    {
        //write below code using DB facade
        $db = DB::connection(env('MYSQL_DB_CONNECTION'))->getPdo();
        $query_create_users_table = 'CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTO_INCREMENT, username TEXT, password TEXT, consent TEXT, two_factor TEXT)';
        $db->exec($query_create_users_table);

        $query_create_sessions_table = 'CREATE TABLE IF NOT EXISTS sessions (id INTEGER PRIMARY KEY AUTO_INCREMENT, user_id INTEGER, session_id TEXT, validity boolean DEFAULT false, valid_until DATETIME, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id))';
        $db->exec($query_create_sessions_table);

        $query_create_two_factor_table = 'CREATE TABLE IF NOT EXISTS two_factor (id INTEGER PRIMARY KEY AUTO_INCREMENT, user_id INTEGER, two_factor_code TEXT, method VARCHAR(255) DEFAULT "mobile", valid_until DATETIME, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id))';
        $db->exec($query_create_two_factor_table);

        $query_create_user_failed_attempts_table = 'CREATE TABLE IF NOT EXISTS user_failed_attempts (id INTEGER PRIMARY KEY AUTO_INCREMENT, user_id INTEGER, number_of_attempts INTEGER DEFAULT 0, temporary_lockout_status boolean DEFAULT false, temporary_lockout_until DATETIME DEFAULT CURRENT_TIMESTAMP, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id))';
        $db->exec($query_create_user_failed_attempts_table);

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

            $update_user = AuthUser::where('username', $this->username)->update([
                'password_hash' => $hashed_password
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


        //get the user from the db
        // $db = new \PDO(env('DB_CONNECTION') . ':' . env('DB_DATABASE'));

        // $query = $db->prepare('SELECT * FROM users WHERE username = ?');

        // $query->execute([$user['username']]);

        // $db_user = $query->fetch(\PDO::FETCH_ASSOC);

        // if (!$db_user) {
        //     return [];
        // }

        // //check if the user and db user passwords match
        // if (!password_verify($user['password'], $db_user['password'])) {
        //     return [];
        // }

        // //to user append the id
        // $user['id'] = $db_user['id'];

        // return $user;

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
        // //get the user from the db
        // $db = new \PDO(env('DB_CONNECTION') . ':' . env('DB_DATABASE'));

        // $query = $db->prepare('SELECT * FROM users WHERE id = ?');

        // $query->execute([$user_id]);

        // $user = $query->fetch(\PDO::FETCH_ASSOC);

        // if (!$user) {
        //     return false;
        // }

        // //generate the 2fa code which is a random 6 digit number
        // $two_factor_code = rand(100000, 999999);

        // //create the two factor code in the db
        // $valid_until = date('Y-m-d H:i:s', time() + 60 * 5); //5 minutes

        // $query = $db->prepare('INSERT INTO two_factor (user_id, two_factor_code, valid_until) VALUES (?, ?, ?)');
        // $query->execute([$user_id, $two_factor_code, $valid_until]);

        // //TODO send the 2fa code to the user
        // Log::info(['TwoFA Code' => $two_factor_code]);

        // return true;

        $user = DB::table('users')->where('id', $user_id)->first();

        if (!$user) {
            return false;
        }

        //generate the 2fa code which is a random 6 digit number
        $two_factor_code = rand(100000, 999999);

        //create the two factor code in the db
        $valid_until = date('Y-m-d H:i:s', time() + 60 * 5); //5 minutes

        DB::table('two_factor')->insert([
            'user_id' => $user_id,
            'two_factor_code' => $two_factor_code,
            'valid_until' => $valid_until
        ]);

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
            // $user = $this->get_user_from_login_cookie($request);

            // Log::info(['USER FROM COOKIE' => $user]);

            // if (!$user) {
            //     return false;
            // }

            // //get the two factor code from the request
            // $two_factor_code = $request->code;

            // //get the two factor code from the db
            // $db = new \PDO(env('DB_CONNECTION') . ':' . env('DB_DATABASE'));

            // $query = $db->prepare('SELECT * FROM two_factor WHERE user_id = ? AND two_factor_code = ?');

            // $query->execute([$user['id'], $two_factor_code]);

            // $two_factor = $query->fetch(\PDO::FETCH_ASSOC);


            // //check if the two factor code is expired
            // $now_time = date('Y-m-d H:i:s');

            // if ($two_factor['valid_until'] < $now_time) {
            //     return false;
            // }

            // if (!$two_factor) {

            //     //Increment the number of failed attempts
            //     $query = $db->prepare('SELECT * FROM user_failed_attempts WHERE user_id = ?');

            //     $query->execute([$user['id']]);

            //     $user_failed_attempts = $query->fetch(\PDO::FETCH_ASSOC);


            //     if (!$user_failed_attempts) {
            //         //create the user failed attempts
            //         $query = $db->prepare('INSERT INTO user_failed_attempts (user_id, number_of_attempts) VALUES (?, ?)');

            //         $query->execute([$user['id'], 1]);
            //     } else {
            //         //increment the number of attempts
            //         $query = $db->prepare('UPDATE user_failed_attempts SET number_of_attempts = ? WHERE user_id = ?');

            //         $query->execute([$user_failed_attempts['number_of_attempts'] + 1, $user['id']]);
            //     }


            //     //check if the number of attempts is greater than 3
            //     if ($user_failed_attempts['number_of_attempts'] >= 3) {
            //         //lock the user out for 5 minutes
            //         $query = $db->prepare('UPDATE user_failed_attempts SET temporary_lockout_status = ?, temporary_lockout_until = ? WHERE user_id = ?');
            //         $query->execute(['true', date('Y-m-d H:i:s', time() + 60 * 5), $user['id']]);
            //     }

            //     return false;
            // }


            // //reset the number of failed attempts
            // $query = $db->prepare('UPDATE user_failed_attempts SET number_of_attempts = ? WHERE user_id = ?');
            // $query->execute([0, $user['id']]);



            // //check if the two factor code is expired
            // $now_time = date('Y-m-d H:i:s');

            // if ($two_factor['valid_until'] < $now_time) {
            //     return false;
            // }

            // //update the user two factor column to true
            // $query = $db->prepare('UPDATE users SET two_factor = ? WHERE id = ?');

            // $query->execute(['true', $user['id']]);

            // //delete the two factor code from the db
            // $query = $db->prepare('DELETE FROM two_factor WHERE user_id = ?');

            // $query->execute([$user['id']]);

            // //send the user to the home page
            // return true;


            $user = $this->get_user_from_login_cookie($request);

            Log::info(['USER FROM COOKIE' => $user]);

            if (!$user) {
                return false;
            }

            //get the two factor code from the request
            $two_factor_code = $request->code;

            $two_factor = DB::table('two_factor')->where('user_id', $user['id'])
                ->where('two_factor_code', $two_factor_code)
                ->first();

            //check if the two factor code is expired
            $now_time = date('Y-m-d H:i:s');

            if ($two_factor->valid_until < $now_time) {
                return false;
            }

            if (!$two_factor) {

                //Increment the number of failed attempts
                $user_failed_attempts = DB::table('user_failed_attempts')->where('user_id', $user['id'])->first();

                if (!$user_failed_attempts) {
                    //create the user failed attempts
                    DB::table('user_failed_attempts')->insert([
                        'user_id' => $user['id'],
                        'number_of_attempts' => 1
                    ]);
                } else {
                    //increment the number of attempts
                    DB::table('user_failed_attempts')->where('user_id', $user['id'])->update([
                        'number_of_attempts' => $user_failed_attempts->number_of_attempts + 1
                    ]);
                }

                if ($user_failed_attempts->number_of_attempts >= 3) {
                    //lock the user out for 5 minutes
                    DB::table('user_failed_attempts')->where('user_id', $user['id'])->update([
                        'temporary_lockout_status' => 'true',
                        'temporary_lockout_until' => date('Y-m-d H:i:s', time() + 60 * 5)
                    ]);
                }

                return false;
            }

            //reset the number of failed attempts
            DB::table('user_failed_attempts')->where('user_id', $user['id'])->update([
                'number_of_attempts' => 0
            ]);


            //check if the two factor code is expired
            $now_time = date('Y-m-d H:i:s');

            if ($two_factor->valid_until < $now_time) {
                return false;
            }

            //update the user two factor column to true

            DB::table('users')->where('id', $user['id'])->update([
                'two_factor' => 'true'
            ]);

            //delete the two factor code from the db
            DB::table('two_factor')->where('user_id', $user['id'])->delete();

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
        // $db = new \PDO(env('DB_CONNECTION') . ':' . env('DB_DATABASE'));

        // $query = $db->prepare('INSERT INTO sessions (user_id, session_id, validity, valid_until) VALUES (?, ?, ?, ?)');

        // $query->execute([$user_id, $session_id, $validity, $valid_until]);

        try {

            $valid = $validity == 'true' ? 1 : 0;

            DB::table('sessions')->insert([
                'user_id' => $user_id,
                'session_id' => $session_id,
                'validity' => $valid,
                'valid_until' => $valid_until
            ]);


            //get the user from the db
            $session = DB::table('sessions')->where('session_id', $session_id)->first();

            return $session;
        } catch (\Exception $e) {
            Log::info(['create_session: ' => $e->getMessage()]);

            return false;
        }
    }

    public function create_session_id($user_id, $validity, $valid_until)
    {
        try {
            $session_id = bin2hex(random_bytes(32));

            $session = $this->create_session($user_id, $session_id, $validity, $valid_until);

            Log::info(['SESSION' => $session]);

            return $session_id;
        } catch (\Exception $e) {
            Log::info(['create_session_id: ' => $e->getMessage()]);

            return false;
        }
    }

    public function get_user(Request $request)
    {
        $session_id = $request->cookie('user_session');

        if (!$session_id) {
            return [];
        }

        if (!$this->check_session($session_id)) {
            return [];
        }

        // $db = new \PDO(env('DB_CONNECTION') . ':' . env('DB_DATABASE'));

        // $query = $db->prepare('SELECT * FROM sessions WHERE session_id = ?');

        // $query->execute([$session_id]);

        // $session = $query->fetch(\PDO::FETCH_ASSOC);

        // $user_id = $session['user_id'];

        // $query = $db->prepare('SELECT * FROM users WHERE id = ?');

        // $query->execute([$user_id]);

        // $user = $query->fetch(\PDO::FETCH_ASSOC);

        // //remove the password from the user
        // unset($user['password']);

        // return $user;

        $session = DB::table('sessions')->where('session_id', $session_id)->first();

        $user_id = $session->user_id;

        $user = DB::table('users')->where('id', $user_id)->first();

        //remove the password from the user
        unset($user->password);

        return $user;
    }

    public function update_session_id($session_id, $validity, $valid_until)
    {
        $this->update_session($session_id, $validity, $valid_until);

        //update the cookie in the browser
        Cookie::queue($this->session_name, $session_id, $this->cookie_ttl, '/api/auth', null, false, true);

        return $session_id;
    }

    private function update_session($session_id, $validity, $valid_until)
    {
        // $db = new \PDO(env('DB_CONNECTION') . ':' . env('DB_DATABASE'));

        // $query = $db->prepare('UPDATE sessions SET validity = ?, valid_until = ? WHERE session_id = ?');

        // $query->execute([$validity, $valid_until, $session_id]);

        DB::table('sessions')->where('session_id', $session_id)->update([
            'validity' => $validity,
            'valid_until' => $valid_until
        ]);

        return true;
    }

    public function delete_session($session_id)
    {
        //delete the sessions
        // $db = new \PDO(env('DB_CONNECTION') . ':' . env('DB_DATABASE'));

        // $query = $db->prepare('DELETE FROM sessions WHERE session_id = ?');

        // $query->execute([$session_id]);


        // //also invalidate the cookie called user_session in the browser
        // Cookie::queue(Cookie::forget('user_session'));

        DB::table('sessions')->where('session_id', $session_id)->delete();

        //also invalidate the cookie called user_session in the browser
        setcookie($this->session_name, '', time() - 3600, '/api', null, false, true);

        return true;
    }

    //get_user_from_session
    public function get_user_from_session($request)
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

    //encrypt using openssl HS256 algorithm and return the encrypted string
    public function encrypt($data, $key)
    {
        $encrypted = base64_encode(openssl_encrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $key));

        return $encrypted;
    }

    //decrypt using openssl HS256 algorithm and return the decrypted string
    public function decrypt($data, $key)
    {
        $decrypted = openssl_decrypt(base64_decode($data), 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $key);

        return $decrypted;
    }

    //generate_auth_code
    public function generate_auth_code($user_id, $client_id, $request_session_id, $code_challenge, $redirect_uri, $scopes)
    {
        //generate the auth code
        $auth_code = bin2hex(random_bytes(32));

        //create the auth code in the db
        $expires_at = date('Y-m-d H:i:s', time() + 60 * 5); //5 minutes

        // $query = $db->prepare('INSERT INTO auth_codes (client_id, user_id, auth_code, redirect_uri, scopes, valid_until) VALUES (?, ?, ?, ?, ?, ?)');
        // $query->execute([$client_id, $user_id, $auth_code, $redirect_uri, $scopes, $valid_until]);

        $auth_code_model = new AuthCode();
        $auth_code_model->client_id = $client_id;
        $auth_code_model->user_id = $user_id;
        $auth_code_model->auth_code = $auth_code;
        $auth_code_model->redirect_uri = $redirect_uri;
        $auth_code_model->scopes = $scopes;
        $auth_code_model->expires_at = $expires_at;

        return $auth_code;
    }

    //set session
    public function set_session($session_name, $session_value)
    {
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
}
