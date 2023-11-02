<?php

use App\Http\Controllers\AuthController;
use App\Models\AuthCode;
use App\Models\AuthModel;
use App\Models\AuthRequest;
use App\Models\Client;
use App\Models\Session;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
 */

// Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
//     return $request->user();
// });

// / -> /login
Route::get('/', function () {
    return redirect()->route('login');
});

Route::group(['middleware' => ['web'], 'prefix' => 'auth'], function () {
    Route::get('/authorize', [AuthController::class, 'client_authorize'])->name('authorize');
    Route::get('/login', [AuthController::class, 'login'])->name('login');
    Route::post('/submit_login', [AuthController::class, 'submit_login'])->name('submit_login');
    Route::get('/consent', [AuthController::class, 'consent'])->name('consent');
    Route::post('/submit_consent', [AuthController::class, 'submit_consent'])->name('submit_consent');
    Route::get('/2fa', [AuthController::class, 'two_factor'])->name('2fa');
    Route::post('/submit_2fa', [AuthController::class, 'submit_two_factor'])->name('submit_2fa');
    Route::post('/verification/resend', [AuthController::class, 'resend_verification'])
        ->name('verification.resend');

    //any other route will be redirected to login
    Route::any('{any}', function () {
        return redirect()->route('login');
    })->where('any', '.*');
});

//verification.resend

Route::group(['middleware' => ['web', 'check_auth']], function () {
    Route::get('/home', [AuthController::class, 'home'])->name('home');

    Route::post('/logout', [AuthController::class, 'logout'])->name('logout_api');
});

//for testing
Route::group(['middleware' => []], function () {
    Route::get('/redirect', function (Request $request) {

        $all_params = $request->all();

        //display all params
        echo "<pre>";
        print_r($all_params);
        echo "</pre>";

        //get the auth code
        Log::info('Auth code Raw: ' . $all_params['code']);
        Log::info('Auth code: ' . urldecode($all_params['code']));

        $code = urldecode($all_params['code']);

        //get the auth code from the db
        $auth_code = AuthCode::where('code', $code)
            ->where('expires_at', '>', date('Y-m-d H:i:s'))
            ->where('revoked', false)
            ->first();

        //if the auth code is not found or is revoked
        if (!$auth_code) {
            echo "Auth code is invalid or revoked!";
            exit();
        }

        //create a form with all params and submit it to the redirect_uri

        $redirect_uri = $auth_code->redirect_uri;

        // $form = '<form id="form" action="' . $redirect_uri . '" method="post">';
        // foreach ($all_params as $key => $value) {
        //     $form .= '<input type="hidden" name="' . $key . '" value="' . $value . '">';
        // }
        // $form .= '</form>';

        // $form .= '<script>document.getElementById("form").submit();</script>';

        // echo $form;

        //display all auth code params
        echo "<pre>";
        print_r($auth_code->toArray());
        echo "</pre>";

        $client_id = $auth_code->client_id;

        //get the client secret with like
        $client = Client::find($client_id);
        $client_secret = $client->client_secret;

        //try to decode the code
        $auth_model = new AuthModel();
        $decoded_code = $auth_model->encrypt_decrypt(
            'decrypt', $all_params['code'], $client_secret,
            env('APP_KEY')
        );
        $decoded_code = json_decode($decoded_code);

        // Log::info('Decoded code: ' . $decoded_code);
        Log::info('Secret: ' . $client_secret);

        echo "<pre>";
        print_r($decoded_code);
        echo "</pre>";
        //display the decoded code

        //get session data
        $session_data = Session::find($auth_code->session_id);

        echo "<pre>";
        print_r($session_data->toArray());
        echo "</pre>";

        // get AuthRequest data
        $auth_request = AuthRequest::find($decoded_code->request_id);

        echo "<pre>";
        print_r($auth_request->toArray());
        echo "</pre>";

        echo exit();

    });
});

//token
Route::group(['middleware' => []], function () {
    Route::post('/token', [AuthController::class, 'token'])->name('token');
});
