<?php

use App\Http\Controllers\AuthController;
use App\Models\AuthCode;
use App\Models\AuthModel;
use Illuminate\Http\Request;
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

        //get the client secret
        $client = \App\Models\Client::where('client_id', $client_id)->first();
        $client_secret = $client->secret;

        //try to decode the code
        $auth_model = new AuthModel();
        $urldecoded_code = urldecode($code);
        $decoded_code = $auth_model->decrypt($code, $client_secret);

        echo "<pre>";
        print_r($decoded_code);
        echo "</pre>";
        //display the decoded code

        echo exit();

    });
});
