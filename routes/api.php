<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Log;
use App\Http\Controllers\AuthController;

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

Route::group(['middleware' => ['web', 'redirect_auth'], 'prefix' => 'auth'], function () {
    Route::get('/login', [AuthController::class, 'login'])->name('login');
    Route::post('/submit_login',  [AuthController::class, 'submit_login'])->name('submit_login');
    Route::get('/consent', [AuthController::class, 'consent'])->name('consent');
    Route::post('/submit_consent',  [AuthController::class, 'submit_consent'])->name('submit_consent');
    Route::get('/2fa', [AuthController::class, 'two_factor'])->name('2fa');
    Route::post('/submit_2fa',  [AuthController::class, 'submit_two_factor'])->name('submit_2fa');
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
