<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
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
        // $get_user = $this->get_user($request);

        // try {
        //     if (!$get_user) {
        //         return $next($request);
        //     }

        //     return redirect($this->home_path);
        // } catch (\Exception $e) {
        //     return $next($request);
        // }

        //log the request url
        Log::info('REQUEST URL: ' . $request->url());

        return $next($request);
    }
}
