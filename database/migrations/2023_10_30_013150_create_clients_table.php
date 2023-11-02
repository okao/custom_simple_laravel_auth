<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('clients', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->string('email')->nullable();
            $table->string('logo')->nullable();
            $table->string('description')->nullable();
            $table->string('domain')->nullable();
            $table->text('white_listed_ips')->nullable();
            $table->boolean('active')->default(true);
            $table->text('client_id')->nullable();
            $table->string('client_secret')->nullable();
            $table->string('logged_out_uri')->nullable();
            $table->string('redirect_uri')->nullable();
            $table->string('scopes')->nullable();
            $table->string('grant_types')->default('authorization_code');
            $table->string('response_types')->default('code');
            $table->text('privateKey_path')->nullable();
            $table->text('publicKey_path')->nullable();

            //all oauth config options are here
            $table->unsignedInteger('auth_code_ttl')->default(5); //authorization code ttl in minutes
            $table->unsignedInteger('access_token_ttl')->default(10); //access token ttl in minutes
            $table->unsignedInteger('refresh_token_ttl')->default(1440); //refresh token ttl in minutes
            $table->unsignedInteger('max_attempts')->default(5); //max attempts to login before lockout
            $table->unsignedInteger('lockout_ttl')->default(60); //lockout time in minutes after max attempts
            $table->boolean('allow_skip_permission')->default(false); //if false, user must have permission to access client
            $table->boolean('allow_multiple_tokens')->default(false); //if false, only one token per user per client
            $table->boolean('allow_refresh_token')->default(true); //if false, refresh token will not be issued

            $table->boolean('skip_pkce')->default(false); //if true, pkce will not be required
            $table->unsignedInteger('rate_limit')->default(15); //max requests per minute, 15 is default for oauth clients (not users)

            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('clients');
    }
};
