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
        Schema::create('auth_requests', function (Blueprint $table) {
            $table->id();
            $table->string('request_code')->nullable();
            $table->string('client_id')->nullable();
            $table->unsignedBigInteger('user_id')->nullable();
            $table->string('request_session_id');
            $table->string('state')->nullable();
            $table->string('scopes')->nullable();
            $table->text('code_challenge')->nullable();
            $table->dateTime('expires_at')->nullable();

            //user details
            $table->string('username')->nullable();
            $table->string('password_hash')->nullable();
            $table->boolean('consent_granted')->default(false);
            $table->boolean('two_factor_granted')->default(false);

            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('auth_requests');
    }
};
