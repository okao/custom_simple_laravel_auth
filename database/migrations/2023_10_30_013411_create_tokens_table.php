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
        Schema::create('tokens', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('client_id')->index();
            $table->unsignedBigInteger('user_id')->index();
            $table->string('scopes')->nullable();
            $table->string('for', 255)->default('oauth');
            $table->string('request_session_id', 255)->nullable();
            $table->string('type', 100)->default('access_token')->index();
            $table->text('token');
            $table->unsignedBigInteger('refresh_token_id')->nullable()->index();
            $table->unsignedInteger('usage')->default(0);
            $table->unsignedBigInteger('expires_in')->nullable();
            $table->timestamp('revoked_at')->nullable();
            $table->boolean('revoked')->default(false);
            $table->string('ip', 255)->nullable();
            $table->string('user_agent', 255)->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('tokens');
    }
};
