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
        Schema::create('auth_codes', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('user_id');
            $table->string('session_id')->nullable();
            $table->string('client_id', 255)->nullable();
            $table->text('code');
            $table->text('redirect_uri')->nullable();
            $table->text('scopes')->nullable();
            $table->text('code_challenge')->nullable();
            $table->boolean('revoked')->default(false);
            $table->dateTime('expires_at')->nullable();
            $table->dateTime('last_used_at')->nullable();
            $table->timestamps();

            // Indexes
            $table->index('user_id');
            $table->index('client_id');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('auth_codes');
    }
};
