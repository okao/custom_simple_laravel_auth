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
        // user_id INTEGER, session_id TEXT, validity boolean DEFAULT false, valid_until DATETIME, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at
        Schema::create('sessions', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('user_id');
            $table->text('session_id');
            $table->boolean('validity')->default(false);
            $table->dateTime('valid_until')->nullable();
            $table->dateTime('last_used_at')->nullable();
            $table->timestamps();

            //foreign key
            $table->foreign('user_id')->references('id')->on('auth_users')->onDelete('cascade')->onUpdate('cascade');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('sessions');
    }
};
