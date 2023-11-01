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
        // user_id INTEGER, number_of_attempts INTEGER DEFAULT 0, temporary_lockout_status boolean DEFAULT false, temporary_lockout_until DATETIME DEFAULT CURRENT_TIMESTAMP, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at
        Schema::create('user_failed_attempts', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('user_id');
            $table->integer('number_of_attempts')->default(0);
            $table->boolean('temporary_lockout_status')->default(false);
            $table->dateTime('temporary_lockout_until')->nullable();
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
        Schema::dropIfExists('user_failed_attempts');
    }
};
