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
        // user_id INTEGER, two_factor_code TEXT, method VARCHAR(255) DEFAULT "mobile", valid_until DATETIME, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at
        Schema::create('two_factors', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('user_id');
            $table->text('two_factor_code')->nullable();
            $table->string('method', 255)->default('mobile');
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
        Schema::dropIfExists('two_factors');
    }
};
