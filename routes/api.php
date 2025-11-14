<?php

use App\Http\Controllers\Api\Admin\DashboardController;
use App\Http\Controllers\Api\AuthController;
use Illuminate\Support\Facades\Route;

Route::controller(AuthController::class)->prefix('auth')->group(function () {
    Route::post('signup', 'signup');
    Route::post('signin', 'signin');
    Route::post('refresh-token', 'refreshToken');
    Route::post('signout', 'signout');
});

Route::middleware(['auth:api'])->prefix('admin')->group(function () {
    Route::controller(DashboardController::class)->prefix('dashboard')->group(function () {
        Route::get('test', 'test');
    });
});
