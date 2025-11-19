<?php

use App\Http\Controllers\Api\Admin\DashboardController;
use App\Http\Controllers\Api\AuthController;
use Illuminate\Support\Facades\Route;

Route::controller(AuthController::class)->prefix('auth')->group(function () {
    Route::post('sign-up', 'signup');
    Route::post('sign-in', 'signin');
    Route::post('refresh-token', 'refreshToken');
    Route::post('delete-one-time-token/{token}', 'deleteOneTimeToken');
});

Route::middleware(['auth:api'])->group(function () {
    Route::controller(AuthController::class)->prefix('auth')->group(function () {
        Route::post('sign-out', 'signout');
        Route::get('me', 'me');
        Route::post('change-password', 'changePassword');
        Route::post('update', 'profileUpdate');
    });

    Route::prefix('admin')->group(function () {
        Route::controller(DashboardController::class)->prefix('dashboard')->group(function () {
            Route::get('test', 'test');
        });
    });
});
