<?php

use App\Http\Controllers\Api\AuthController;
use Illuminate\Support\Facades\Route;

Route::controller(AuthController::class)->prefix('auth')->group(function () {
    Route::get('github-redirect', 'githubRedirect');
    Route::get('github-callback', 'githubCallback');
});
