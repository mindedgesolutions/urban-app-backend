<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\OneTimeToken;
use App\Models\RefreshToken;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;

class AuthController extends Controller
{
    public function signup(Request $request) {}

    // -----------------------------------

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'username' => 'required|exists:users,email',
            'password' => 'required'
        ], [
            'username.required' => 'Username is required',
            'username.exists'   => 'User does not exist',
            'password.required' => 'Password is required'
        ]);
        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }
        try {
            DB::beginTransaction();

            if (!Auth::attempt(['email' => $request->username, 'password' => $request->password])) {
                return response()->json(['errors' => ['Incorrect credentials']], Response::HTTP_UNAUTHORIZED);
            }
            $user = Auth::user();
            $tokenResult = $user->createToken('AuthToken');
            $accessToken = $tokenResult->accessToken;
            $tokenModel = $tokenResult->token;
            $expiresAt = $tokenModel->expires_at ?? Carbon::now()->addMinutes(5);
            $refreshToken = Str::random(64);
            $name = config('lookup.REFRESH_TOKEN_NAME');

            RefreshToken::create([
                'user_id' => $user->id,
                'token' => hash('sha256', $refreshToken),
                'revoked' => false,
                'expires_at' => now()->addDays(3),
            ]);

            $oneTimeToken = Str::random(64);
            OneTimeToken::create([
                'user_id' => $user->id,
                'token_id' => $oneTimeToken,
                'status' => 'active',
            ]);

            $responseData = [
                'data' => $user,
                'token' => $accessToken,
                'token_type' => 'Bearer',
                'expires_in' => $expiresAt, // 15 minutes in seconds
                'one_time_pass' => $oneTimeToken,
            ];

            DB::commit();

            return response()->json($responseData, Response::HTTP_OK)->cookie(
                $name,
                $refreshToken,
                60 * 24 * 30,
                '/',
                null,
                false,
                true,
                false,
                'Lax'
            );
        } catch (\Throwable $th) {
            Log::error('Login error: ', $th->getMessage());
            DB::rollBack();
            return response()->json(['error' => 'Login failed'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    // -----------------------------------

    public function mobileLogin(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'username' => 'required|exists:users,email',
            'password' => 'required'
        ], [
            'username.required' => 'Username is required',
            'username.exists'   => 'User does not exist',
            'password.required' => 'Password is required'
        ]);
        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }
        try {
            DB::beginTransaction();

            if (!Auth::attempt(['email' => $request->username, 'password' => $request->password])) {
                return response()->json(['errors' => ['Incorrect credentials']], Response::HTTP_UNAUTHORIZED);
            }
            $user = Auth::user();
            $tokenResult = $user->createToken('AuthToken');
            $accessToken = $tokenResult->accessToken;
            $tokenModel = $tokenResult->token;
            $expiresAt = $tokenModel->expires_at ?? Carbon::now()->addMinutes(5);
            $refreshToken = Str::random(64);
            $name = config('lookup.REFRESH_TOKEN_NAME');

            RefreshToken::create([
                'user_id' => $user->id,
                'token' => hash('sha256', $refreshToken),
                'revoked' => false,
                'expires_at' => now()->addDays(3),
            ]);

            $oneTimeToken = Str::random(64);
            OneTimeToken::create([
                'user_id' => $user->id,
                'token_id' => $oneTimeToken,
                'status' => 'active',
            ]);

            $responseData = [
                'data' => $user,
                'token' => $accessToken,
                'token_type' => 'Bearer',
                'expires_in' => $expiresAt, // 15 minutes in seconds
                'one_time_pass' => $oneTimeToken,
                'refresh_token' => $refreshToken,
            ];

            DB::commit();

            return response()->json($responseData, Response::HTTP_OK);
        } catch (\Throwable $th) {
            Log::error('Login error: ', $th->getMessage());
            DB::rollBack();
            return response()->json(['error' => 'Login failed'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    // -----------------------------------

    public function refreshToken(Request $request)
    {
        try {
            DB::beginTransaction();

            $name = config('lookup.REFRESH_TOKEN_NAME');
            $refreshToken = $request->cookie($name);

            if (!$refreshToken) {
                return response()->json(['error' => 'Unauthenticated'], 401);
            }

            $stored = RefreshToken::where('token', hash('sha256', $refreshToken))
                ->where('revoked', false)
                ->where('expires_at', '>', now())
                ->first();
            Log::info('Created refresh token: ' . ($stored ? $stored->id : 'null'));

            if (!$stored) {
                return response()->json(['error' => 'Unauthenticated'], 401);
            }

            $user = User::find($stored->user_id);
            if (!$user) {
                return response()->json(['error' => 'Unauthenticated'], 401);
            }

            $tokenResult = $user->createToken('AuthToken');
            $tokenModel = $tokenResult->token;
            $expiresAt = $tokenModel->expires_at ?? now()->addMinutes(5);

            $newRefreshToken = Str::random(64);
            RefreshToken::whereId($stored->id)->update([
                'token'      => hash('sha256', $newRefreshToken),
                'expires_at' => $expiresAt,
            ]);

            DB::commit();

            return response()->json([
                'data'        => $user,
                'token'       => $tokenResult->accessToken,
                'token_type'  => 'Bearer',
                'expires_in'  => $expiresAt,
            ])->cookie(
                $name,
                $newRefreshToken,
                60 * 24 * 30,
                '/',
                null,
                false,
                true,
                false,
                'Lax'
            );
        } catch (\Throwable $th) {
            DB::rollBack();
            Log::error('Token refresh error: ' . $th->getMessage());
            return response()->json(['error' => 'Token refresh failed'], 500);
        }
    }

    // -----------------------------------

    public function deleteOneTimeToken($token)
    {
        $check = OneTimeToken::where('token_id', $token)->where('status', 'active')->first();
        if ($check) {
            OneTimeToken::where('token_id', $token)->update(['status' => 'used']);
            return response()->json(['message' => 'success'], Response::HTTP_OK);
        } else {
            return response()->json(['errors' => ['Token not found']], Response::HTTP_UNAUTHORIZED);
        }
    }

    // -----------------------------------

    public function signout(Request $request)
    {
        $name = config('lookup.REFRESH_TOKEN_NAME');
        $refreshToken = $request->cookie($name);
        if ($refreshToken) {
            RefreshToken::where('token', hash('sha256', $refreshToken))
                ->where('revoked', false)
                ->update(['revoked' => true]);
            RefreshToken::where('token', hash('sha256', $refreshToken))->delete();
        }
        $request->user()->token()->revoke();
        $cookieName = config('lookup.REFRESH_TOKEN_NAME');
        Log::info('Cookie name: ' . $cookieName);
        $forgetCookie = cookie()->forget($cookieName, '/', null, false, true, false, 'Lax');

        return response()->json(['message' => 'Logged out successfully'])
            ->withCookie($forgetCookie);
    }

    // -----------------------------------

    public function me(Request $request)
    {
        $user = Auth::user();

        return response()->json(['data' => $user], Response::HTTP_OK);
    }

    // -----------------------------------

    public function changePassword(Request $request) {}

    // -----------------------------------

    public function profileUpdate(Request $request) {}
}
