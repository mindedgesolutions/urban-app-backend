<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\RefreshToken;
use App\Models\User;
use GuzzleHttp\Client;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Laravel\Socialite\Facades\Socialite;

class AuthController extends Controller
{
    public function signup(Request $request) {}

    // -----------------------------------

    public function signin(Request $request) {}

    // -----------------------------------

    public function githubRedirect(Request $request)
    {
        return Socialite::driver('github')->redirect();
    }

    // -----------------------------------

    public function githubCallback(Request $request)
    {
        try {
            DB::beginTransaction();

            $githubUser = Socialite::driver('github')
                ->setHttpClient(new Client([
                    'verify' => false
                ]))
                ->user();

            $user = User::updateOrCreate(
                [
                    'email' => $githubUser->getEmail()
                ],
                [
                    'name' => $githubUser->getName(),
                    'email' => $githubUser->getEmail(),
                    'social_type' => 'github',
                    'social_id' => $githubUser->getId(),
                ]
            );

            $tokenResult = $user->createToken('AuthToken');
            $accessToken = $tokenResult->accessToken;
            $refreshToken = $tokenResult->token->id;
            $expiresAt = $tokenResult->token->expires_at;
            $name = config('lookup.REFRESH_TOKEN_NAME');

            RefreshToken::create([
                'user_id' => $user->id,
                'token' => hash('sha256', $refreshToken),
                'expires_at' => $expiresAt,
                'revoked' => false,
            ]);

            DB::commit();

            $refreshCookie = cookie(
                $name,              // name
                $refreshToken,      // value
                60 * 24 * 15,       // expiry in minutes (15 days)
                '/api',             // path
                null,               // domain (null = current)
                false,              // secure (set true in HTTPS)
                true,               // httpOnly
                false,              // raw
                'Lax'               // SameSite (important for cross-origin React app)
            );

            return redirect('http://localhost:5173/admin/authenticating')->cookie($refreshCookie);
        } catch (\Throwable $th) {
            DB::rollBack();
            return response()->json(['error' => 'Authentication failed'], 500);
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

            $refreshCookie = cookie(
                $name,
                $newRefreshToken,
                60 * 24 * 15,
                '/api',
                null,
                false,
                true,
                false,
                'Lax'
            );

            return response()->json([
                'data'        => $user,
                'token'       => $tokenResult->accessToken,
                'token_type'  => 'Bearer',
                'expires_in'  => 15 * 60,
            ])->cookie($refreshCookie);
        } catch (\Throwable $th) {
            DB::rollBack();
            return response()->json(['error' => 'Token refresh failed'], 500);
        }
    }

    // -----------------------------------

    public function signout(Request $request) {}
}
