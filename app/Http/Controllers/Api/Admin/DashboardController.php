<?php

namespace App\Http\Controllers\Api\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Http\Response;

class DashboardController extends Controller
{
    public function test()
    {
        $text = "This is an authenticated route";

        return response()->json(['message' => $text], Response::HTTP_OK);
    }
}
