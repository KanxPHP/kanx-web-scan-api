<?php

require_once __DIR__ . '/../vendor/autoload.php';

use KanxPHP\Core\SafeJSON;
use KanxPHP\Core\SafeInput;
use KanxPHP\Core\Exceptions\IntegrityException;
use KanxPHP\Controllers\AuditorController;
use KanxPHP\Controllers\SslCheckController;
use KanxPHP\Controllers\RobotsController;
use KanxPHP\Controllers\DnsController;
use KanxPHP\Controllers\WhoisController;
use KanxPHP\Controllers\GeolocationController;
use KanxPHP\Controllers\TrustScoreController;

/**
 * RapidAPI Web-Scan Kit Entry Point
 */

try {
    // 1. Get all input (automatically merges $_GET and JSON body)
	$input = SafeInput::all();

	// 2. Routing logic remains the same
	$tool = SafeInput::get('tool', 'health');

    // 3. Determine which tool to run (via URL param or JSON body)
    $tool = SafeInput::get('tool');

    // 4. The RAD Routing Engine
    $response = match ($tool) {
        'audit'  => (new AuditorController())->handle($input),
        'ssl'    => (new SslCheckController())->handle($input),
        'robots' => (new RobotsController())->handle($input),
        'dns'    => (new DnsController())->handle($input),
        'whois'    => (new WhoisController())->handle($input),
        'geo'    => (new GeolocationController())->handle($input),
        'trust'    => (new TrustScoreController())->handle($input),
        'health' => SafeJSON::success(['status' => 'online', 'kit' => 'web-scan-v1']),
        default  => SafeJSON::error("Unknown tool requested. Options: audit, ssl, robots, dns.", [], 404)
    };

    echo $response;

} catch (IntegrityException $e) {
    // Catch malformed JSON payloads specifically
    echo SafeJSON::error($e->getMessage(), $e->getContext(), 422);
} catch (\Throwable $e) {
    // Catch-all for any unexpected infrastructure crashes
    echo SafeJSON::error("Infrastructure Error", ['trace' => $e->getMessage()], 500);
}