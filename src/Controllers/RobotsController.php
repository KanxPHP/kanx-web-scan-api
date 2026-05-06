<?php

namespace KanxPHP\Controllers;

use KanxPHP\Core\SafeCurl;
use KanxPHP\Core\SafeJSON;
use KanxPHP\Core\SafeInput;

class RobotsController 
{

    public function handle($input) 
    {
        $url = $input['url'] ?? null;

        if (!$url || !filter_var($url, FILTER_VALIDATE_URL)) {
            return SafeJSON::error("A valid base URL is required.");
        }

        // Ensure we are hitting the /robots.txt path
        $baseUrl = rtrim($url, '/');
        $robotsUrl = $baseUrl . '/robots.txt';

        // 1. Fetch the file securely using your SafeCurl module
        $content = SafeCurl::fetch($robotsUrl, false); // false = fetch body content

        if (!$content) {
            return SafeJSON::error("Could not find or fetch robots.txt at {$robotsUrl}");
        }

        // 2. Parse Logic
        $lines = explode("\n", $content);
        $rules = [];
        $currentUserAgent = '*';

        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line) || strpos($line, '#') === 0) continue;

            if (stripos($line, 'User-agent:') === 0) {
                $currentUserAgent = trim(str_ireplace('User-agent:', '', $line));
            } elseif (stripos($line, 'Disallow:') === 0) {
                $path = trim(str_ireplace('Disallow:', '', $line));
                $rules[$currentUserAgent]['disallow'][] = $path;
            } elseif (stripos($line, 'Sitemap:') === 0) {
                $rules['global']['sitemaps'][] = trim(str_ireplace('Sitemap:', '', $line));
            }
        }

        return SafeJSON::success([
            'source' => $robotsUrl,
            'parsed_at' => date('c'),
            'directives' => $rules
        ]);
    }
    
}