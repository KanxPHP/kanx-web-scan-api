<?php

namespace KanxPHP\Controllers;

use KanxPHP\Core\SafeCurl;
use KanxPHP\Core\SafeJSON;
use KanxPHP\Core\SafeInput;

class GeolocationController {

    public function handle($input) 
    {
        $target = $input['url'] ?? $input['domain'] ?? null;

        if (!$target) {
            return SafeJSON::error("IP or Domain is required.");
        }
        
        // 1. Resolve domain to IP if necessary
        $ip = filter_var($target, FILTER_VALIDATE_IP) ? $target : gethostbyname($target);

        if ($ip === $target && !filter_var($ip, FILTER_VALIDATE_IP)) {
            return SafeJSON::error("Invalid target or DNS resolution failed.");
        }

        // 2. Fetch Geo Data (Stateless)
        // Using ip-api.com (Free for non-commercial/dev, easy to swap for paid MaxMind/IPStack)
        $raw = SafeCurl::fetch("http://ip-api.com/json/{$ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,isp,proxy", false);
        
        $data = json_decode($raw, true);

        if (!$data || $data['status'] !== 'success') {
            return SafeJSON::error("Geolocation data unavailable.");
        }

        return SafeJSON::success([
            'ip' => $ip,
            'location' => [
                'city' => $data['city'],
                'region' => $data['regionName'],
                'country' => $data['country'],
                'country_code' => $data['countryCode'],
                'coordinates' => [
                    'lat' => $data['lat'],
                    'lon' => $data['lon']
                ]
            ],
            'network' => [
                'isp' => $data['isp'],
                'is_proxy' => $data['proxy'] ?? false
            ]
        ]);
    }
}
