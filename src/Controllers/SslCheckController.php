<?php

namespace KanxPHP\Controllers;

use KanxPHP\Core\SafeJSON;
use KanxPHP\Core\SafeInput;

class SslCheckController 
{

    public function handle($input) 
    {
        $host = $input['host'] ?? null;
        
        if (!$host || !filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            return SafeJSON::error("A valid 'host' (e.g., example.com) is required.");
        }

        try {
            // Step 1: Enhanced SSL Context
            $context = stream_context_create([
                "ssl" => [
                    "capture_peer_cert" => true,
                    "SNI_enabled" => true,       // CRITICAL: Allows identifying the domain on shared IPs
                    "peer_name" => $host,        // Ensures the cert matches the requested host
                    "verify_peer" => false,      // Skip CA validation for inspection-only scans
                    "verify_peer_name" => false,
                    "ciphers" => "HIGH:!SSLv2:!SSLv3", // Force modern cipher suites
                ]
            ]);

            // Step 2: Use tls:// for modern negotiation instead of ssl://
            $client = @stream_socket_client(
                "tls://{$host}:443", 
                $errno, 
                $errstr, 
                15, 
                STREAM_CLIENT_CONNECT, 
                $context
            );

            if (!$client) {
                return SafeJSON::error("Could not establish SSL connection to {$host}: {$errstr}");
            }

            // Step 3: Extract and parse the X.509 certificate
            $params = stream_context_get_params($client);
            $cert = openssl_x509_parse($params['options']['ssl']['peer_certificate']);
            
            $expiresAt = $cert['validTo_time_t'];
            $daysLeft = ceil(($expiresAt - time()) / 86400);

            return SafeJSON::success([
                'host' => $host,
                'is_valid' => $daysLeft > 0,
                'expires_at' => date('Y-m-d H:i:s', $expiresAt),
                'days_remaining' => (int)$daysLeft,
                'issuer' => $cert['issuer']['CN'] ?? 'Unknown',
                'serial_number' => $cert['serialNumber']
            ]);
            
        } catch (\Exception $e) {
            return SafeJSON::error("Failed to parse SSL certificate: " . $e->getMessage());
        }
    }

}