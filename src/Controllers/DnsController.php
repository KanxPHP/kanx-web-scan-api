<?php

namespace KanxPHP\Controllers;

use KanxPHP\Core\SafeJSON;
use KanxPHP\Core\SafeInput;

class DnsController 
{

    public function handle($input) 
    {
        $domain = $input['url'] ?? SafeInput::get('domain') ?? null;
        $typeInput = strtoupper(SafeInput::get('type') ?? 'ANY');

        // 1. Validation
        if (!$domain || !filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            return SafeJSON::error("A valid 'domain' is required.");
        }

        // Map user input to PHP DNS constants
        $typeMap = [
            'A'     => DNS_A,
            'AAAA'  => DNS_AAAA,
            'MX'    => DNS_MX,
            'TXT'   => DNS_TXT,
            'CNAME' => DNS_CNAME,
            'NS'    => DNS_NS,
            'ANY'   => DNS_ANY
        ];

        $dnsType = $typeMap[$typeInput] ?? DNS_ANY;

        // 2. Core Logic
        try {
            // Using @ to suppress warnings for non-existent domains
            $records = @dns_get_record($domain, $dnsType);

            if ($records === false || empty($records)) {
                return SafeJSON::error("No DNS records found for {$domain}.", [], 404);
            }

            return SafeJSON::success([
                'domain' => $domain,
                'queried_type' => $typeInput,
                'count' => count($records),
                'records' => $records
            ]);

        } catch (\Exception $e) {
            return SafeJSON::error("Internal DNS resolution error: " . $e->getMessage());
        }
    }

}