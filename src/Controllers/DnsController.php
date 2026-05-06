<?php

namespace KanxPHP\Controllers;

use KanxPHP\Core\SafeJSON;

class DnsController 
{

    public function handle($input) 
    {
        $domain = $input['domain'] ?? null;
        $typeInput = strtoupper($input['type'] ?? 'ANY');

        if (!$domain || !filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            return SafeJSON::error("A valid 'domain' is required.");
        }

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
        $records = @dns_get_record($domain, $dnsType);

        // --- RAD PRODUCTION FALLBACK FOR DIGITALOCEAN ---
        // If ANY fails or returns empty, perform a targeted look-up array
        if (($records === false || empty($records)) && $typeInput === 'ANY') {
            $records = [];
            $fallbackTypes = [DNS_A, DNS_AAAA, DNS_MX, DNS_TXT, DNS_NS];
            
            foreach ($fallbackTypes as $fallbackType) {
                $subRecords = @dns_get_record($domain, $fallbackType);
                if (is_array($subRecords)) {
                    $records = array_merge($records, $subRecords);
                }
            }
        }
        // ------------------------------------------------

        if (empty($records)) {
            return SafeJSON::error("No DNS records found for {$domain}.", [], 404);
        }

        return SafeJSON::success([
            'domain' => $domain,
            'queried_type' => $typeInput,
            'count' => count($records),
            'records' => $records
        ]);
    }
}

