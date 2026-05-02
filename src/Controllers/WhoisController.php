<?php

namespace KanxPHP\Controllers;

use KanxPHP\Core\SafeJSON;
use KanxPHP\Core\SafeInput;
use KanxPHP\Core\SafeCache;

class WhoisController {

    public function handle($input) 
    {
        $domain = $input['domain'] ?? SafeInput::get('domain') ?? null;
        
        if (!$domain || !filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            return SafeJSON::error("Valid domain required.");
        }

        $full = SafeInput::get('full') == 'true' ? 'full' : 'short';
        $domainCached = $domain.'_'.$full;
      
        // Check cache first
        if ($cached = SafeCache::get("whois_$domainCached")) {
            return SafeJSON::success($cached);
        }

        // Standard WHOIS server for most TLDs
        $whoisServer = "whois.iana.org";
        $rawData = $this->queryWhois($whoisServer, $domain);
        $parsed = $this->parseWhois($rawData);

        // Logic: Extract Registration Date (Simplified)
        preg_match('/created:\s+(.*)/i', $rawData, $matches);
        $created = $matches[1] ?? 'Unknown';
        $data = [
            'domain' => $domain,
            'status' => $parsed['status'] ?? 'unknown',
            'dates' => [
                'created' => $parsed['created'] ?? null,
                'updated' => $parsed['updated'] ?? null,
                'expires' => $parsed['expiry'] ?? null,
            ],
            'organisation' => $parsed['organisation'] ?? null,
            'email' => $parsed['email'] ?? null,
            'phone' => $parsed['phone'] ?? null,
            'organisations' => $parsed['organisations'] ?? null,
            'addresses' => $parsed['addresses'] ?? null,
            'contacts' => $parsed['contacts'] ?? null,
            'phones' => $parsed['phones'] ?? null,
            'emails' => $parsed['emails'] ?? null,
            'registrar' => $parsed['registrar'] ?? 'unknown',
            'refer' => $parsed['refer'] ?? 'unknown',
            'nameservers' => $parsed['nameservers'] ?? [],
            'trust_score' => $this->calculateTrust($parsed),
            'registration_date' => trim($created),
            'trust_age_years' => $this->calculateAge($created),
            'remarks' => $parsed['remarks'] ?? [],
            'raw' => (SafeInput::get('full') == 'true') ? $rawData : "Full data hidden. Pass 'full:true' to see all."
        ];

        // Store for 24 hours
        SafeCache::set("whois_$domainCached", $data, '+24 hours');

        return SafeJSON::success($data);

    }

    private function parseWhois(string $raw): array {
        $data = [];
        $lines = explode("\n", $raw);

        // Map of variations found in different WHOIS servers
        $map = [
            'created' => ['Creation Date', 'created', 'Registered on', 'Creation-Date'],
            'expiry'  => ['Registry Expiry Date', 'expiry', 'Expiry date', 'Expiration Date', 'Expires on', 'Record expires', 'Expiration date', 'Registrar Registration Expiration Date'],
            'updated' => ['Updated Date', 'last-updated', 'Updated', 'Changed', 'changed'],
            'registrar' => ['Registrar', 'registrar'],
            'status'  => ['Domain Status', 'status', 'Status'],
            'remarks'  => ['remarks', 'Remarks'],
            'domain'  => ['domain', 'Domain'],
            'refer'  => ['refer', 'Refer'],
            'organisation'  => ['organisation', 'Organisation'],
            'phone' => ['phone', 'Phone', 'telephone', 'Telephone'],
            'email' => ['e-mail', 'email', 'email', 'Email'],
            'whois' => ['whois'],
        ];

        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line) || strpos($line, '%') === 0 || strpos($line, '#') === 0) continue;

            if (strpos($line, ':') !== false) {
                list($key, $value) = explode(':', $line, 2);
                $key = trim($key);
                $value = trim($value);

                // Map specific keys to our normalized array
                foreach ($map as $normalizedKey => $variations) {
                    if (in_array($key, $variations)) {
                        $data[$normalizedKey] = $value;
                    }
                }

                // Special handling for Nameservers (multi-line)
                if (stripos($key, 'Name Server') !== false || stripos($key, 'nserver') !== false) {
                    $data['nameservers'][] = strtolower($value);
                }

                // Special handling for Address (multi-line)
                if (stripos($key, 'Address') !== false || stripos($key, 'address') !== false) {
                    $data['addresses'][] = $value;
                }

                // Special handling for Contact (multi-line)
                if (stripos($key, 'Contact') !== false || stripos($key, 'contact') !== false) {
                    $data['contacts'][] = $value;
                }

                // Special handling for Contact Names (multi-line)
                if (stripos($key, 'name') !== false || stripos($key, 'Name') !== false) {
                    $data['contact_names'][] = $value;
                }

                // Special handling for Organisations (multi-line)
                if (stripos($key, 'organisation') !== false || stripos($key, 'Organisation') !== false) {
                    $data['organisations'][] = $value;
                }

                // Special handling for Emails (multi-line)
                if (stripos($key, 'e-mail') !== false || stripos($key, 'E-Mail') !== false) {
                    $data['emails'][] = $value;
                }

                // Special handling for Phones (multi-line)
                if (stripos($key, 'phone') !== false || stripos($key, 'Phone') !== false) {
                    $data['phones'][] = $value;
                }

            }
        }

        return $data;
    }

    private function calculateTrust(array $parsed): int {
        if (!isset($parsed['created'])) return 0;
        $age = (time() - strtotime($parsed['created'])) / (365 * 24 * 60 * 60);
        return ($age > 2) ? 100 : 50; // Simple RAD logic
    }

    private function queryWhois($server, $domain) 
    {
        $fp = @fsockopen($server, 43, $errno, $errstr, 10);
        if (!$fp) return "Connection failed.";
        
        fputs($fp, $domain . "\r\n");
        $out = "";
        while (!feof($fp)) { $out .= fgets($fp, 128); }
        fclose($fp);
        return $out;
    }

    private function calculateAge($date) 
    {
        if ($date === 'Unknown') return 0;
        $years = (time() - strtotime($date)) / (365 * 24 * 60 * 60);
        return round($years, 1);
    }
}