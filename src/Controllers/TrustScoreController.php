<?php

namespace KanxPHP\Controllers;

use KanxPHP\Core\SafeJSON;
use KanxPHP\Core\SafeCache;
use KanxPHP\Core\SafeInput;

class TrustScoreController 
{

    public function handle($input) 
    {
        $domain = $input['domain'] ?? null;
        if (!$domain) return SafeJSON::error("Domain required.");

        // 1. Check Cache first (High-speed RAD strategy)
        $cacheKey = "trust_score_" . md5($domain);
        if ($cached = SafeCache::get($cacheKey)) return SafeJSON::success($cached);

        // 2. Orchestrate - Collect data from internal tools
        $whoisData = json_decode((new WhoisController())->handle(['domain' => $domain]), true)['data'] ?? [];
        $sslData   = json_decode((new SslCheckController())->handle(['host' => $domain]), true)['data'] ?? [];
        $auditData = json_decode((new AuditorController())->handle(['url' => "https://$domain"]), true)['data'] ?? [];

        // 3. Scoring Algorithm
        $score = 0;
        $factors = [];

        // Factor: Domain Age (Max 40 points)
        $age = $whoisData['trust_age_years'] ?? 0;
        if ($age >= 5) { $score += 40; $factors[] = "Established domain (5+ years)"; }
        elseif ($age >= 1) { $score += 20; $factors[] = "Mature domain (1+ year)"; }
        else { $factors[] = "New domain (Higher risk)"; }

        // Factor: SSL Security (Max 30 points)
        if ($sslData['is_valid'] ?? false) { 
            $score += 30; 
            $factors[] = "Valid SSL Certificate active";
        }

        // Factor: Header Security (Max 30 points)
        $secureHeaders = array_filter($auditData['details'] ?? []);
        $headerScore = count($secureHeaders) * 7.5; // 4 headers * 7.5 = 30
        $score += $headerScore;
        if ($headerScore >= 20) $factors[] = "Strong security header configuration";

        // 4. Final Assessment
        $result = [
            'domain' => $domain,
            'trust_score' => min(100, $score),
            'rating' => $this->getRating($score),
            'analysis' => $factors,
            'raw_metrics' => [
                'age_years' => $age,
                'ssl_active' => $sslData['is_valid'] ?? false,
                'security_headers' => count($secureHeaders)
            ]
        ];

        // Cache the result for 24 hours to save CPU
        SafeCache::set($cacheKey, $result, '+24 hours');

        return SafeJSON::success($result);
    }

    private function getRating($score) 
    {
        if ($score >= 80) return "Verified & Trusted";
        if ($score >= 50) return "Neutral / Pass";
        return "High Risk / Untrusted";
    }
}
