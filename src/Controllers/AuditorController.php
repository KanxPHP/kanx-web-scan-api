<?php

namespace KanxPHP\Controllers;

use KanxPHP\Core\SafeCurl;
use KanxPHP\Core\SafeJSON;
use KanxPHP\Core\SafeInput;

class AuditorController 
{

    public function handle($input)    
    {
        $url = $input['url'] ?? null;

        // 1. Securely fetch headers using SafeCurl (prevents SSRF)
        
        // --- PERFORMANCE TRACKING START ---
        $startTime = microtime(true);
        $response = SafeCurl::getHeaders($url);
        $endTime = microtime(true);
        $latencyMs = round(($endTime - $startTime) * 1000); 
        // ----------------------------------
        
        if (!$response) {
            return SafeJSON::error("Target unreachable or blocked by security policy.");
        }

        // 2. The Logic (Stateless security)
        $security = [
            'hsts' => isset($response['Strict-Transport-Security']),
            'csp'  => isset($response['Content-Security-Policy']),
            'x_frame' => isset($response['X-Frame-Options']),
            'x_content_type' => isset($headers['X-Content-Type-Options']),
            'server' => $response['Server'] ?? 'Hidden',
            'timestamp' => time()
        ];

        $perfGrade = $this->calculatePerformanceGrade($latencyMs);

        // 3. Calculate the Grade
        $score = count(array_filter($security));
        $total = count($security);
        
        $gradeMap = [
            4 => ['grade' => 'A', 'label' => 'Secure', 'color' => '#2ecc71'],
            3 => ['grade' => 'B', 'label' => 'Good', 'color' => '#f1c40f'],
            2 => ['grade' => 'C', 'label' => 'Warning', 'color' => '#e67e22'],
            1 => ['grade' => 'D', 'label' => 'Poor', 'color' => '#d35400'],
            0 => ['grade' => 'F', 'label' => 'Insecure', 'color' => '#e74c3c'],
        ];

        $assessment = $gradeMap[$score] ?? $gradeMap[0];

        // 4. Return formatted response
         // 3. Return the enhanced report
        return SafeJSON::success([
            'url' => $url,
            'summary' => [
                'score' => "{$score}/{$total}",
                'grade' => $assessment['grade'],
                'status' => $assessment['label'],
                'color_code' => $assessment['color']
            ],
            'performance_audit' => [
                'latency' => $latencyMs . "ms",
                'grade' => $perfGrade['grade'],
                'label' => $perfGrade['label'],
                'color' => $perfGrade['color']
            ],
            'details' => $security,
            'recommendations' => $this->getRecommendations($security)
        ]);
    }

     private function getRecommendations($security) {
        $tips = [];
        if (!$security['hsts']) $tips[] = "Enable HSTS to force HTTPS connections.";
        if (!$security['csp'])  $tips[] = "Implement a Content Security Policy to prevent XSS.";
        if (!$security['x_frame']) $tips[] = "Add X-Frame-Options to stop Clickjacking attacks.";
        return $tips;
    }

    private function calculatePerformanceGrade(int $ms): array {
        if ($ms <= 200)  return ['grade' => 'A+', 'label' => 'Elite', 'color' => '#2ecc71'];
        if ($ms <= 500)  return ['grade' => 'A',  'label' => 'Fast',  'color' => '#27ae60'];
        if ($ms <= 1000) return ['grade' => 'B',  'label' => 'Average', 'color' => '#f1c40f'];
        if ($ms <= 2000) return ['grade' => 'C',  'label' => 'Slow', 'color' => '#e67e22'];
        return ['grade' => 'F', 'label' => 'Poor', 'color' => '#e74c3c'];
    }
}