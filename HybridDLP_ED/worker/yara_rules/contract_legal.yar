rule Contract_Legal_Document {
    meta:
        description = "Detect contracts and legal documents"
        severity = "high"
        author = "HybridDLP"
    
    strings:
        // Contract keywords (Vietnamese)
        $keyword1 = "hợp đồng" nocase
        $keyword2 = "thỏa thuận" nocase
        $keyword3 = "điều khoản" nocase
        $keyword4 = "phụ lục" nocase
        $keyword5 = "bảo mật" nocase
        $keyword6 = "pháp lý" nocase
        $keyword7 = "luật" nocase
        $keyword8 = "thỏa thuận bảo mật" nocase
        $keyword9 = "cam kết" nocase
        
        // Keywords (English)
        $keyword10 = "contract" nocase
        $keyword11 = "agreement" nocase
        $keyword12 = "terms" nocase
        $keyword13 = "annex" nocase
        $keyword14 = "NDA" nocase
        $keyword15 = "non-disclosure" nocase
        $keyword16 = "confidential" nocase
        $keyword17 = "legal" nocase
        $keyword18 = "law" nocase
        $keyword19 = "confidentiality" nocase
        $keyword20 = "non-disclosure agreement" nocase
        
        // Legal document patterns
        $date_pattern = /\d{1,2}\/\d{1,2}\/\d{4}/  // Date format
        $signature = /ký|signature|chữ ký/i
    
    condition:
        // Match if contract/legal keywords found
        ($keyword1 or $keyword2 or $keyword3 or $keyword4 or $keyword5 or 
         $keyword6 or $keyword7 or $keyword8 or $keyword9 or $keyword10 or
         $keyword11 or $keyword12 or $keyword13 or $keyword14 or $keyword15 or $keyword16 or
         $keyword17 or $keyword18 or $keyword19 or $keyword20) and
        ($date_pattern or $signature)
}
