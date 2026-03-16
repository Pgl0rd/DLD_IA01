rule Vietnam_ID_Single {
    meta:
        description = "Detect single Vietnam ID card numbers (CMND/CCCD) without requiring keywords"
        severity = "high"
        author = "HybridDLP"
        confidence = "medium"  // Medium vì có thể false positive với số khác
    
    strings:
        // CMND: exactly 9 digits (standalone)
        $cmnd = /\b[0-9]{9}\b/
        
        // CCCD: exactly 12 digits (standalone)
        $cccd = /\b[0-9]{12}\b/
        
        // Context keywords (optional, increases confidence) - Vietnamese
        $keyword1 = "CMND" nocase
        $keyword2 = "CCCD" nocase
        $keyword3 = "Chứng minh nhân dân" nocase
        $keyword4 = "Căn cước công dân" nocase
        $keyword5 = "Căn cước" nocase
        $keyword6 = "Số CMND" nocase
        $keyword7 = "Số CCCD" nocase
        $keyword8 = "Mã số" nocase
        $keyword9 = "Số định danh" nocase
        $keyword10 = "định danh" nocase
        $keyword11 = "chứng minh" nocase
        
        // Keywords (English)
        $keyword12 = "ID number" nocase
        $keyword13 = "ID card" nocase
        $keyword14 = "identity card" nocase
        $keyword15 = "citizen ID" nocase
        $keyword16 = "national ID" nocase
        $keyword17 = "identification" nocase
    
    condition:
        // Match CMND or CCCD
        // High confidence if with keywords, medium if standalone
        ($cmnd or $cccd) and
        // Exclude common false positives (phone numbers, years)
        not (/\b(09|08|07|03)[0-9]{8}\b/ and $cmnd) and  // Not phone number
        not (/\b(19|20)[0-9]{2}\b/ and $cmnd)  // Not year
}
