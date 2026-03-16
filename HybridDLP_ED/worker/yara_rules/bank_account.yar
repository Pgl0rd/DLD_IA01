rule Bank_Account {
    meta:
        description = "Detect bank account numbers (Vietnam) with improved validation"
        severity = "high"
        author = "HybridDLP"
        confidence = "high"
    
    strings:
        // Vietnam bank account: 9-14 digits (improved pattern)
        // Exclude phone numbers and years
        $bank_account_9 = /\b[0-9]{9}\b/  // 9 digits (not phone)
        $bank_account_10 = /\b[0-9]{10}\b/  // 10 digits (not phone)
        $bank_account_11 = /\b[0-9]{11}\b/  // 11 digits
        $bank_account_12 = /\b[0-9]{12}\b/  // 12 digits (not CCCD)
        $bank_account_13 = /\b[0-9]{13}\b/  // 13 digits
        $bank_account_14 = /\b[0-9]{14}\b/  // 14 digits
        
        // Bank keywords (required for validation) - Vietnamese
        $keyword1 = "tài khoản" nocase
        $keyword2 = "số tài khoản" nocase
        $keyword3 = "STK" nocase
        $keyword4 = "số TK" nocase
        $keyword5 = "TK" nocase
        $keyword6 = "số tài khoản ngân hàng" nocase
        $keyword7 = "tài khoản ngân hàng" nocase
        
        // Keywords (English)
        $keyword8 = "bank account" nocase
        $keyword9 = "account number" nocase
        $keyword10 = "account" nocase
        $keyword11 = "banking" nocase
        $keyword12 = "account no" nocase
        $keyword13 = "account #" nocase
        
        // Bank names (Vietnam) - increases confidence
        $bank1 = "Vietcombank" nocase
        $bank2 = "Vietinbank" nocase
        $bank3 = "BIDV" nocase
        $bank4 = "Agribank" nocase
        $bank5 = "Techcombank" nocase
        $bank6 = "ACB" nocase
        $bank7 = "VPBank" nocase
        $bank8 = "MBBank" nocase
        $bank9 = "TPBank" nocase
        $bank10 = "Sacombank" nocase
        $bank11 = "VietABank" nocase
        $bank12 = "SHB" nocase
        $bank13 = "Eximbank" nocase
        $bank14 = "HDBank" nocase
        $bank15 = "MSB" nocase
    
    condition:
        // Match bank account number AND (keywords OR bank name)
        // Exclude phone numbers (09x, 08x, 07x, 03x)
        // Note: 12 digits could be CCCD, but if with bank keywords, it's likely bank account
        (($bank_account_9 and not /\b(09|08|07|03)[0-9]{7}\b/) or
         ($bank_account_10 and not /\b(09|08|07|03)[0-9]{8}\b/) or
         $bank_account_11 or
         $bank_account_12 or  // 12 digits - could be CCCD or bank account, rely on keywords
         $bank_account_13 or
         $bank_account_14) and
        (($keyword1 or $keyword2 or $keyword3 or $keyword4 or $keyword5 or 
          $keyword6 or $keyword7 or $keyword8 or $keyword9 or $keyword10 or
          $keyword11 or $keyword12 or $keyword13) or
         ($bank1 or $bank2 or $bank3 or $bank4 or $bank5 or $bank6 or 
          $bank7 or $bank8 or $bank9 or $bank10 or $bank11 or $bank12 or 
          $bank13 or $bank14 or $bank15))
}
