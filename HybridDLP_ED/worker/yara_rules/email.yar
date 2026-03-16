rule Email_Pattern {
    meta:
        description = "Detect email addresses in bulk"
        severity = "medium"
        author = "HybridDLP"
    
    strings:
        // Email pattern
        $email = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/
        
        // Keywords indicating email list (English)
        $keyword1 = "email" nocase
        $keyword2 = "contact" nocase
        $keyword3 = "mailing list" nocase
        $keyword4 = "email list" nocase
        $keyword5 = "contact list" nocase
        $keyword6 = "address book" nocase
        
        // Keywords (Vietnamese)
        $keyword7 = "email" nocase
        $keyword8 = "danh sách email" nocase
        $keyword9 = "danh bạ" nocase
        $keyword10 = "liên hệ" nocase
        $keyword11 = "địa chỉ email" nocase
        $keyword12 = "thư điện tử" nocase
    
    condition:
        // Match if multiple emails found (potential email list)
        #email > 5 and 
        ($keyword1 or $keyword2 or $keyword3 or $keyword4 or $keyword5 or $keyword6 or
         $keyword7 or $keyword8 or $keyword9 or $keyword10 or $keyword11 or $keyword12)
}
