rule Financial_Data {
    meta:
        description = "Detect financial data (amounts, balances, transactions)"
        severity = "high"
        author = "HybridDLP"
    
    strings:
        // Large amounts with multiple comma separators (e.g., 1,500,000,000 VND)
        // Pattern: matches numbers with 1-3 digits, followed by one or more groups of comma/dot + 3 digits
        $amount_vnd1 = /\b[0-9]{1,3}([.,][0-9]{3})+\s*VND/i
        $amount_vnd2 = /\b[0-9]{1,3}([.,][0-9]{3})+\s*đồng/i
        $amount_vnd3 = /\b[0-9]{1,3}([.,][0-9]{3})+\s*vnđ/i
        
        // Large amounts without separators (e.g., 1500000000 VND)
        $amount_vnd4 = /\b[0-9]{7,}\s*VND/i
        
        // Medium amounts with single separator (e.g., 1,000,000 VND or 500,000 VND)
        $amount_vnd5 = /\b[0-9]{1,3}[.,][0-9]{3}\s*VND/i
        $amount_vnd6 = /\b[0-9]{1,3}[.,][0-9]{3}\s*đồng/i
        $amount_vnd7 = /\b[0-9]{1,3}[.,][0-9]{3}\s*vnđ/i
        
        // USD amounts
        $amount_usd1 = /\$[0-9]{1,3}([.,][0-9]{3})+/
        $amount_usd2 = /\$[0-9]{7,}/
        $amount_usd3 = /\$[0-9]{1,3}[.,][0-9]{3}/
        
        // Financial keywords (Vietnamese)
        $keyword1 = "doanh thu" nocase
        $keyword2 = "lợi nhuận" nocase
        $keyword3 = "chi phí" nocase
        $keyword4 = "ngân sách" nocase
        $keyword5 = "số dư" nocase
        $keyword6 = "giao dịch" nocase
        $keyword7 = "thanh toán" nocase
        $keyword8 = "hóa đơn" nocase
        $keyword9 = "báo cáo tài chính" nocase
        $keyword10 = "báo cáo" nocase
        $keyword11 = "tài chính" nocase
        $keyword12 = "công ty" nocase
        $keyword13 = "corporation" nocase
        $keyword14 = "company" nocase
        
        // Financial keywords (English)
        $keyword15 = "balance" nocase
        $keyword16 = "revenue" nocase
        $keyword17 = "profit" nocase
        $keyword18 = "budget" nocase
        $keyword19 = "transaction" nocase
        $keyword20 = "payment" nocase
        $keyword21 = "invoice" nocase
        $keyword22 = "financial report" nocase
        $keyword23 = "financial statement" nocase
        $keyword24 = "income" nocase
        $keyword25 = "expense" nocase
        $keyword26 = "expenditure" nocase
        $keyword27 = "cost" nocase
    
    condition:
        // Match if has amount AND keyword (high confidence)
        // OR match if has large amount (>= 7 digits) OR multiple separators
        // OR match if has strong financial keyword (báo cáo tài chính, financial report, etc.)
        (
            (
                ($amount_vnd1 or $amount_vnd2 or $amount_vnd3 or $amount_vnd4 or $amount_vnd5 or $amount_vnd6 or $amount_vnd7 or $amount_usd1 or $amount_usd2 or $amount_usd3) and
                ($keyword1 or $keyword2 or $keyword3 or $keyword4 or $keyword5 or $keyword6 or $keyword7 or $keyword8 or $keyword9 or $keyword10 or $keyword11 or $keyword12 or $keyword13 or $keyword14 or $keyword15 or $keyword16 or $keyword17 or $keyword18 or $keyword19 or $keyword20 or $keyword21 or $keyword22 or $keyword23 or $keyword24 or $keyword25 or $keyword26 or $keyword27)
            ) or
            // Large amounts with multiple separators (high value transactions)
            ($amount_vnd1 or $amount_vnd2 or $amount_vnd3 or $amount_usd1) or
            // Very large amounts without separators
            ($amount_vnd4 or $amount_usd2) or
            // Strong financial report keywords
            ($keyword9 or $keyword22 or $keyword23)
        )
}
