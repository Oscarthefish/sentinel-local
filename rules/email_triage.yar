rule phishing_html_form
{
    meta:
        description = "HTML attachment containing a credential-style form"
        author = "Sentinel Local"
    strings:
        $form = /<form[^>]+/ nocase
        $pwd = /type\s*=\s*["']password["']/ nocase
        $login = /login|sign in|verify account|mfa/i
    condition:
        $form and 1 of ($pwd, $login)
}

rule html_script_dropper
{
    meta:
        description = "HTML or script attachment with active script content"
        author = "Sentinel Local"
    strings:
        $script = /<script[^>]*>/ nocase
        $jsuri = "javascript:"
        $wscript = "WScript.Shell"
        $powershell = "powershell"
    condition:
        1 of ($script, $jsuri, $wscript, $powershell)
}

rule invoice_lure_attachment
{
    meta:
        description = "Common invoice-payment lure terms in suspicious attachments"
        author = "Sentinel Local"
    strings:
        $invoice = /invoice|remittance|payment advice|purchase order|wire transfer/i
        $urgency = /urgent|immediately|today|overdue/i
        $bank = /bank details|account update|payment release/i
    condition:
        $invoice and 1 of ($urgency, $bank)
}

rule fake_mfa_or_security_notice
{
    meta:
        description = "Security warning lure often used in credential harvesting HTML"
        author = "Sentinel Local"
    strings:
        $mfa = /mfa|multi-factor|approve sign-in|push notification/i
        $security = /suspicious login|security alert|password expires|mailbox blocked/i
        $verify = /verify now|review activity|unlock mailbox/i
    condition:
        2 of them
}
