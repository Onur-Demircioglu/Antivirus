rule ExampleMalware {
    meta:
        description = "Basit kötü amaçlı yazılım tespiti"
        author = "Your Name"
        date = "2024-03-21"
    
    strings:
        $suspicious_string1 = "cmd.exe" ascii wide
        $suspicious_string2 = "powershell.exe" ascii wide
        
    condition:
        any of them
}