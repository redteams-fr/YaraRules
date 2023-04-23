rule Base64Usage
{
    meta:
        description = "Uses Base64 encoder/decoder"

    strings:
        $base64_pattern = /Landroid\/util\/Base64;->/

    condition:
        $base64_pattern
}
