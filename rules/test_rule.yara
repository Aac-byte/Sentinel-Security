rule TestMalware
{
    strings:
        $a = "malware"
        $b = "virus"
        $c = "trojan"

    condition:
        any of them
}
