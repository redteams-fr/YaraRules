rule Detect_JokerBr :tag1 tag2
{
    meta:
        description = "Rule to detect JokerBr"
        author = "redteams.fr"
        date = "2023-04-16"

    strings:
        $jokerbr = "JokerBr"

    condition:
        $jokerbr
}
