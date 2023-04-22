rule exported_activity
{
    meta:
        description = "Detect exported activities"
        author = "redteams.fr"
        date = "2023-04-16"
    strings:
        $activity = "android:exported=\"true\""
    condition:
        $activity
}