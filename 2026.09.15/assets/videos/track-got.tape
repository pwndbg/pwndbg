# https://github.com/charmbracelet/vhs

# Output pwndbg.gif
Output pwndbg.mp4
Output pwndbg.webm

Set FontSize 20
Set Width 1920
Set Height 1080
Set TypingSpeed 100ms

Sleep 1s
Type "pwndbg storage"
Enter
Sleep 2s
Type "start"
Enter
Sleep 3s
Type "track-got enable"
Sleep 3s
Enter 1
Sleep 7s
Type "continue"
Sleep 3s
Enter 1
Sleep 10s
Type "1"
Sleep 1
Enter 1
Sleep 2
Ctrl+C
Sleep 7s
Type "track-got info"
Sleep 3s
Enter 1
Sleep 7s
Type "exit"
Sleep 2s
Enter 1
