# https://github.com/charmbracelet/vhs

# Output pwndbg.gif
Output pwndbg.mp4
Output pwndbg.webm

Set FontSize 24
Set Width 1920
Set Height 1080
Set TypingSpeed 100ms

Sleep 1s
Type "pwndbg --args curl -L https://demo.cyotek.com/features/redirectlooptest.php"
Enter
Sleep 2s
Type "start"
Enter
Sleep 3s
Type "track-heap enable"
Sleep 3s
Enter 1
Sleep 3s
Type "continue"
Sleep 3s
Enter 1
Sleep 10s
Ctrl+C
Sleep 7s
Type "exit"
