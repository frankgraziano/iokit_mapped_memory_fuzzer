This is some old code that I used when fuzzing IOKit for the first
time.

This is a simple mapped memory fuzzer that attempts to enumerate
through all registered IOKit devices and attempts to open them with all
the various typecodes that may or may not be exposed.

This fuzzer found CVD-2015-1137 which was a Null Pointer Dereference in
the nVidia nvAccelerator driver.

You can read about it here:
https://yahoo-security.tumblr.com/post/115874628495/nvidia-null-pointer-
vulnerability-cve-2015-1137

Hopefully someone can gain some knowledge from this.

—FG