# sleepmask utility

this repo shows off a generalized sleepmask class with two seperate implmentations working with the same sleepmask code. 

The first sleepmask is just a generic threadpool timer based sleepmask. The second is meant to exploit a vulnerable RWX section, and write an arg loading callback to it in order to facilitate sleepmasking. Thus, you could use the sleepmask to conceal a large region of shellcode with a very small code cave. Unlike other RWX injection techniques (mockingjay) which rely writing shellcode to a large RWX region.

## detection 

the code is largely "defanged" and does not hide the sleeping thread's callstack, or the "context pointing to VirtualProtect" IoC that patriot scans for (https://github.com/joe-desimone/patriot). Also the RWX PoC does not load a signed dll and instead just simulates a code cave with VirtualProtect. So neither of these will work very well copy-pasted "as is".
