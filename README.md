# Whisper
File encryption using chaotic unimodal 1D maps of the form <img src="https://render.githubusercontent.com/render/math?math=x' = rx^p(1-x^q)">

**Features**  
* Variable password size: 14 to 64 characters (longer passwords result in higher security)  
* At least <img src="https://render.githubusercontent.com/render/math?math=10^{27}"> non-degenerate combinations
* Straightforward algorithm without any complicated bitwise/mathematical operations

Essentially the program encrypts a given file byte by byte using a reversible and chaotic transformation.

This code hasn't been tested extensively. I give no guarantees regarding its reliability in terms of security and reversibility. Use it at your own risk.  
If you find a way to break the encryption, do let me know!
