# Whisper
File encryption using chaotic unimodal 1D maps of the form <img src="https://render.githubusercontent.com/render/math?math=x' = rx^p(1-x)^q">

**Features**  
* Variable password size: 14 to 64 characters (longer passwords result in higher security)  
* At least <img src="https://render.githubusercontent.com/render/math?math=10^{27}"> non-degenerate combinations for a 14 character password, x 94 combinations for each extra character
* Works with all kinds of files.
* Straightforward algorithm without any complicated bitwise/math operations 

Download the .cpp file and compile  
```
> g++ Whisper.cpp -o Whisper
```
Type  
```
> Whisper h
```
for usage instructions.  

Currently the code is written with Windows OS in mind. It may not compile on other platforms. You may need to comment out a few lines highlighted in the code.  

Please refer to "Whisper_doc.md" for details regarding the algorithm itself.

This code hasn't been tested extensively. Though I haven't found any issues so far, I give no guarantees regarding its reliability in terms of security and reversibility. Use it at your own risk.  
If you find a way to break the encryption, do let me know!

Update 20-07-2021:  
After some more testing, I have found that this program is not secure against a known-cleartext-attack. If you know about 50 characters (or fewer if you are good) from the original file, you can estimate the key by solving a bunch of coupled transcedental equations. Of course, if you are just trying to hide data from snoopy family members, and if none of them happen to be math graduates, this code will do the job for you.
