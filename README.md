# SHA256

This is an SHA256implementation from scratch.

My goal here was to have a SHA256 implementation that was portable and reasonable fast.
 
It is absolutly NOT the fastest you can get, but it should be preatty close to the fastest you can get without using intrinsics.

The test vector come the the NIST`s CAVS 11.0

The speed test is just a random buffer being hashed over and over.
As a comparison, on my M1 Max Mac, I get arround 340 MB/s