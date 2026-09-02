# HTTP MP4 regression data

`http-mp4-legitimate.pcap` is derived from the public `sample-5s.mp4` file downloaded from [Samplelib's sample MP4 page](https://samplelib.com/sample-mp4.html). Samplelib states that its sample videos are available with no license restrictions.

The source file was used only to build a small deterministic HTTP response capture. The capture preserves a normal ISO-BMFF prefix containing `ftyp`, `free`, and `mdat`, and fragments the HTTP response and MP4 bytes across TCP packets. It is a negative regression case for the fake-MP4 heuristic: the response must not trigger `NDPI_HTTP_SUSPICIOUS_CONTENT` because it contains normal media evidence and no dominant private `uuid` box.

Source URL: `https://samplelib.com/lib/preview/mp4/sample-5s.mp4`
05bd857af7f70bf51b6aac1144046973bf3325c9101a554bc27dc9607dbbd8f5  tests/data/legit-sample.mp4
