# ESteg
A simple steganography program to embed the contents of a text file into a PNG
image file. Support for JPEGs and audio files to be added soon.

## Install Dependencies and Run
Run the following command to install dependencies:
```
$ pip install -r requirements.txt
```
Then run this to run the program:
```
$ ./esteg.py
```
Example:
```
$ ./esteg.py --embed message.txt img.png    # embed the contents of message.txt in img.png
$ ./esteg.py img.png_esteg.png              # extract message from img.png_esteg.png
```

## TODO
- [X] Encrypt message before embedding.
- [ ] Support JPEG images by storing messages in DCT coefficients.
- [ ] Support WAV files.
