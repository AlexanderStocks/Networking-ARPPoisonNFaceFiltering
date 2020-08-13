import re
import zlib
import cv2

from scapy.all import *

# replace these with the location of your pictures and faces
from scapy.layers.inet import TCP

picturesDir = "/home/alex/FaceScanner/pictures"
facesDir = "/home/alex/FaceScanner/faces"
pcap_file = "packet.pcap"


# takes raw HTTP traffic, splits headers
def httpHeaders(httpItem):
    try:
        rawHeaders = httpItem[:httpItem.index("\r\n\r\n") + 2]

        headers = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", rawHeaders))
    except TypeError:
        return None
    if "Content-Type" not in headers:
        return None
    return headers


# take http headers, if image mime type in headers, split out type of image, if compressio then decompress
def imageExtract(headers, httpItem):
    newImage = None
    newImage_type = None

    try:
        if "image" in headers['Content-Type']:

            newImage_type = headers['Content-Type'].split("/")[1]

            newImage = httpItem[httpItem.index("\r\n\r\n") + 4]

            # if compression, decompress
            try:
                if "Content-Encoding" in headers.keys():
                    if headers['Content-Encoding'] == "gzip":
                        newImage = zlib.decompress(newImage, 16 + zlib.MAX_WBITS)
                    elif headers['Content-Encoding'] == "deflate":
                        newImage = zlib.decompress(newImage)
            except:
                pass
    except:
        return None, None
    return newImage, newImage_type


def detectFaces(path, file_name):
    # reads image
    img = cv2.imread(path)
    # applies pre-trained classifier
    cascade = cv2.CascadeClassifier("haarcascade_frontalface.xml")
    # returns rectangle coordinates for face in image
    rects = cascade.detectMultiScale(img, 1.3, 4, cv2.CASCADE_SCALE_IMAGE, (20, 20))

    if len(rects) == 0:
        return False

    rects[:, 2:] += rects[:, :2]
    # draw triangle over area
    for x1, y1, x2, y2 in rects:
        cv2.rectangle(img, (x1, y1), (x2, y2), (127, 255, 0), 2)
    # write image 
    cv2.imwrite("%s/%s-%s" % (facesDir, pcap_file, file_name), img)

    return True


def assmbleHttp(pcap_file):
    foundImages = 0
    detectedFaces = 0

    # open the pcap file for processing
    openPcap = rdpcap(pcap_file)

    # separate each tcp session into a dictionary
    sessionDict = openPcap.sessions()

    for session in sessionDict:
        httpItem = ""

        for packet in sessionDict[session]:

            try:
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    # concat only http traffic into single buffer
                    httpItem += str(packet[TCP].payload)

            except TypeError:
                pass
        headers = httpHeaders(httpItem)

        if headers is None:
            continue

        image, image_type = imageExtract(headers, httpItem)

        if image is not None and image_type is not None:

            file_name = "%s-FaceScanner_%d.%s" % (packet, foundImages, image_type)

            fd = open("%s/%s" % (picturesDir, file_name), "wb")
            fd.write(image)
            fd.close()

            foundImages += 1

            try:
                result = detectFaces("%s/%s" % (picturesDir, file_name), file_name)

                if result is True:
                    detectedFaces += 1
            except cv2.error:
                pass
    return foundImages, detectedFaces


foundImages, detectedFaces = assmbleHttp(pcap_file)

print("Extracted: %d images" % foundImages)
print("Detected: %d faces" % detectedFaces)
