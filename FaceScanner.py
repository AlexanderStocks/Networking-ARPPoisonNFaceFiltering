import re
import zlib
import cv2

from scapy.all import *

# replace these with the location of your pictures and faces
from scapy.layers.inet import TCP

pictures_directory = "/home/alex/FaceScanner/pictures"
faces_directory = "/home/alex/FaceScanner/faces"
pcap_file = "packet.pcap"

# takes raw HTTP traffic, splits headers
def get_http_headers(http_payload):

    try:
        headers_raw = http_payload[:http_payload.index("\r\n\r\n") + 2]

        headers = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", headers_raw))
    except (TypeError):
        return None
    if "Content-Type" not in headers:
        return None
    return headers
# take http headers, if image mime type in headers, split out type of image, if compressio then decompress
def extract_image(headers, http_payload):
    image = None
    image_type = None

    try:
        if "image" in headers['Content-Type']:

            image_type = headers['Content-Type'].split("/")[1]

            image = http_payload[http_payload.index("\r\n\r\n") + 4]

            #if compression, decompress
            try:
                if"Content-Encoding" in headers.keys():
                    if headers['Content-Encoding'] == "gzip":
                        image = zlib.decompress(image, 16+zlib.MAX_WBITS)
                    elif headers['Content-Encoding'] == "deflate":
                        image = zlib.decompress(image)
            except:
                pass
    except:
        return None, None
    return image, image_type


def http_assembler(pcap_file):
    carved_images = 0
    faces_detected = 0

    # open the pcap file for processing
    a = rdpcap(pcap_file)

    # separate each tcp session into a dictionary
    sessions = a.sessions()

    for session in sessions:
        http_payload = ""

        for packet in sessions[session]:

            try:
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:

                    # concat only http traffic into single buffer
                    http_payload += str(packet[TCP].payload)

            except TypeError:
                pass
        headers = get_http_headers(http_payload)

        if headers is None:
            continue

        image, image_type = extract_image(headers, http_payload)

        if image is not None and image_type is not None:

            file_name = "%s-FaceScanner_%d.%s" % (packet, carved_images, image_type)

            fd = open("%s/%s" % (pictures_directory, file_name), "wb")
            fd.write(image)
            fd.close()

            carved_images += 1

            try:
                result = faces_detect("%s/%s" % (pictures_directory, file_name), file_name)

                if result is True:
                    faces_detected += 1
            except cv2.error:
                pass
    return carved_images, faces_detected

carved_images, faces_detected = http_assembler(pcap_file)

print("Extracted: %d images" % carved_images)
print("Detected: %d faces" % faces_detected)

