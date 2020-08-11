import re
import zlib
import cv2

from scapy.all import *

# replace these with the location of your pictures and faces
pictures_directory = "/home/alex/FaceScanner/pictures"
faces_directory = "/home/alex/FaceScanner/faces"
pcap_file = "packet.pcap"