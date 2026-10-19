"""Versioned nominal print geometry; physical scale/lens accuracy is not certified."""
from functools import lru_cache
from io import BytesIO

import cv2
import numpy as np
from PIL import Image

MAT_VERSION='desktop-v1'
MARKER_IDS=(0,1,2,3)
MARKER_TOP_LEFTS=((28,28),(708,28),(708,408),(28,408))


def plane_corners():
    return tuple(tuple((float(x+dx-100),float(y+dy-100)) for dx,dy in ((0,0),(63,0),(63,63),(0,63)))
        for x,y in MARKER_TOP_LEFTS)


@lru_cache(maxsize=1)
def printable_mat():
    image=np.full((500,800,3),255,np.uint8)
    dictionary=cv2.aruco.getPredefinedDictionary(cv2.aruco.DICT_4X4_50)
    for ident,(x,y) in zip(MARKER_IDS,MARKER_TOP_LEFTS,strict=True):
        marker=cv2.aruco.generateImageMarker(dictionary,ident,64)
        image[y:y+64,x:x+64]=cv2.cvtColor(marker,cv2.COLOR_GRAY2BGR)
    cv2.rectangle(image,(100,100),(699,399),(160,160,160),1)
    cv2.line(image,(250,480),(550,480),(0,0,0),1)
    for x in range(250,551,30):cv2.line(image,(x,476),(x,484),(0,0,0),1)
    cv2.putText(image,'100 mm | PRINT ACTUAL SIZE - VERIFY WITH RULER',(214,496),cv2.FONT_HERSHEY_SIMPLEX,.31,(0,0,0),1)
    enlarged=np.repeat(np.repeat(image,4,axis=0),4,axis=1)
    output=BytesIO();Image.fromarray(cv2.cvtColor(enlarged,cv2.COLOR_BGR2RGB)).save(output,format='PNG',dpi=(304.8,304.8))
    return output.getvalue()
