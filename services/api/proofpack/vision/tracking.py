"""Bounded per-station scene tracking; both consecutive and cumulative changes reset stability."""
from dataclasses import dataclass

import cv2
import numpy as np


@dataclass(frozen=True)
class SceneDecision:
    generation: int
    changed: bool
    changed_pixels: int


class SceneTracker:
    def __init__(self, *, pixel_delta: int, max_changed_pixels: int):
        if type(pixel_delta) is not int or not 0<=pixel_delta<=254 or type(max_changed_pixels) is not int or max_changed_pixels<0:
            raise ValueError("explicit bounded scene thresholds required")
        self.pixel_delta=pixel_delta
        self.max_changed_pixels=max_changed_pixels
        self._anchor=None
        self._previous=None
        self._context=None
        self._generation=0
        self._sequence=0

    def invalidate(self) -> SceneDecision:
        self._anchor=self._previous=None
        self._context=None
        self._generation+=1
        return SceneDecision(self._generation,True,0)

    def update(self, frame: np.ndarray, *, sequence: int, context: str) -> SceneDecision:
        if (type(sequence) is not int or sequence<1 or (context==self._context and sequence<=self._sequence)
                or not context or len(context)>256
                or frame.dtype!=np.uint8 or frame.ndim!=3 or frame.shape[2]!=3
                or frame.shape[0]*frame.shape[1]>2000000):
            raise ValueError("invalid sequence, context or frame")
        gray=cv2.cvtColor(frame,cv2.COLOR_BGR2GRAY)
        changed_pixels=0
        changed=(self._anchor is None or self._context!=context or self._anchor.shape!=gray.shape)
        if not changed:
            immediate=int(np.count_nonzero(cv2.absdiff(gray,self._previous)>self.pixel_delta))
            cumulative=int(np.count_nonzero(cv2.absdiff(gray,self._anchor)>self.pixel_delta))
            changed_pixels=max(immediate,cumulative)
            changed=changed_pixels>self.max_changed_pixels
        if changed:
            self._generation+=1
            self._anchor=gray.copy()
            self._context=context
        self._previous=gray.copy()
        self._sequence=sequence
        return SceneDecision(self._generation,changed,changed_pixels)
