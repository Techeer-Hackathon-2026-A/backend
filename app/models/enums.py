from enum import Enum


class ScanStatus(str, Enum):
    PENDING = "pending"
    CLONING = "cloning"
    DETECTING = "detecting"
    CLASSIFYING = "classifying"
    FIXING = "fixing"
    COMPLETED = "completed"
    FAILED = "failed"


class FindingStatus(str, Enum):
    OPEN = "open"
    FIXED = "fixed"
    IGNORED = "ignored"
    FALSE_POSITIVE = "false_positive"
