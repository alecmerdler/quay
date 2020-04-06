from enum import IntEnum, unique
from collections import namedtuple


@unique
class EventType(IntEnum):
    """
    Type of event emitted by Quay.
    """

    delete_tag = 0
    move_tag = 1
    create_tag = 2


class Event(namedtuple("Event", ["type", "metadata"])):
    """
    Anything that happens in Quay worthy of recognition.
    """
