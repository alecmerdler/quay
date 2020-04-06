import logging
import redis

from data.events_model.interface import EventsInterface
from data.events_model.datatypes import Event, EventType


class RedisEventsModel(EventsInterface):
    """
    Redis-backed events model implementation. 
    """

    def __init__(self):
        # TODO(alecmerdler): Accept Redis connection info

    def publish(self, event):
        raise NotImplementedError

    def subscribe(self, callback):
        raise NotImplementedError
