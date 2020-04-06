import logging
import uuid

from data.events_model.interface import EventsInterface, SubscriptionInterface
from data.events_model.datatypes import Event, EventType


logger = logging.getLogger(__name__)


class Subscription(SubscriptionInterface):
    """
    Default events subscription implementation.
    """

    def __init__(self, next_func):
        self._cancelled = False      
        self._next_func = next_func  

    def cancel(self):
        self._cancelled = True


class EventsModel(EventsInterface):
    """
    Default events model implementation.
    """

    def __init__(self):
        self.subscribers = {}

    def publish(self, event):
        if event.type not in EventType:
            raise UnsupportedEventException()

        for subscriber in self.subscribers.values():
            subscriber(event)

    def subscribe(self, callback):
        sub_uuid = str(uuid.uuid4())
        # sub = Subscription()

        self.subscribers[sub_uuid] = callback

        def cancel():
            self.subscribers.pop(sub_uuid, None)

        return cancel
            