from data.events_model import events_model
from data.events_model.datatypes import Event, EventType


def test_subscribe():
    events_model.configure()

    calls = []

    def callback(event):
        assert event is not None

        calls.append(event)

    cancel = events_model.subscribe(callback)
    events_model.publish(Event(EventType.create_tag, {"tag_name": "v1.0.0"}))
    events_model.publish(Event(EventType.move_tag, {"tag_name": "v1.0.0"}))
    events_model.publish(Event(EventType.delete_tag, {"tag_name": "v1.0.0"}))

    assert len(calls) == 3

    cancel()

    events_model.publish(Event(EventType.create_tag, {"tag_name": "v1.0.1"}))

    assert len(calls) == 3


def test_subscribe_generator():
    events_model.configure()

    last_event = None
    cancelled = False

    def callback(event):
      assert event is not None

      last_event = event

    cancel = events_model.subscribe(callback)

    def generator():
        while not cancelled:
            if last_event is not None:
                yield last_event

                last_event = None

    for event in generator():
        assert event is not None

    cancel()
    cancelled = True
