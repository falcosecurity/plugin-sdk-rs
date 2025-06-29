# Falco events

This crate provides support for working with Falco events.

The events may come in multiple forms:

- a raw byte buffer, as received from the plugin API or an external source, using a data
  format compatible with the Falco libs ringbuffer scheme
- a [raw event](events::RawEvent), which contains some metadata about the event, but all
  parameters are available only as a series of byte buffers
- a [parsed event](events::Event), which deserializes the raw fields into a Rust data type
  (either [an event-specific type](events::types), or a [generic enum](events::types::AnyEvent)
  encompassing all known event types)

## Autogenerated event types

## Field types

Since the parsed events are strongly typed, we need type definitions for every field that exists
in the event schema. These types are available in [`fields::types`] under names used by the C API.

See [`fields::types`] for information about the specific types available.

### Autogenerated enums and bitflags

Some fields in the event types are defined as `PT_FLAGS` or `PT_ENUMFLAGS`. These are available
in the Rust SDK as enums (`PT_ENUMFLAGS`) or as structs generated by the [`bitflags`](https://docs.rs/bitflags)
crate (`PT_FLAGS`).

All these types live in the [`fields::event_flags`] module.

### Autogenerated dynamic value types

Some event fields take different types, based on e.g. syscall parameters. These are encoded as
the `PT_DYN` type in the Falco event table and are available as Rust enums in [`fields::dynamic_params`].

## Up and down the ladder of abstraction

### Byte slice to raw event

To read an event from a `&[u8]` to a [`events::RawEvent`], use [`events::RawEvent::from`].
It does some basic sanity checking on the slice, but does *not* validate e.g. that all event
parameters are present and the event is not truncated.

There also exists [`events::RawEvent::from_ptr`], which is useful if all you have is a raw pointer,
but it's unsafe for two reasons:

- it dereferences a raw pointer, which is unsafe enough
- it determines the length of the memory to access based on the event header

This method creates a slice from the pointer (based on the discovered length) and passes it
to [`events::RawEvent::from`].

### Raw event to typed event

There are two methods you can use to further refine the event type, depending on your use case.

If you are expecting an event of a particular type (or a handful of types), you can match
on [`events::RawEvent::event_type`] and call [`events::RawEvent::load`] with the appropriate
generic type, for example:

```
# use falco_event::events::RawEvent;
# let event = RawEvent {
#    metadata: Default::default(),
#    len: 0,
#    event_type: 0,
#    nparams: 0,
#    payload: &[],
# };
use falco_event::events::types::EventType;
use falco_event::events::types;
use falco_event::num_traits::FromPrimitive;

match EventType::from_u16(event.event_type) {
    Some(EventType::SYSCALL_OPENAT2_E) => {
        let openat2_e_event = event.load::<types::PPME_SYSCALL_OPENAT2_E>()?;
        // openat2_e_event is Event<types::PPME_SYSCALL_OPENAT2_E>
        // ...
    }
    Some(EventType::SYSCALL_OPENAT2_X) => {
        let openat2_x_event = event.load::<types::PPME_SYSCALL_OPENAT2_X>()?;
        // openat2_x_event is Event<types::PPME_SYSCALL_OPENAT2_X>
        // ...
    }
    _ => (),
}

# Result::<(), anyhow::Error>::Ok(())
```

**Note**: [events::RawEvent::load] validates the event type internally too, so you can also use
an if-let chain:

```
# use falco_event::events::RawEvent;
# let event = RawEvent {
#    metadata: Default::default(),
#    len: 0,
#    event_type: 0,
#    nparams: 0,
#    payload: &[],
# };
use falco_event::events::types::EventType;
use falco_event::events::types;

if let Ok(openat2_e_event) = event.load::<types::PPME_SYSCALL_OPENAT2_E>() {
    // openat2_e_event is Event<types::PPME_SYSCALL_OPENAT2_E>
    // ...
} else if let Ok(openat2_x_event) = event.load::<types::PPME_SYSCALL_OPENAT2_X>() {
    // openat2_x_event is Event<types::PPME_SYSCALL_OPENAT2_X>
    // ...
}
```

On the other hand, if you do not expect any particular event type, but still want to have it
as a strongly typed struct, you can use [events::RawEvent::load_any], which returns
an `Event<AnyEvent>`, where [events::types::AnyEvent] is a large enum, encompassing all known event
types.

Please note that the available methods in this case are very limited. Realistically, you can
only expect a [std::fmt::Debug] implementation, though this may change over time. You can
still match each variant and access its fields, but note that explicit matching might be preferred:
you do not pay the cost of building the type-safe representation of events you're not interested in.

### Event (raw or typed) to byte buffer

There is a trait ([events::EventToBytes]) that writes a serialized form of an event to a writer
(i.e., a type that implements [std::io::Write], for example `Vec<u8>`).
