use std::io::Write;

pub trait EventToBytes {
    fn write<W: Write>(&self, writer: W) -> std::io::Result<()>;
}

impl EventToBytes for &[u8] {
    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(self)
    }
}

#[cfg(all(test, feature = "full-schema"))]
mod tests {
    use crate::events::types::{AnyEvent, PPME_SYSCALL_OPEN_X};
    use crate::events::{Event, EventMetadata, EventToBytes, RawEvent};
    use crate::fields::types::{PT_FLAGS32_file_flags, PT_FD, PT_FSPATH};

    #[test]
    fn test_event_to_bytes() {
        let evt = Event {
            metadata: EventMetadata { ts: 1, tid: 1 },
            params: PPME_SYSCALL_OPEN_X {
                fd: Some(PT_FD(5)),
                name: Some(PT_FSPATH::new("/etc/passwd")),
                flags: Some(PT_FLAGS32_file_flags::O_RDWR),
                mode: Some(0o644),
                dev: Some(0),
                ino: Some(0),
            },
        };

        let mut buf = Vec::new();
        evt.write(&mut buf).unwrap();

        let evt2 = RawEvent::from(buf.as_slice()).unwrap();
        let evt2 = evt2.load::<PPME_SYSCALL_OPEN_X>().unwrap();

        assert_eq!(evt2.params.fd, Some(PT_FD(5)));
        assert_eq!(evt2.params.name, Some(PT_FSPATH::new("/etc/passwd")));
        assert_eq!(evt2.params.flags, Some(PT_FLAGS32_file_flags::O_RDWR));
        assert_eq!(evt2.params.mode, Some(0o644));
        assert_eq!(evt2.params.dev, Some(0));
        assert_eq!(evt2.params.ino, Some(0));
    }

    #[test]
    fn test_any_event_to_bytes() {
        let evt = Event {
            metadata: EventMetadata { ts: 1, tid: 1 },
            params: AnyEvent::SYSCALL_OPEN_X(PPME_SYSCALL_OPEN_X {
                fd: Some(PT_FD(5)),
                name: Some(PT_FSPATH::new("/etc/passwd")),
                flags: Some(PT_FLAGS32_file_flags::O_RDWR),
                mode: Some(0o644),
                dev: Some(0),
                ino: Some(0),
            }),
        };

        let mut buf = Vec::new();
        evt.write(&mut buf).unwrap();

        let evt2 = RawEvent::from(buf.as_slice()).unwrap();
        let evt2 = evt2.load::<PPME_SYSCALL_OPEN_X>().unwrap();

        assert_eq!(evt2.params.fd, Some(PT_FD(5)));
        assert_eq!(evt2.params.name, Some(PT_FSPATH::new("/etc/passwd")));
        assert_eq!(evt2.params.flags, Some(PT_FLAGS32_file_flags::O_RDWR));
        assert_eq!(evt2.params.mode, Some(0o644));
        assert_eq!(evt2.params.dev, Some(0));
        assert_eq!(evt2.params.ino, Some(0));
    }
}
