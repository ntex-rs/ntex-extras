use crate::MultipartError;
use crate::safety::Safety;
use futures::stream::LocalBoxStream;
use futures::{Stream, StreamExt};
use ntex::http::error::PayloadError;
use ntex::util::{Bytes, BytesMut};
use std::cell::{RefCell, RefMut};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

/// Maximum size of a boundary line or of a part's header block.
pub(crate) const MAX_LINE_SIZE: usize = 16 * 1024;

/// Default maximum number of unprocessed body bytes held by the parser.
pub(crate) const DEFAULT_BUFFER_LIMIT: usize = 64 * 1024;

/// Maximum number of ready stream chunks taken per poll, so a fast stream cannot
/// monopolize the task.
const MAX_READY_CHUNKS: usize = 16;

pub(crate) struct PayloadRef {
    payload: Rc<RefCell<PayloadBuffer>>,
}

impl PayloadRef {
    pub(crate) fn new(payload: PayloadBuffer) -> PayloadRef {
        PayloadRef {
            payload: Rc::new(payload.into()),
        }
    }

    pub(crate) fn get_mut<'a, 'b>(&'a self, s: &'b Safety) -> Option<RefMut<'a, PayloadBuffer>>
    where
        'a: 'b,
    {
        if s.current() {
            Some(self.payload.borrow_mut())
        } else {
            None
        }
    }
}

impl Clone for PayloadRef {
    fn clone(&self) -> PayloadRef {
        PayloadRef {
            payload: Rc::clone(&self.payload),
        }
    }
}

/// Payload buffer
pub(crate) struct PayloadBuffer {
    pub(crate) eof: bool,
    pub(crate) buf: BytesMut,
    pub(crate) stream: LocalBoxStream<'static, Result<Bytes, PayloadError>>,
    /// Stream data received but not yet moved into `buf` because of `limit`.
    pending: Option<Bytes>,
    /// Maximum length of `buf`.
    limit: usize,
}

impl PayloadBuffer {
    /// Create new `PayloadBuffer` instance with the default buffer limit
    pub(crate) fn new<S>(stream: S) -> Self
    where
        S: Stream<Item = Result<Bytes, PayloadError>> + 'static,
    {
        Self::with_limit(stream, DEFAULT_BUFFER_LIMIT)
    }

    /// Create new `PayloadBuffer` instance that buffers at most `limit` bytes
    pub(crate) fn with_limit<S>(stream: S, limit: usize) -> Self
    where
        S: Stream<Item = Result<Bytes, PayloadError>> + 'static,
    {
        PayloadBuffer {
            limit,
            eof: false,
            pending: None,
            buf: BytesMut::new(),
            stream: stream.boxed_local(),
        }
    }

    /// Moves ready stream data into `buf`, keeping it within `limit`.
    ///
    /// Data that does not fit is kept in `pending`. Takes at most
    /// `MAX_READY_CHUNKS` chunks per call. When it stops without waiting on the
    /// stream, it wakes the task so the data is read after the parser consumes `buf`.
    pub(crate) fn poll_stream(&mut self, cx: &mut Context) -> Result<(), PayloadError> {
        for _ in 0..MAX_READY_CHUNKS {
            // with a full buffer, still poll once to observe eof or hold the next chunk
            let mut data = if let Some(data) = self.pending.take() {
                data
            } else {
                match Pin::new(&mut self.stream).poll_next(cx) {
                    Poll::Ready(Some(Ok(data))) => data,
                    Poll::Ready(Some(Err(e))) => return Err(e),
                    Poll::Ready(None) => {
                        self.eof = true;
                        return Ok(());
                    }
                    Poll::Pending => return Ok(()),
                }
            };

            let room = self.limit - self.buf.len();
            if data.len() > room {
                self.buf.extend_from_slice(&data[..room]);
                data.advance_to(room);
                self.pending = Some(data);
                break;
            }
            self.buf.extend_from_slice(&data);
        }

        cx.waker().wake_by_ref();
        Ok(())
    }

    /// Returns `true` if `buf` cannot take more data.
    ///
    /// A parser that needs more data while the buffer is full cannot make progress.
    pub(crate) fn is_full(&self) -> bool {
        self.buf.len() >= self.limit
    }

    pub(crate) fn read_exact(&mut self, size: usize) -> Option<Bytes> {
        if size <= self.buf.len() {
            Some(self.buf.split_to(size))
        } else {
            None
        }
    }

    pub(crate) fn read_max(&mut self, size: u64) -> Result<Option<Bytes>, MultipartError> {
        if !self.buf.is_empty() {
            let size = std::cmp::min(self.buf.len() as u64, size) as usize;
            Ok(Some(self.buf.split_to(size)))
        } else if self.eof {
            Err(MultipartError::Incomplete)
        } else {
            Ok(None)
        }
    }

    /// Read until specified ending
    ///
    /// Fails if the ending, including itself, is not found within `MAX_LINE_SIZE` bytes.
    pub(crate) fn read_until(&mut self, line: &[u8]) -> Result<Option<Bytes>, MultipartError> {
        match memchr::memmem::find(&self.buf, line) {
            Some(idx) if idx + line.len() > MAX_LINE_SIZE => {
                Err(MultipartError::Payload(PayloadError::Overflow))
            }
            Some(idx) => Ok(Some(self.buf.split_to(idx + line.len()))),
            None if self.buf.len() > MAX_LINE_SIZE => {
                Err(MultipartError::Payload(PayloadError::Overflow))
            }
            None if self.eof => Err(MultipartError::Incomplete),
            None => Ok(None),
        }
    }

    /// Read bytes until new line delimiter
    pub(crate) fn readline(&mut self) -> Result<Option<Bytes>, MultipartError> {
        self.read_until(b"\n")
    }

    /// Read bytes until new line delimiter or eof
    pub(crate) fn readline_or_eof(&mut self) -> Result<Option<Bytes>, MultipartError> {
        match self.readline() {
            Err(MultipartError::Incomplete) if self.eof => Ok(Some(self.buf.take())),
            line => line,
        }
    }

    /// Put unprocessed data back to the buffer
    pub(crate) fn unprocessed(&mut self, data: Bytes) {
        let buf = BytesMut::from(data.as_ref());
        let buf = std::mem::replace(&mut self.buf, buf);
        self.buf.extend_from_slice(&buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use futures::future::lazy;
    use ntex::{channel::bstream, util::Bytes};

    // #[ntex::test]
    // async fn test_basic() {
    //     let (_sender, payload) = bstream::channel();
    //     let mut payload = PayloadBuffer::new(payload);

    //     assert_eq!(payload.buf.len(), 0);
    //     assert!(lazy(|cx| payload.poll_stream(cx)).await.is_err());
    //     assert_eq!(None, payload.read_max(1).unwrap());
    // }

    #[ntex::test]
    async fn test_eof() {
        let (sender, payload) = bstream::channel();
        let mut payload = PayloadBuffer::new(payload);

        assert_eq!(None, payload.read_max(4).unwrap());
        sender.feed_data(Bytes::from("data"));
        sender.feed_eof();
        lazy(|cx| payload.poll_stream(cx)).await.unwrap();

        assert_eq!(Some(Bytes::from("data")), payload.read_max(4).unwrap());
        assert_eq!(payload.buf.len(), 0);
        assert!(payload.read_max(1).is_err());
        assert!(payload.eof);
    }

    #[ntex::test]
    async fn test_err() {
        let (sender, payload) = bstream::channel();
        let mut payload = PayloadBuffer::new(payload);
        assert_eq!(None, payload.read_max(1).unwrap());
        sender.set_error(PayloadError::Incomplete(None));
        lazy(|cx| payload.poll_stream(cx)).await.err().unwrap();
    }

    #[ntex::test]
    async fn test_readmax() {
        let (sender, payload) = bstream::channel();
        let mut payload = PayloadBuffer::new(payload);

        sender.feed_data(Bytes::from("line1"));
        sender.feed_data(Bytes::from("line2"));
        lazy(|cx| payload.poll_stream(cx)).await.unwrap();
        assert_eq!(payload.buf.len(), 10);

        assert_eq!(Some(Bytes::from("line1")), payload.read_max(5).unwrap());
        assert_eq!(payload.buf.len(), 5);

        assert_eq!(Some(Bytes::from("line2")), payload.read_max(5).unwrap());
        assert_eq!(payload.buf.len(), 0);
    }

    #[ntex::test]
    async fn test_readexactly() {
        let (sender, payload) = bstream::channel();
        let mut payload = PayloadBuffer::new(payload);

        assert_eq!(None, payload.read_exact(2));

        sender.feed_data(Bytes::from("line1"));
        sender.feed_data(Bytes::from("line2"));
        lazy(|cx| payload.poll_stream(cx)).await.unwrap();

        assert_eq!(Some(Bytes::from_static(b"li")), payload.read_exact(2));
        assert_eq!(payload.buf.len(), 8);

        assert_eq!(Some(Bytes::from_static(b"ne1l")), payload.read_exact(4));
        assert_eq!(payload.buf.len(), 4);
    }

    #[ntex::test]
    async fn test_readuntil() {
        let (sender, payload) = bstream::channel();
        let mut payload = PayloadBuffer::new(payload);

        assert_eq!(None, payload.read_until(b"ne").unwrap());

        sender.feed_data(Bytes::from("line1"));
        sender.feed_data(Bytes::from("line2"));
        lazy(|cx| payload.poll_stream(cx)).await.unwrap();

        assert_eq!(
            Some(Bytes::from("line")),
            payload.read_until(b"ne").unwrap()
        );
        assert_eq!(payload.buf.len(), 6);

        assert_eq!(
            Some(Bytes::from("1line2")),
            payload.read_until(b"2").unwrap()
        );
        assert_eq!(payload.buf.len(), 0);
    }

    /// STATEMENT: Fragmented lines and restored unread bytes retain their order through payload EOF.
    ///
    /// HOW:
    /// - Feed a line split across its CRLF, then close the stream after a trailing fragment.
    /// - Read the line, put a partially read suffix back, and confirm EOF returns the complete suffix without duplication.
    #[ntex::test]
    async fn fragmented_lines_and_unprocessed_bytes_survive_eof() {
        let (sender, stream) = bstream::channel();
        let mut payload = PayloadBuffer::new(stream);
        sender.feed_data(Bytes::from_static(b"head\r"));
        lazy(|cx| payload.poll_stream(cx)).await.unwrap();
        assert!(payload.readline().unwrap().is_none());
        sender.feed_data(Bytes::from_static(b"\ntail"));
        sender.feed_eof();
        lazy(|cx| payload.poll_stream(cx)).await.unwrap();

        assert_eq!(payload.readline().unwrap().unwrap(), "head\r\n");
        let prefix = payload.read_max(2).unwrap().unwrap();
        assert_eq!(prefix, "ta");
        payload.unprocessed(prefix);
        assert_eq!(payload.readline_or_eof().unwrap().unwrap(), "tail");
        assert!(payload.readline_or_eof().unwrap().unwrap().is_empty());
        assert!(matches!(
            payload.read_max(1),
            Err(MultipartError::Incomplete)
        ));
    }

    /// STATEMENT: Shared payload access transfers to the live field token and returns to the parent after that token is dropped.
    ///
    /// HOW:
    /// - Clone the parent's `Safety` for an active field and read a prefix using the field's shared payload reference.
    /// - Confirm the parent cannot borrow while the field is live, then drop the field token and read the remaining bytes through the parent.
    #[ntex::test]
    async fn shared_payload_access_tracks_field_lifetime() {
        let (sender, stream) = bstream::channel();
        let payload = PayloadRef::new(PayloadBuffer::new(stream));
        let parent = Safety::new();
        sender.feed_data(Bytes::from_static(b"firstsecond"));
        sender.feed_eof();
        lazy(|cx| payload.get_mut(&parent).unwrap().poll_stream(cx))
            .await
            .unwrap();

        let field = lazy(|cx| parent.clone(cx)).await;
        let shared = payload.clone();
        assert!(payload.get_mut(&parent).is_none());
        assert_eq!(
            shared
                .get_mut(&field)
                .unwrap()
                .read_max(5)
                .unwrap()
                .unwrap(),
            "first"
        );
        drop(field);
        assert_eq!(
            payload
                .get_mut(&parent)
                .unwrap()
                .read_max(6)
                .unwrap()
                .unwrap(),
            "second"
        );
        assert!(matches!(
            payload.get_mut(&parent).unwrap().read_max(1),
            Err(MultipartError::Incomplete)
        ));
    }

    /// STATEMENT: `poll_stream` never buffers more than the configured limit and keeps the excess.
    ///
    /// HOW:
    /// - Feed 8-byte chunks into a buffer limited to 12 bytes and poll repeatedly.
    /// - Confirm the buffer stops at 12 bytes, a second poll without consuming adds nothing,
    ///   and consumed room is refilled from the held remainder in order.
    #[ntex::test]
    async fn poll_stream_keeps_buffer_within_limit() {
        let (sender, payload) = bstream::channel();
        let mut payload = PayloadBuffer::with_limit(payload, 12);
        sender.feed_data(Bytes::from("12345678"));
        sender.feed_data(Bytes::from("abcdefgh"));

        lazy(|cx| payload.poll_stream(cx)).await.unwrap();
        assert_eq!(payload.buf, "12345678abcd");
        lazy(|cx| payload.poll_stream(cx)).await.unwrap();
        assert_eq!(payload.buf, "12345678abcd");

        assert_eq!(payload.read_exact(10).unwrap(), "12345678ab");
        lazy(|cx| payload.poll_stream(cx)).await.unwrap();
        assert_eq!(payload.buf, "cdefgh");
    }

    /// STATEMENT: `poll_stream` wakes the task when it stops before the stream is pending.
    ///
    /// HOW:
    /// - Poll with a counting waker after feeding more than `MAX_READY_CHUNKS` chunks, then
    ///   with a full buffer, then with an empty stream.
    /// - Confirm the first two polls wake the task and the pending stream does not.
    #[ntex::test]
    async fn poll_stream_wakes_when_data_may_remain() {
        let (sender, payload) = bstream::channel();
        let mut payload = PayloadBuffer::with_limit(payload, 32);
        for _ in 0..MAX_READY_CHUNKS + 4 {
            sender.feed_data(Bytes::from("x"));
        }
        let (waker, count) = futures_test::task::new_count_waker();
        let mut cx = Context::from_waker(&waker);

        payload.poll_stream(&mut cx).unwrap();
        assert_eq!(payload.buf.len(), MAX_READY_CHUNKS);
        assert_eq!(count.get(), 1);

        sender.feed_data(Bytes::from("y".repeat(32)));
        payload.poll_stream(&mut cx).unwrap();
        assert_eq!(payload.buf.len(), 32);
        assert_eq!(count.get(), 2);

        payload.buf.clear();
        payload.poll_stream(&mut cx).unwrap();
        assert_eq!(payload.buf.len(), 20);
        assert_eq!(count.get(), 2);
    }

    /// STATEMENT: `poll_stream` observes end of stream even when the buffer is full.
    ///
    /// HOW:
    /// - Fill a 4-byte buffer exactly, then close the stream.
    /// - Confirm the next poll sets `eof` without consuming the buffered bytes.
    #[ntex::test]
    async fn poll_stream_observes_eof_with_full_buffer() {
        let (sender, payload) = bstream::channel();
        let mut payload = PayloadBuffer::with_limit(payload, 4);
        sender.feed_data(Bytes::from("1234"));
        lazy(|cx| payload.poll_stream(cx)).await.unwrap();
        assert!(payload.is_full() && !payload.eof);

        sender.feed_eof();
        lazy(|cx| payload.poll_stream(cx)).await.unwrap();
        assert!(payload.eof);
        assert_eq!(payload.buf, "1234");
    }
}
