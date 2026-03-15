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

pub(crate) struct PayloadRef {
    payload: Rc<RefCell<PayloadBuffer>>,
}

impl PayloadRef {
    pub(crate) fn new(payload: PayloadBuffer) -> PayloadRef {
        PayloadRef { payload: Rc::new(payload.into()) }
    }

    pub(crate) fn get_mut<'a, 'b>(&'a self, s: &'b Safety) -> Option<RefMut<'a, PayloadBuffer>>
    where
        'a: 'b,
    {
        if s.current() { Some(self.payload.borrow_mut()) } else { None }
    }
}

impl Clone for PayloadRef {
    fn clone(&self) -> PayloadRef {
        PayloadRef { payload: Rc::clone(&self.payload) }
    }
}

/// Payload buffer
pub(crate) struct PayloadBuffer {
    pub(crate) eof: bool,
    pub(crate) buf: BytesMut,
    pub(crate) stream: LocalBoxStream<'static, Result<Bytes, PayloadError>>,
}

impl PayloadBuffer {
    /// Create new `PayloadBuffer` instance
    pub(crate) fn new<S>(stream: S) -> Self
    where
        S: Stream<Item = Result<Bytes, PayloadError>> + 'static,
    {
        PayloadBuffer { eof: false, buf: BytesMut::new(), stream: stream.boxed_local() }
    }

    pub(crate) fn poll_stream(&mut self, cx: &mut Context) -> Result<(), PayloadError> {
        loop {
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(Ok(data))) => self.buf.extend_from_slice(&data),
                Poll::Ready(Some(Err(e))) => return Err(e),
                Poll::Ready(None) => {
                    self.eof = true;
                    return Ok(());
                }
                Poll::Pending => return Ok(()),
            }
        }
    }

    /// Read exact number of bytes
    #[cfg(test)]
    pub(crate) fn read_exact(&mut self, size: usize) -> Option<Bytes> {
        if size <= self.buf.len() { Some(self.buf.split_to(size)) } else { None }
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
    pub(crate) fn read_until(&mut self, line: &[u8]) -> Result<Option<Bytes>, MultipartError> {
        let res =
            twoway::find_bytes(&self.buf, line).map(|idx| self.buf.split_to(idx + line.len()));

        if res.is_none() && self.eof { Err(MultipartError::Incomplete) } else { Ok(res) }
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

        assert_eq!(Some(Bytes::from("line")), payload.read_until(b"ne").unwrap());
        assert_eq!(payload.buf.len(), 6);

        assert_eq!(Some(Bytes::from("1line2")), payload.read_until(b"2").unwrap());
        assert_eq!(payload.buf.len(), 0);
    }
}
