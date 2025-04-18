//! HTTP/1.1 Response Encoder

use std::{
    future::poll_fn,
    io,
    pin::{Pin, pin},
    task::{Context, Poll, ready},
};

use http::{
    HeaderMap, HeaderValue, StatusCode,
    header::{CONTENT_LENGTH, CONTENT_TYPE},
};
use tokio::{fs::File, io::AsyncWriteExt};
use tokio_splice2::{AsyncWriteFd, SpliceIoCtx};

const DEFAULT_CONTENT_TYPE: &str = "application/octet-stream";

#[derive(Debug, Clone)]
/// A struct representing an HTTP/1.1 response.
pub(crate) struct Response {
    pub status: StatusCode,
    pub headers: Option<HeaderMap>,
}

impl Response {
    /// Write to stream, returns body written.
    pub(crate) async fn write_to_stream<W, B>(
        &self,
        w: &mut W,
        body: Option<B>,
    ) -> io::Result<usize>
    where
        W: AsyncWriteFd + Unpin,
        B: BodyT<W>,
    {
        // Status line
        w.write_all(b"HTTP/1.1 ").await?;
        w.write_all(self.status.as_str().as_bytes()).await?;
        w.write_all(b" OK\r\n").await?;

        if let Some(headers) = &self.headers {
            // Headers
            for (k, v) in headers.iter() {
                w.write_all(k.as_str().as_bytes()).await?;
                w.write_u8(b':').await?;
                w.write_all(v.as_bytes()).await?;
                w.write_all(b"\r\n").await?;
            }
        }

        // Header: content length
        let content_length = body.as_ref().map(BodyT::content_length).unwrap_or(0);
        w.write_all(CONTENT_LENGTH.as_str().as_bytes()).await?;
        w.write_u8(b':').await?;
        w.write_all(content_length.to_string().as_bytes()).await?;
        w.write_all(b"\r\n").await?;

        if let Some(content_type) = body.as_ref().and_then(BodyT::content_type) {
            w.write_all(CONTENT_TYPE.as_str().as_bytes()).await?;
            w.write_u8(b':').await?;
            w.write_all(content_type.as_bytes()).await?;
            w.write_all(b"\r\n").await?;
        }

        // CRLF
        w.write_all(b"\r\n").await?;

        // Body
        if let Some(mut body) = body {
            let mut body = pin!(body);
            let mut w = Pin::new(w);

            return poll_fn(|cx| body.as_mut().poll_write_to_stream(w.as_mut(), cx)).await;
        }

        w.flush().await?;

        Ok(0)
    }
}

/// Body
pub(crate) trait BodyT<W>: Sized {
    fn poll_write_to_stream(
        self: Pin<&mut Self>,
        _w: Pin<&mut W>,
        _cx: &mut Context,
    ) -> Poll<io::Result<usize>>
    where
        W: AsyncWriteFd,
    {
        Poll::Ready(Ok(0))
    }

    /// content-length
    fn content_length(&self) -> usize {
        0
    }

    /// content-type
    fn content_type(&self) -> Option<HeaderValue> {
        None
    }
}

impl<W, T: BodyT<W> + Unpin> BodyT<W> for &mut T {}

impl<W> BodyT<W> for () {}

#[pin_project::pin_project]
pub(crate) struct SpliceIoBody<'f, W> {
    #[pin]
    file: &'f mut File,

    size: usize,

    #[pin]
    ctx: SpliceIoCtx<&'f mut File, W>,
}

impl<'f, W> SpliceIoBody<'f, W> {
    ///
    pub(crate) async fn new(
        file: &'f mut File,
        f_offset_start: Option<u64>,
        f_offset_end: Option<u64>,
    ) -> io::Result<Self> {
        let file_len = file.metadata().await?.len();

        Self::new_with_file_len(file, file_len, f_offset_start, f_offset_end)
    }

    ///
    pub(crate) fn new_with_file_len(
        file: &'f mut File,
        file_len: u64,
        f_offset_start: Option<u64>,
        f_offset_end: Option<u64>,
    ) -> io::Result<Self> {
        let ctx = SpliceIoCtx::prepare_from_file(file_len, f_offset_start, f_offset_end)?;

        Ok(Self {
            file,
            size: (f_offset_end.unwrap_or(file_len) - f_offset_start.unwrap_or(0)) as usize,
            ctx,
        })
    }
}

impl<W> BodyT<W> for SpliceIoBody<'_, W> {
    fn poll_write_to_stream(
        self: Pin<&mut Self>,
        w: Pin<&mut W>,
        cx: &mut Context,
    ) -> Poll<io::Result<usize>>
    where
        W: AsyncWriteFd,
    {
        // ugly API

        let this = self.project();

        this.ctx.poll_copy(cx, this.file, w)
    }

    fn content_length(&self) -> usize {
        self.size
    }

    fn content_type(&self) -> Option<HeaderValue> {
        Some(HeaderValue::from_static(DEFAULT_CONTENT_TYPE))
    }
}

#[pin_project::pin_project]
pub(crate) struct BytesBody<B> {
    has_written: usize,
    has_error: bool,

    // content-type, default
    content_type: HeaderValue,

    #[pin]
    inner: Option<B>,
}

impl<B> BytesBody<B> {
    pub(crate) fn new(inner: B, content_type: Option<&'static str>) -> Self {
        Self {
            has_written: 0,
            has_error: false,
            content_type: HeaderValue::from_static(content_type.unwrap_or(DEFAULT_CONTENT_TYPE)),
            inner: Some(inner),
        }
    }
}

impl<W, B> BodyT<W> for BytesBody<B>
where
    B: AsRef<[u8]>,
{
    fn poll_write_to_stream(
        self: Pin<&mut Self>,
        mut w: Pin<&mut W>,
        cx: &mut Context,
    ) -> Poll<io::Result<usize>>
    where
        W: AsyncWriteFd,
    {
        let this = self.project();

        let Some(inner) = this.inner.as_ref().get_ref().as_ref() else {
            return Poll::Ready(Err(io::Error::other("poll after ready")));
        };

        let inner = inner.as_ref();
        let inner_len = inner.len();

        while *this.has_written < inner_len {
            *this.has_written += ready!(w.as_mut().poll_write(cx, &inner[*this.has_written..]))
                .inspect_err(|_| {
                    *this.has_error = true;
                })?;
        }

        debug_assert!(
            *this.has_written <= inner_len,
            "Write more than body length?"
        );

        Poll::Ready(Ok(*this.has_written))
    }

    fn content_length(&self) -> usize {
        self.inner
            .as_ref()
            .map(|l| l.as_ref().len())
            .unwrap_or_default()
    }

    fn content_type(&self) -> Option<HeaderValue> {
        Some(self.content_type.clone())
    }
}
