//! Testing macros

use rpcap_impl::layer;

/// Foo Error
#[derive(Debug)]
pub enum FooError {
    /// Invalid Bar
    Bar,
}

layer! {
    /// Foo Test Struct
    pub Foo {
        bar: {
            range: 0..,
            spec: u8
        }
    }
}

impl<T> Foo<T>
where
    T: AsRef<[u8]>,
{
    /// Validate the packet
    pub fn validate(&self) -> Result<(), FooError> {
        todo!()
    }
}
