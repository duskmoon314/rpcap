use proc_macro::TokenStream;

mod packet;

#[cfg(feature = "packet")]
#[proc_macro_attribute]
pub fn layer(attr: TokenStream, item: TokenStream) -> TokenStream {
    packet::layer::attribute_layer(attr, item)
}
