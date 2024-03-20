use darling::{FromAttributes, FromMeta};
use heck::ToSnekCase;
use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{parse_macro_input, Attribute, Expr, Field, ItemStruct, Lit, Type, TypePath, TypeSlice};

#[derive(Debug, FromMeta)]
struct LayerFieldArgs {
    range: Expr,
}

impl FromAttributes for LayerFieldArgs {
    fn from_attributes(attrs: &[Attribute]) -> darling::Result<Self> {
        // let mut range;

        for attr in attrs {
            if attr.path().is_ident("layer") {
                let args = Self::from_meta(&attr.meta)?;
                return Ok(args);
            }
        }

        Err(darling::Error::missing_field("range"))
    }
}

pub fn attribute_layer(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemStruct);

    let ItemStruct {
        attrs,
        vis,
        ident,
        fields,
        ..
    } = item;

    let err_ident = format_ident!("{}Error", ident);
    let macro_ident = format_ident!("{}", ident.to_string().to_snek_case());

    let mut field_ranges: Vec<proc_macro2::TokenStream> = Vec::new();
    let mut field_methods: Vec<proc_macro2::TokenStream> = Vec::new();
    let mut field_mut_methods: Vec<proc_macro2::TokenStream> = Vec::new();

    let mut min_header_length_value: usize = 0;

    for field in fields {
        let Field {
            attrs, ident, ty, ..
        } = field;

        let ident = ident.expect("Field must have an identifier");

        let args = match LayerFieldArgs::from_attributes(&attrs) {
            Ok(args) => args,
            Err(err) => return err.write_errors().into(),
        };
        let attrs: Vec<_> = attrs
            .iter()
            .filter(|attr| !attr.path().is_ident("layer"))
            .collect();
        let range = match &args.range {
            Expr::Range(range) => range,
            _ => {
                return darling::Error::unexpected_expr_type(&args.range)
                    .write_errors()
                    .into()
            }
        };

        // If ExprRange.end is Some and the value is ExprLit whose List is Int
        // then parse the value, convert to usize, and cmp with
        // min_header_length_value. If greater, replace.
        if let Some(end) = &range.end {
            if let Expr::Lit(lit) = end.as_ref() {
                if let Lit::Int(end) = &lit.lit {
                    let end = end.base10_parse::<usize>().expect("Invalid range end");
                    min_header_length_value = std::cmp::max(min_header_length_value, end);
                }
            }
        }

        let method_doc = format!(" Get the `{}` field.", ident);
        let method_mut_doc = format!(" Get the `{}` field as mutable.", ident);
        let method_mut_ident = format_ident!("{}_mut", ident);

        if let Type::Slice(TypeSlice { elem, .. }) = &ty {
            if let Type::Path(TypePath { path, .. }) = elem.as_ref() {
                if path.is_ident("u8") {
                    // field that will not convert to Field<ty>

                    field_methods.push(quote! {
                        #[doc = #method_doc]
                        #( #attrs )*
                        #[inline]
                        pub fn #ident(&self) -> &[u8] {
                            &self.data.as_ref()[#range]
                        }
                    });
                    field_mut_methods.push(quote! {
                        #[doc = #method_mut_doc]
                        #( #attrs )*
                        #[inline]
                        pub fn #method_mut_ident(&mut self) -> &mut [u8] {
                            let range = #range;
                            &mut self.data.as_mut()[range]
                        }
                    });
                    continue;
                }
            }
        }
        field_methods.push(quote! {
            #[doc = #method_doc]
            #( #attrs )*
            #[inline]
            pub fn #ident(&self) -> &crate::utils::field::Field<#ty> {
                unsafe { &*(self.data.as_ref()[#range].as_ptr() as *const _)}
            }
        });
        field_mut_methods.push(quote! {
            #[doc = #method_mut_doc]
            #( #attrs )*
            #[inline]
            pub fn #method_mut_ident(&mut self) -> &mut crate::utils::field::Field<#ty> {
                let range = #range;
                unsafe { &mut *(self.data.as_mut()[range].as_mut_ptr() as *mut _)}
            }
        });
    }
    field_ranges.push(quote! {
        #[doc = "Minimum length of the layer header."]
        pub const MIN_HEADER_LENGTH: usize = #min_header_length_value;
    });

    let doc_new_unchecked = format!(
        " Create a new [`{}`] layer from the given data without validation.",
        ident
    );
    // // let doc_new = format!(" Create a new [`{}`] layer from the given data.", ident);
    let doc_macro = format!(" Create a new [`{}`] layer", ident);

    quote! {
        #(#attrs)*
        #[derive(Debug, Clone, Copy, PartialEq)]
        #vis struct #ident <T>
        where
            T: AsRef<[u8]>,
        {
            data: T
        }

        /// generated constants, field accessors and methods
        impl<T> #ident <T>
        where
            T: AsRef<[u8]>,
        {
            #(#field_ranges)*

            #[doc = #doc_new_unchecked]
            ///
            /// # Safety
            ///
            /// The caller muest ensure the given data is valid. That is, the
            /// data must be long enough to contain the entire layer.
            ///
            /// Feature `strict` may add additional validation that the caller
            /// must ensure.
            ///
            /// If the data is invalid, further operations on the layer may
            /// cause panics when accessing fields.
            ///
            /// A safe alternative is to implement a [`validate`] method and
            /// wrap this method in a safer [`new`] method.
            #[inline]
            pub const unsafe fn new_unchecked(data: T) -> Self {
                Self { data }
            }

            /// Get the reference to the inner data
            #[inline]
            pub const fn inner(&self) -> &T {
                &self.data
            }

            #( #field_methods )*
        }

        /// generated field accessors and methods
        impl<T> #ident <T>
        where
            T: AsRef<[u8]> + AsMut<[u8]>,
        {
            /// Get the mutable reference to the inner data.
            #[inline]
            pub fn inner_mut(&mut self) -> &mut T {
                &mut self.data
            }

            #( #field_mut_methods )*
        }

        impl<T> AsRef<[u8]> for #ident <T>
        where
            T: AsRef<[u8]>,
        {
            #[inline]
            fn as_ref(&self) -> &[u8] {
                self.data.as_ref()
            }
        }

        impl<T> AsMut<[u8]> for #ident <T>
        where
            T: AsRef<[u8]> + AsMut<[u8]>,
        {
            #[inline]
            fn as_mut(&mut self) -> &mut [u8] {
                self.data.as_mut()
            }
        }

        impl<T> AsRef<T> for #ident <T>
        where
            T: AsRef<[u8]>,
        {
            #[inline]
            fn as_ref(&self) -> &T {
                self.inner()
            }
        }

        impl<T> AsMut<T> for #ident <T>
        where
            T: AsRef<[u8]> + AsMut<[u8]>,
        {
            #[inline]
            fn as_mut(&mut self) -> &mut T {
                self.inner_mut()
            }
        }

        #[doc = #doc_macro]
        #[macro_export]
        macro_rules! #macro_ident {
            ($($field:ident : $value:expr),* $(,)?) => {
                #macro_ident!(
                    #min_header_length_value,
                    $($field : $value),*
                )
            };

            ($length:expr, $($field:ident : $value:expr),* $(,)?) => {
                || -> Result<$crate::layer::prelude::#ident<[u8; $length]>, $crate::layer::prelude::#err_ident> {
                    let mut layer: $crate::layer::prelude::#ident<[u8; $length]> = unsafe { $crate::layer::prelude::#ident::<[u8; $length]>::new_unchecked([0; $length]) };
                    paste::paste! {
                        $(
                            layer.[< $field _mut >]().set($value);
                        )*
                    }
                    Ok(layer)
                }()
            }
        }
    }
    .into()
}
