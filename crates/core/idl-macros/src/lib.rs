// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `#[azos_interface(id = N, level = L [, words = W])]` (L13). Use it through
//! `azos_idl`, which documents the generated items and the wire form.
//!
//! The expansion is `expand`, a plain function over `proc_macro2` tokens, so
//! the unit tests below check the exact error of every refusal.

mod lint;

use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use syn::{
    parse::Parser, punctuated::Punctuated, spanned::Spanned, Expr, ExprLit, FnArg, Ident, ItemTrait, Lit, Meta,
    MetaNameValue, Pat, ReturnType, Token, TraitItem, Type,
};

/// ABI ceiling on inline words, checked here for a literal `words = W`
/// (the runtime asserts it again against `azos_abi`).
const WORDS_CEILING: usize = 8;

const FLAG_IDEMPOTENT: u8 = 1;
const FLAG_AT_MOST_ONCE: u8 = 2;
const FLAG_ONCE_ONLY: u8 = 4;

#[proc_macro_attribute]
pub fn azos_interface(attr: proc_macro::TokenStream, item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    match expand(attr.into(), item.into()) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

struct Args {
    id: u32,
    level: u16,
    /// `words = W`, if given.
    words: Option<usize>,
}

fn int_value<T: core::str::FromStr>(nv: &MetaNameValue, what: &str) -> syn::Result<T>
where
    T::Err: core::fmt::Display,
{
    match &nv.value {
        Expr::Lit(ExprLit { lit: Lit::Int(i), .. }) => i.base10_parse::<T>(),
        other => Err(syn::Error::new(other.span(), format!("azos_interface: `{what}` must be an integer literal"))),
    }
}

fn parse_args(attr: TokenStream) -> syn::Result<Args> {
    let list = Punctuated::<MetaNameValue, Token![,]>::parse_terminated
        .parse2(attr)
        .map_err(|e| syn::Error::new(e.span(), format!("azos_interface: expected `id = N, level = L`: {e}")))?;
    let (mut id, mut level, mut words) = (None, None, None);
    for nv in &list {
        let key = nv.path.get_ident().map(|i| i.to_string()).unwrap_or_default();
        let dup = |k: &str| syn::Error::new_spanned(&nv.path, format!("azos_interface: `{k}` given twice"));
        match key.as_str() {
            "id" => {
                if id.is_some() { return Err(dup("id")); }
                id = Some(int_value::<u32>(nv, "id")?);
            }
            "level" => {
                if level.is_some() { return Err(dup("level")); }
                level = Some(int_value::<u16>(nv, "level")?);
            }
            "words" => {
                if words.is_some() { return Err(dup("words")); }
                words = Some(int_value::<usize>(nv, "words")?);
            }
            other => {
                return Err(syn::Error::new_spanned(
                    &nv.path,
                    format!("azos_interface: unknown argument `{other}` (expected `id`, `level`, `words`)"),
                ))
            }
        }
    }
    let id = id.ok_or_else(|| syn::Error::new(Span::call_site(), "azos_interface: missing `id = N` (a non-zero interface id)"))?;
    let level = level.ok_or_else(|| {
        syn::Error::new(Span::call_site(), "azos_interface: missing `level = L` (the interface's stability level, from 1)")
    })?;
    if id == 0 {
        return Err(syn::Error::new(Span::call_site(), "azos_interface: `id` 0 is reserved (a zeroed message must name no interface)"));
    }
    if level == 0 {
        return Err(syn::Error::new(Span::call_site(), "azos_interface: `level` 0 is reserved for the pre-IDL protocols; levels start at 1"));
    }
    if let Some(w) = words {
        if !(1..=WORDS_CEILING).contains(&w) {
            return Err(syn::Error::new(Span::call_site(), format!("azos_interface: `words = {w}` is outside 1..={WORDS_CEILING}, the ABI ceiling on inline words")));
        }
    }
    Ok(Args { id, level, words })
}

struct Param {
    name: Ident,
    ty: Type,
}

struct Method {
    ident: Ident,
    /// `&mut self` (true) or `&self` (false).
    mutable: bool,
    params: Vec<Param>,
    ret: Type,
    flags: u8,
    attrs: Vec<syn::Attribute>,
}

fn parse_method(tf: &syn::TraitItemFn, errs: &mut Vec<syn::Error>) -> Option<Method> {
    let sig = &tf.sig;
    let start = errs.len();
    if tf.default.is_some() {
        errs.push(syn::Error::new_spanned(&tf.default, "azos_interface: an interface method has no body; the implementation is the trait impl"));
    }
    if sig.asyncness.is_some() || sig.constness.is_some() || sig.unsafety.is_some() || sig.abi.is_some() || sig.variadic.is_some() {
        errs.push(syn::Error::new_spanned(sig, "azos_interface: an interface method is a plain `fn` (no async, const, unsafe, extern or variadic)"));
    }
    if !sig.generics.params.is_empty() || sig.generics.where_clause.is_some() {
        errs.push(syn::Error::new_spanned(&sig.generics, "azos_interface: an interface method has no generics or where clause"));
    }
    // Flags.
    let mut flags = 0u8;
    let mut n_flags = 0;
    let mut attrs = Vec::new();
    for a in &tf.attrs {
        let name = a.path().get_ident().map(|i| i.to_string());
        let f = match name.as_deref() {
            Some("idempotent") => FLAG_IDEMPOTENT,
            Some("at_most_once") => FLAG_AT_MOST_ONCE,
            Some("once_only") => FLAG_ONCE_ONLY,
            _ => { attrs.push(a.clone()); continue; }
        };
        if !matches!(a.meta, Meta::Path(_)) {
            errs.push(syn::Error::new_spanned(a, "azos_interface: this attribute takes no arguments"));
        }
        flags |= f;
        n_flags += 1;
    }
    if n_flags > 1 {
        errs.push(syn::Error::new_spanned(&sig.ident, format!("azos_interface: method `{}` has more than one of #[idempotent], #[at_most_once], #[once_only]; they are mutually exclusive failure semantics", sig.ident)));
    }
    // Receiver.
    let mut mutable = false;
    let mut inputs = sig.inputs.iter();
    match inputs.next() {
        Some(FnArg::Receiver(r)) if r.reference.is_some() && r.colon_token.is_none() => mutable = r.mutability.is_some(),
        _ => errs.push(syn::Error::new_spanned(sig, "azos_interface: an interface method takes `&self` or `&mut self`")),
    }
    // Parameters.
    let mut params = Vec::new();
    for a in inputs {
        match a {
            FnArg::Typed(pt) => match &*pt.pat {
                Pat::Ident(pi) if pi.by_ref.is_none() && pi.subpat.is_none() => {
                    errs.extend(lint::check_param(&pi.ident, &pt.ty));
                    params.push(Param { name: pi.ident.clone(), ty: (*pt.ty).clone() });
                }
                other => errs.push(syn::Error::new_spanned(other, "azos_interface: a parameter is a plain name (`name: Type`)")),
            },
            FnArg::Receiver(r) => errs.push(syn::Error::new_spanned(r, "azos_interface: only the first parameter is the receiver")),
        }
    }
    // Name and return type.
    errs.extend(lint::check_method_name(&sig.ident, &sig.output));
    errs.extend(lint::check_return(&sig.output));
    let ret: Type = match &sig.output {
        ReturnType::Default => syn::parse_quote!(()),
        ReturnType::Type(_, t) => (**t).clone(),
    };
    if errs.len() > start {
        return None;
    }
    Some(Method { ident: sig.ident.clone(), mutable, params, ret, flags, attrs })
}

/// The whole expansion. `Err` carries every refusal, combined.
pub(crate) fn expand(attr: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    let args = parse_args(attr)?;
    let tr: ItemTrait = syn::parse2(item)
        .map_err(|e| syn::Error::new(e.span(), "azos_interface applies to a trait (`pub trait Name { fn op(&mut self, ..) -> R; }`)"))?;

    let mut errs: Vec<syn::Error> = Vec::new();
    if !tr.generics.params.is_empty() || tr.generics.where_clause.is_some() {
        errs.push(syn::Error::new_spanned(&tr.generics, "azos_interface: an interface trait has no generics"));
    }
    if !tr.supertraits.is_empty() {
        errs.push(syn::Error::new_spanned(&tr.supertraits, "azos_interface: an interface trait has no supertraits"));
    }
    if tr.unsafety.is_some() || tr.auto_token.is_some() {
        errs.push(syn::Error::new_spanned(&tr.ident, "azos_interface: an interface trait is a plain `trait`"));
    }
    let mut methods = Vec::new();
    for it in &tr.items {
        match it {
            TraitItem::Fn(f) => {
                if let Some(m) = parse_method(f, &mut errs) {
                    methods.push(m);
                }
            }
            other => errs.push(syn::Error::new_spanned(other, "azos_interface: an interface trait holds methods only (no consts, types or macros)")),
        }
    }
    if tr.items.is_empty() {
        errs.push(syn::Error::new_spanned(&tr.ident, "azos_interface: an interface needs at least one method"));
    }
    if tr.items.len() >= u16::MAX as usize {
        errs.push(syn::Error::new_spanned(&tr.ident, "azos_interface: op numbers are 16 bits; too many methods"));
    }
    // Duplicate names cannot happen (rustc refuses), but two methods whose
    // names differ only in case would collide as `OP_*` constants.
    let mut seen: Vec<String> = Vec::new();
    for m in &methods {
        let up = m.ident.to_string().to_ascii_uppercase();
        if seen.contains(&up) {
            errs.push(syn::Error::new_spanned(&m.ident, "azos_interface: two methods differ only in case; their OP_* constants would collide"));
        }
        seen.push(up);
    }
    if let Some(mut first) = errs.pop() {
        while let Some(e) = errs.pop() {
            first.combine(e);
        }
        return Err(first);
    }

    Ok(generate(&args, &tr, &methods))
}

fn generate(args: &Args, tr: &ItemTrait, methods: &[Method]) -> TokenStream {
    let tname = &tr.ident;
    let vis = &tr.vis;
    let name_s = tname.to_string();
    let idl_ty = format_ident!("{}Idl", tname);
    let call_trait = format_ident!("{}Call", tname);
    let client = format_ident!("{}Client", tname);
    let direct = format_ident!("{}Direct", tname);
    let placed = format_ident!("{}Placed", tname);
    let id = args.id;
    let level = args.level;
    let words_limit = match args.words {
        Some(w) => quote!(#w),
        None => quote!(::azos_idl::INLINE_WORDS_MAX),
    };

    // The trait as written, with the flag attributes removed.
    let mut clean = tr.clone();
    for it in clean.items.iter_mut() {
        if let TraitItem::Fn(f) = it {
            f.attrs.retain(|a| {
                !matches!(a.path().get_ident().map(|i| i.to_string()).as_deref(), Some("idempotent" | "at_most_once" | "once_only"))
            });
        }
    }

    let mut op_consts = Vec::new();
    let mut op_rows = Vec::new();
    let mut asserts = Vec::new();
    let mut dispatch_arms = Vec::new();
    let mut call_decls = Vec::new();
    let mut client_fns = Vec::new();
    let mut direct_fns = Vec::new();
    let mut placed_fns = Vec::new();

    for (i, m) in methods.iter().enumerate() {
        let op = (i + 1) as u16;
        let mname = &m.ident;
        let mname_s = mname.to_string();
        let op_const = format_ident!("OP_{}", mname_s.to_ascii_uppercase());
        let req_words_c = format_ident!("REQ_WORDS_{}", mname_s.to_ascii_uppercase());
        let req_caps_c = format_ident!("REQ_CAPS_{}", mname_s.to_ascii_uppercase());
        let rep_words_c = format_ident!("REP_WORDS_{}", mname_s.to_ascii_uppercase());
        let rep_caps_c = format_ident!("REP_CAPS_{}", mname_s.to_ascii_uppercase());
        let flags = m.flags;
        let pnames: Vec<&Ident> = m.params.iter().map(|p| &p.name).collect();
        let ptys: Vec<&Type> = m.params.iter().map(|p| &p.ty).collect();
        let ret = &m.ret;
        let docs = &m.attrs;

        op_consts.push(quote! {
            pub const #op_const: u16 = #op;
            pub const #req_words_c: usize = 1 #( + <#ptys as ::azos_idl::Wire>::WORDS )*;
            pub const #req_caps_c: usize = 0 #( + <#ptys as ::azos_idl::Wire>::CAPS )*;
            pub const #rep_words_c: usize = 1 + <#ret as ::azos_idl::Wire>::WORDS;
            pub const #rep_caps_c: usize = <#ret as ::azos_idl::Wire>::CAPS;
        });
        let m_msg = format!("azos_interface {name_s}::{mname_s}: the request does not fit the inline words (header + arguments)");
        let r_msg = format!("azos_interface {name_s}::{mname_s}: the reply does not fit the inline words (status + return)");
        let c_msg = format!("azos_interface {name_s}::{mname_s}: more capability entries than the ABI carries");
        asserts.push(quote! {
            assert!(#idl_ty::#req_words_c <= #idl_ty::WORDS, #m_msg);
            assert!(#idl_ty::#rep_words_c <= #idl_ty::WORDS, #r_msg);
            assert!(#idl_ty::#req_caps_c <= ::azos_idl::CAPS_MAX, #c_msg);
            assert!(#idl_ty::#rep_caps_c <= ::azos_idl::CAPS_MAX, #c_msg);
        });
        op_rows.push(quote! {
            ::azos_idl::OpInfo {
                op: Self::#op_const,
                name: #mname_s,
                flags: #flags,
                req_words: Self::#req_words_c as u8,
                req_caps: Self::#req_caps_c as u8,
                rep_words: Self::#rep_words_c as u8,
                rep_caps: Self::#rep_caps_c as u8,
            }
        });

        let recv_call = if m.mutable { quote!(&mut *server) } else { quote!(&*server) };
        dispatch_arms.push(quote! {
            x if x == Self::#op_const => {
                r.expect(Self::#req_words_c, Self::#req_caps_c)?;
                #( let #pnames = <#ptys as ::azos_idl::Wire>::get(&mut r); )*
                r.finish()?;
                #[allow(clippy::let_unit_value)]
                let out = <S as #tname>::#mname(#recv_call #( , #pnames )*);
                <#ret as ::azos_idl::Wire>::put(&out, w);
                ::azos_idl::__private::Ok(())
            }
        });

        let recv = if m.mutable { quote!(&mut self) } else { quote!(&self) };
        call_decls.push(quote! {
            #(#docs)*
            fn #mname(#recv #( , #pnames : #ptys )*) -> ::azos_idl::Result<#ret>;
        });
        client_fns.push(quote! {
            fn #mname(#recv #( , #pnames : #ptys )*) -> ::azos_idl::Result<#ret> {
                let mut msg = ::azos_idl::MsgDesc::default();
                msg.version = ::azos_idl::MSG_VERSION;
                msg.deadline = self.deadline_ns;
                {
                    let mut w = ::azos_idl::Writer::new(&mut msg);
                    w.word(::azos_idl::header(#idl_ty::ID, #idl_ty::LEVEL, #idl_ty::#op_const));
                    #( <#ptys as ::azos_idl::Wire>::put(&#pnames, &mut w); )*
                    w.finish();
                }
                ::azos_idl::Transport::call(&self.transport, &mut msg)?;
                let mut r = ::azos_idl::Reader::new(&msg);
                r.status()?;
                r.expect_reply(#idl_ty::#rep_words_c, #idl_ty::#rep_caps_c)?;
                let out = <#ret as ::azos_idl::Wire>::get(&mut r);
                r.finish()?;
                ::azos_idl::__private::Ok(out)
            }
        });
        placed_fns.push(quote! {
            fn #mname(#recv #( , #pnames : #ptys )*) -> ::azos_idl::Result<#ret> {
                match self {
                    Self::Direct(__stub) => <#direct<S> as #call_trait>::#mname(__stub #( , #pnames )*),
                    Self::Endpoint(__stub) => <#client<T> as #call_trait>::#mname(__stub #( , #pnames )*),
                }
            }
        });
        let direct_recv = if m.mutable { quote!(&mut self.0) } else { quote!(&self.0) };
        direct_fns.push(quote! {
            fn #mname(#recv #( , #pnames : #ptys )*) -> ::azos_idl::Result<#ret> {
                ::azos_idl::__private::Ok(<S as #tname>::#mname(#direct_recv #( , #pnames )*))
            }
        });
    }

    let n_ops = methods.len();
    quote! {
        #clean

        /// The generated support for the interface: its id, level, op table
        /// and server dispatcher, as associated items.
        #[allow(non_snake_case, dead_code, clippy::all)]
        #vis struct #idl_ty;

        #[allow(non_snake_case, dead_code, clippy::all)]
        impl #idl_ty {
            /// The interface id.
            pub const ID: u32 = #id;
            /// The interface's stability level.
            pub const LEVEL: u16 = #level;
            /// Inline words available to a request or a reply.
            pub const WORDS: usize = #words_limit;
            #(#op_consts)*
            /// The op table: one row per method, in method order.
            pub const OPS: [::azos_idl::OpInfo; #n_ops] = [ #(#op_rows),* ];

            /// The server dispatcher: decode the request in `req`, call the
            /// implementation, write the reply into `reply` (always a valid
            /// reply; its status says whether it was served). The result says
            /// the same, for the server's own accounting.
            pub fn dispatch<S: #tname + ?Sized>(
                server: &mut S,
                req: &::azos_idl::MsgDesc,
                reply: &mut ::azos_idl::MsgDesc,
            ) -> ::azos_idl::Result {
                ::azos_idl::__private::fresh_reply(reply);
                let res = {
                    let mut w = ::azos_idl::Writer::new(reply);
                    w.word(::azos_idl::STATUS_OK);
                    let r = Self::handle(server, req, &mut w);
                    w.finish();
                    r
                };
                if let ::azos_idl::__private::Err(e) = res {
                    ::azos_idl::__private::error_reply(reply, e);
                }
                res
            }

            fn handle<S: #tname + ?Sized>(
                server: &mut S,
                req: &::azos_idl::MsgDesc,
                w: &mut ::azos_idl::Writer<'_>,
            ) -> ::azos_idl::Result {
                let mut r = ::azos_idl::Reader::new(req);
                let h = r.header()?;
                if ::azos_idl::header_id(h) != Self::ID {
                    return ::azos_idl::__private::Err(::azos_idl::IdlError::BadInterface);
                }
                if ::azos_idl::header_level(h) > Self::LEVEL {
                    return ::azos_idl::__private::Err(::azos_idl::IdlError::LevelTooNew);
                }
                match ::azos_idl::header_op(h) {
                    #(#dispatch_arms)*
                    _ => ::azos_idl::__private::Err(::azos_idl::IdlError::BadOp),
                }
            }
        }

        const _: () = {
            assert!(#idl_ty::WORDS <= ::azos_idl::INLINE_WORDS_MAX, "azos_interface: `words` is above the ABI ceiling");
            #(#asserts)*
        };

        /// The caller's view of the interface: implemented by the client stub
        /// (through a transport) and the direct stub (in process).
        #vis trait #call_trait {
            #(#call_decls)*
        }

        /// The endpoint-call stub: packs each call into a message and sends it
        /// through the transport.
        #vis struct #client<T: ::azos_idl::Transport> {
            transport: T,
            deadline_ns: u64,
        }

        impl<T: ::azos_idl::Transport> #client<T> {
            pub const fn new(transport: T) -> Self {
                Self { transport, deadline_ns: 0 }
            }
            /// Every call carries this absolute deadline (nanoseconds on the
            /// monotonic clock; 0 = none).
            pub const fn with_deadline(mut self, deadline_ns: u64) -> Self {
                self.deadline_ns = deadline_ns;
                self
            }
            pub fn transport(&self) -> &T {
                &self.transport
            }
        }

        impl<T: ::azos_idl::Transport> #call_trait for #client<T> {
            #(#client_fns)*
        }

        /// The direct-call stub: the same calls on an implementation in this
        /// address space, with no message (the kernel-host placement).
        #vis struct #direct<S: #tname>(pub S);

        impl<S: #tname> #call_trait for #direct<S> {
            #(#direct_fns)*
        }

        /// A driver that runs in either of two hosts, as one caller's value:
        /// the direct-call stub when the implementation is in this address
        /// space, the endpoint-call stub when a task serves it on an
        /// endpoint. The code that calls through it (`#call_trait`) does not
        /// know which; the host that holds it picks the variant per call from
        /// the driver's current placement.
        #vis enum #placed<S: #tname, T: ::azos_idl::Transport> {
            Direct(#direct<S>),
            Endpoint(#client<T>),
        }

        impl<S: #tname, T: ::azos_idl::Transport> #call_trait for #placed<S, T> {
            #(#placed_fns)*
        }
    }
}

#[cfg(test)]
mod tests;
