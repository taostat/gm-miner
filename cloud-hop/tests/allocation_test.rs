#![expect(
    clippy::expect_used,
    reason = "allocation regression fixtures fail hard on malformed setup"
)]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicUsize, Ordering},
};

use gm_cloud_hop::{parse_deployment_map, rewrite_model_bytes, CloudProvider};

struct CountingAllocator;

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let new_pointer = unsafe { System.realloc(pointer, layout, size) };
        if !new_pointer.is_null() {
            ALLOCATED.fetch_add(size, Ordering::Relaxed);
        }
        new_pointer
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

#[test]
fn escaped_irrelevant_keys_do_not_allocate_their_decoded_contents() {
    let key = r"\u006e".repeat(512 * 1024);
    let body = format!(r#"{{"{key}":{{"{key}":true}},"model":"gpt-5.5"}}"#);
    let map =
        parse_deployment_map(CloudProvider::AzureOpenAi, "gpt-5.5=my-gpt55").expect("test map");

    let before = ALLOCATED.load(Ordering::Relaxed);
    let rewritten =
        rewrite_model_bytes(CloudProvider::AzureOpenAi, body.as_bytes(), &map).expect("rewrite");
    let allocated = ALLOCATED.load(Ordering::Relaxed) - before;

    assert!(rewritten.ends_with(br#""model":"my-gpt55"}"#));
    assert!(
        allocated <= body.len() + 4096,
        "rewrite allocated {allocated} bytes for a {}-byte body; irrelevant escaped keys must not be decoded into owned buffers",
        body.len()
    );
}
