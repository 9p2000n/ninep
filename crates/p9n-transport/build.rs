fn main() {
    #[cfg(feature = "rdma")]
    {
        println!("cargo:rustc-link-lib=ibverbs");
    }
}
