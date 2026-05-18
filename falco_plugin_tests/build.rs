fn main() {
    println!("cargo:rustc-check-cfg=cfg(have_libsinsp)");

    match pkg_config::Config::new().statik(true).probe("libsinsp") {
        Ok(sinsp) => {
            cxx_build::bridge("src/ffi.rs")
                .file("c++/sinsp_test_driver.cpp")
                .flag_if_supported("-Wno-unused-parameter")
                .includes(sinsp.include_paths)
                .compile("falco_sinsp_test_driver");

            for lib in sinsp.libs {
                println!("cargo:rustc-link-lib={lib}");
            }

            println!("cargo:rustc-cfg=have_libsinsp");
        }
        Err(e) => {
            eprintln!("Unable to find libsinsp via pkg-config: {e:?}");
        }
    }

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=c++/sinsp_test_driver.cpp");
    println!("cargo:rerun-if-changed=c++/sinsp_test_driver.h");
}
