//! Build script — wire pkg-config for libnm + g-modules linking.
//!
//! The cdylib is dlopened by NM, so libnm symbols would resolve at
//! load time even without an explicit link, but having cargo error
//! cleanly when libnm-dev is missing beats a confusing dlopen failure
//! later.  g-module is needed for `g_module_open` (used by
//! `get_editor` to load the editor cdylib at runtime).

fn main() {
    if let Err(e) = pkg_config::Config::new().probe("libnm") {
        eprintln!("cargo:warning=libnm pkg-config probe failed: {e}");
        eprintln!("cargo:warning=install libnm-dev (Debian) or libnm-devel (Fedora)");
        std::process::exit(1);
    }
    // g-module is shipped under glib's gmodule-2.0 pc file.
    if let Err(e) = pkg_config::Config::new().probe("gmodule-2.0") {
        eprintln!("cargo:warning=gmodule-2.0 probe failed: {e}");
        std::process::exit(1);
    }
}
