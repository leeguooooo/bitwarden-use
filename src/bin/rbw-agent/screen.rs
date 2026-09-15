//! Is the login session's screen locked? Used to drop keys on screen lock /
//! sleep (the screen locks on sleep), independent of `lock_timeout`.

#[cfg(target_os = "macos")]
pub fn is_locked() -> bool {
    use core_foundation::base::TCFType as _;
    use core_foundation::boolean::CFBoolean;
    use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
    use core_foundation::string::CFString;

    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGSessionCopyCurrentDictionary() -> CFDictionaryRef;
    }

    let raw = unsafe { CGSessionCopyCurrentDictionary() };
    if raw.is_null() {
        // no GUI session (e.g. ssh-only): nothing to watch
        return false;
    }
    let dict: CFDictionary<CFString, core_foundation::base::CFType> =
        unsafe { CFDictionary::wrap_under_create_rule(raw) };
    dict.find(CFString::from_static_string("CGSSessionScreenIsLocked"))
        .and_then(|v| v.downcast::<CFBoolean>())
        .is_some_and(bool::from)
}

#[cfg(not(target_os = "macos"))]
pub fn is_locked() -> bool {
    false
}
