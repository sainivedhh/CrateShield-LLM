#[macro_export]
macro_rules! array_ref {
    ($arr:expr, $offset:expr, $len:expr) => {
        {
            unsafe { &*($arr.as_ptr().offset($offset) as *const [_; $len]) }
        }
    };
}
