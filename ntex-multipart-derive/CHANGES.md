# Changes

## [4.3.0] - 2026-11-22

* Add the `#[multipart(max_parts = N)]` struct attribute to lower a form's part limit

* Drain unknown parts with `form::discard_field` so they count toward the total byte budget

## [4.2.0] - 2026-11-06

* Report size limits that do not fit in `usize` as a compile error instead of panicking

* Support generic structs in `MultipartForm` derive

## [4.1.0] - 2026-10-05

* Update the `ntex` apis

## [4.0.0] - 2026-09-14

* Update the `ntex` to 4.0

## [3.0.0] - 2026-03-24

* Initial release: `#[derive(MultipartForm)]` for `multipart/form-data` parsing #26
