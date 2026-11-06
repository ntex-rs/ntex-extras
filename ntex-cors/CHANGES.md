# Changes

## [4.3.0] - 2026-11-06

* Make `Default` for the `Cors` builder equivalent to `Cors::new()`; `build()` no longer panics

* Treat only `OPTIONS` requests with `Access-Control-Request-Method` as preflight requests

* Add `Vary: Origin` to preflight responses and to responses for requests without `Origin`

* Merge `Origin` into all existing `Vary` headers and skip it if `Origin` or `*` is already present

## [4.2.0] - 2026-11-03

* Update the `ntex` to 4.5

## [4.1.1] - 2026-10-05

* Update the `urly` dependency

## [4.1.0] - 2026-10-05

* Update the `ntex` apis, parse allowed origins with `ntex::url::Url`

## [4.0.0] - 2026-09-14

* Update the `ntex` to 4.0

## [3.2.1] - 2026-02-04

* Fix the `ntex` api usage

## [3.2.0] - 2026-02-02

* Update the `ntex` to 3.0 release

## [3.1.0] - 2025-12-17

* Update the `ntex-service` to 4.0

## [3.0.0] - 2025-11-27

* Update the `ntex` to 3.0

## [2.1.0] - 2025-07-09

* Fix Cors::allowed_origin to set "*" as AllOrSome::All #17

## [1.0.0] - 2024-02-28

* Update the `ntex` dependency to 1.1

## [0.1.0] - 2020-10-05

* Initial release
