# Changes

## [4.3.0] - 2026-11-06

* Return an error instead of silently dropping the identity cookie when it can not be set

* Reject identity cookies larger than 4096 bytes, add `CookieIdentityPolicyError::Overflow`

## [4.2.0] - 2026-11-03

* Update the `ntex` to 4.5

## [4.1.0] - 2026-10-05

* Update the `ntex` apis

## [4.0.0] - 2026-09-14

* Update the `ntex` to 4.0

## [3.2.0] - 2026-02-02

* Update the `ntex` to 3.0 release

## [3.1.0] - 2025-12-17

* Update the `ntex-service` to 4.0

## [3.0.0] - 2025-11-27

* Update the `ntex` to 3.0

## [1.0.0] - 2024-02-28

* Update the `ntex` dependency to 1.1
* Update the `time` dependency to 0.3

## [0.2.1] - 2020-01-10

* Fix panic with already borrowed: BorrowMutError #1263

## [0.2.0] - 2019-12-20

* Use actix-web 2.0

## [0.1.0] - 2019-06-xx

* Move identity middleware to separate crate
