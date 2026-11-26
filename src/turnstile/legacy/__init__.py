"""The customer's policy administration system, as the agents' teams found it.

A 15-year-old SOAP service over a fixed-width record store, plus a nightly CSV extract that
the data team uses for search. Everything here is synthetic, generated deterministically so
tests and reports are reproducible; the shapes and quirks are the point:

* every call needs a session ticket from `Login`, and tickets expire after 15 minutes;
* dates are `YYYYMMDD`, money is integer cents in a string, status is a one-letter code;
* text fields are fixed width (an address line over 30 characters is a fault, not truncated);
* more than four concurrent requests get a `SystemBusy` fault;
* `FileClaim` is not idempotent: a retried request files a second claim;
* `SearchPolicies` has no paging and is slow, which is why search runs on the nightly extract.
"""
