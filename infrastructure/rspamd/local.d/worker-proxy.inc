milter = yes;
timeout = 15s;
count = 1;
max_retries = 2;
discard_on_reject = false;
quarantine_on_reject = false;

upstream "local" {
    default = yes;
    self_scan = yes;
}
